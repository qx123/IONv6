/*
 *	tcpbsi.c:	BSSP TCP-based link service daemon.
 *
 *	Authors: Sotirios-Angelos Lenas, SPICE
 *		 Scott Burleigh, JPL
 *
 *	Copyright (c) 2013, California Institute of Technology.
 *	Copyright (c) 2013, Space Internetworking Center,
 *	Democritus University of Thrace.
 *	
 *	All rights reserved. U.S. Government and E.U. Sponsorship acknowledged.
 *
 */
#include "tcpbsa.h"

static void	interruptThread()
{
	isignal(SIGTERM, interruptThread);
	ionKillMainThread("tcpbsi");
}

/*	*	*	Receiver thread functions	*	*	*/

typedef struct
{
	LystElt		elt;
	pthread_mutex_t	*mutex;
	int		blockSocket;
	pthread_t	thread;
	int		*running;
} ReceiverThreadParms;

static void	terminateReceiverThread(ReceiverThreadParms *parms)
{
	writeErrmsgMemos();
	writeMemo("[i] tcpbsi receiver thread stopping.");
	pthread_mutex_lock(parms->mutex);
	if (parms->blockSocket != -1)
	{
		closesocket(parms->blockSocket);
		parms->blockSocket = -1;
	}

	lyst_delete(parms->elt);
	pthread_mutex_unlock(parms->mutex);
	MRELEASE(parms);
}

static int	receiveBlockByTCP(int *bsiSocket, char *buffer)
{
	unsigned int	blockLength = 0;
	int		bytesToReceive;
	char		*into;
	unsigned int	preamble;
	int		bytesReceived;

	while (blockLength == 0)	/*	length 0 is keep-alive	*/
	{
		bytesToReceive = 4;
		into = (char *) &preamble;
		while (bytesToReceive > 0)
		{
			bytesReceived = itcp_recv(bsiSocket, into,
					bytesToReceive);
			if (bytesReceived < 1)
			{
				return bytesReceived;
			}

			into += bytesReceived;
			bytesToReceive -= bytesReceived;
		}

		blockLength = ntohl(preamble);
		if (blockLength > TCPBSA_BUFSZ)
		{
			writeMemoNote("[?] tcpbsi block length > buffer size",
					utoa(blockLength));
			blockLength = 0;	/*	Ignore.		*/
		}
	}

	bytesToReceive = blockLength;
	into = buffer;
	while (bytesToReceive > 0)
	{
		bytesReceived = itcp_recv(bsiSocket, into,
				bytesToReceive);
		if (bytesReceived < 1)
		{
			return bytesReceived;
		}

		bytesToReceive -= bytesReceived;
		into += bytesReceived;
	}

	return blockLength;
}

static void	*receiveBlocks(void *parm)
{
	/*	Main loop for bundle reception thread on one
	 *	connection, terminating when connection is lost.	*/

	ReceiverThreadParms	*parms = (ReceiverThreadParms *) parm;
	char			*procName = "tcpbsi";
	int			threadRunning = 1;
	char			*buffer;
	int			blockLength;

	buffer = MTAKE(TCPBSA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("tcpbsi can't get TCP buffer.", NULL);
		ionKillMainThread(procName);
		terminateReceiverThread(parms);
		return NULL;
	}

	/*	Now start receiving blocks.				*/

	while (threadRunning && *(parms->running))
	{
		blockLength = receiveBlockByTCP(&parms->blockSocket, buffer);
		switch (blockLength)
		{
		case -1:
			putErrmsg("Can't receive block.", NULL);

			/*	Intentional fall-through to next case.	*/

		case 0:				/*	Normal stop.	*/
			threadRunning = 0;
			continue;

		default:
			break;			/*	Out of switch.	*/
		}

		if (bsspHandleInboundBlock(buffer, blockLength) < 0)
		{
			putErrmsg("tcpbsi can't handle inbound block.", NULL);
			ionKillMainThread(procName);
			threadRunning = 0;
			continue;
		}

		/*	Make sure other tasks have a chance to run.	*/

		sm_TaskYield();
	}

	/*	End of receiver thread; release resources.		*/

	MRELEASE(buffer);
	terminateReceiverThread(parms);
	return NULL;
}

/*	*	*	Access thread functions	*	*	*	*/

typedef struct
{
	struct sockaddr_storage		socketName;
	struct sockaddr_in	*inetName;
	struct sockaddr_in6 *inet6Name;
	int 		domain;
	int			bsiSocket;
	int			running;
} AccessThreadParms;

static void	*spawnReceivers(void *parm)
{
	/*	Main loop for acceptance of connections and
	 *	creation of receivers to service those connections.	*/

	AccessThreadParms	*atp = (AccessThreadParms *) parm;
	char			*procName = "tcpbsi";
	pthread_mutex_t		mutex;
	Lyst			threads;
	int			newSocket;
	struct sockaddr_storage		bsoSocketName;
	socklen_t		nameLength;
	ReceiverThreadParms	*parms;
	LystElt			elt;
	pthread_t		thread;

	snooze(1);	/*	Let main thread become interruptable.	*/
	pthread_mutex_init(&mutex, NULL);
	threads = lyst_create_using(getIonMemoryMgr());
	if (threads == NULL)
	{
		putErrmsg("tcpbsi can't create threads list.", NULL);
		ionKillMainThread(procName);
		pthread_mutex_destroy(&mutex);
		return NULL;
	}

	/*	Can now begin accepting connections from remote
	 *	contacts.  On failure, take down the whole BSI.		*/

	while (atp->running)
	{
		nameLength = sizeof(struct sockaddr_storage);
		newSocket = accept(atp->bsiSocket, (struct sockaddr *) &bsoSocketName,
				&nameLength);
		if (newSocket < 0)
		{
			putSysErrmsg("tcpbsi accept() failed", NULL);
			ionKillMainThread(procName);
			atp->running = 0;
			continue;
		}

		if (atp->running == 0)
		{
			closesocket(newSocket);
			break;	/*	Main thread has shut down.	*/
		}

		parms = (ReceiverThreadParms *)
				MTAKE(sizeof(ReceiverThreadParms));
		if (parms == NULL)
		{
			putErrmsg("tcpbsi can't allocate for thread.", NULL);
			closesocket(newSocket);
			ionKillMainThread(procName);
			atp->running = 0;
			continue;
		}

		pthread_mutex_lock(&mutex);
		parms->elt = lyst_insert_last(threads, parms);
		pthread_mutex_unlock(&mutex);
		if (parms->elt == NULL)
		{
			putErrmsg("tcpbsi can't allocate for thread.", NULL);
			MRELEASE(parms);
			closesocket(newSocket);
			ionKillMainThread(procName);
			atp->running = 0;
			continue;
		}

		parms->mutex = &mutex;
		parms->blockSocket = newSocket;
		parms->running = &(atp->running);
		if (pthread_begin(&(parms->thread), NULL, receiveBlocks,
					parms))
		{
			putSysErrmsg("tcpbsi can't create new thread", NULL);
			MRELEASE(parms);
			closesocket(newSocket);
			ionKillMainThread(procName);
			atp->running = 0;
			continue;
		}

		/*	Make sure other tasks have a chance to run.	*/

		sm_TaskYield();
	}

	closesocket(atp->bsiSocket);
	writeErrmsgMemos();

	/*	Shut down all current BSI threads cleanly.		*/

	while (1)
	{
		pthread_mutex_lock(&mutex);
		elt = lyst_first(threads);
		if (elt == NULL)	/*	All threads shut down.	*/
		{
			pthread_mutex_unlock(&mutex);
			break;
		}

		/*	Trigger termination of thread.			*/

		parms = (ReceiverThreadParms *) lyst_data(elt);
		thread = parms->thread;
#ifdef mingw
		shutdown(parms->blockSocket, SD_BOTH);
#else
		pthread_kill(thread, SIGTERM);
#endif
		pthread_mutex_unlock(&mutex);
		pthread_join(thread, NULL);
	}

	lyst_destroy(threads);
	writeErrmsgMemos();
	writeMemo("[i] tcpbsi access thread has ended.");
	pthread_mutex_destroy(&mutex);
	return NULL;
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined (ION_LWT)
int	tcpbsi(int a1, int a2, int a3, int a4, int a5,
		int a6, int a7, int a8, int a9, int a10)
{
	char	*socketSpec = (char *) a1;
#else
int	main(int argc, char *argv[])
{
	char	*socketSpec = (argc > 1 ? argv[1] : NULL);
#endif
	
	BsspVdb			*vdb;
	char			*hostName;
	unsigned short		portNbr;
	// unsigned int		hostNbr;
	unsigned char 		hostAddr[sizeof(struct in6_addr)];
	AccessThreadParms	atp;
	socklen_t		nameLength;
//	char			*tcpDelayString; // Temporarily commented out to fix linking errors with tcpDelayEnable in ion-3.3.0
	pthread_t		accessThread;
	int			fd;

	if (socketSpec == NULL)
	{
		PUTS("Usage: tcpbsi <local host name>[:<port number>]");
		return 0;
	}

	if (bsspInit(0) < 0)
	{
		putErrmsg("tcpbsi can't initialize BSSP.", NULL);
		return 1;
	}

	vdb = getBsspVdb();
	if (vdb->rlBsiPid != ERROR && vdb->rlBsiPid != sm_TaskIdSelf())
	{
		putErrmsg("RL-BSI task is already started.",
				itoa(vdb->rlBsiPid));
		return 1;
	}

	/*	All command-line arguments are now validated.		*/

	hostName = socketSpec;
	if ((atp.domain = parseSocketSpec(socketSpec, &portNbr, hostAddr)) < 0)
	{
		putErrmsg("RL-BSI can't get IP/port for host.", hostName);
		return -1;
	}

	if (portNbr == 0)
	{
		portNbr = bsspTcpDefaultPortNbr;
	}

	portNbr = htons(portNbr);
	memset((char *) &(atp.socketName), 0, sizeof(struct sockaddr_storage));
	if (atp.domain == AF_INET)
	{
		atp.inetName = (struct sockaddr_in *) &(atp.socketName);
		atp.inetName->sin_family = AF_INET;
		atp.inetName->sin_port = portNbr;
		memcpy((char *) &(atp.inetName->sin_addr.s_addr), (char *) hostAddr, 4);
		atp.bsiSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (atp.domain == AF_INET)
	{
		atp.inet6Name = (struct sockaddr_in6 *) &(atp.socketName);
		atp.inet6Name->sin6_family = AF_INET6;
		atp.inet6Name->sin6_port = portNbr;
		memcpy((char *) &(atp.inet6Name->sin6_addr.s6_addr), (char *) hostAddr, 16);
		atp.bsiSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	if (atp.bsiSocket < 0)
	{
		putSysErrmsg("RL-BSI can't open TCP socket", NULL);
		return 1;
	}

	nameLength = sizeof(struct sockaddr_storage);
	if (reUseAddress(atp.bsiSocket)
	|| bind(atp.bsiSocket, (struct sockaddr *) &(atp.socketName), nameLength) < 0
	|| listen(atp.bsiSocket, 5) < 0
	|| getsockname(atp.bsiSocket, (struct sockaddr *) &(atp.socketName), &nameLength) < 0)
	{
		closesocket(atp.bsiSocket);
		putSysErrmsg("RL-BSI can't initialize socket", NULL);
		return 1;
	}

//      Temporarily commented out to fix linking errors with tcpDelayEnable in ion-3.3.0
//
//	tcpDelayString = getenv("TCP_DELAY_NSEC_PER_BYTE");
//	if (tcpDelayString == NULL)
//	{
//		tcpDelayEnabled = 0;
//	}
//	else	/*	Artificial TCP delay, for testing purposes.	*/
//	{
//		tcpDelayEnabled = 1;
//		tcpDelayNsecPerByte = strtol(tcpDelayString, NULL, 0);
//		if (tcpDelayNsecPerByte < 0
//		|| tcpDelayNsecPerByte > 16384)
//		{
//			tcpDelayNsecPerByte = 0;
//		}
//	}

	/*	Set up signal handling: SIGTERM is shutdown signal.	*/

	ionNoteMainThread("tcpbsi");
	isignal(SIGTERM, interruptThread);

	/*	Start the access thread.				*/

	atp.running = 1;
	if (pthread_begin(&accessThread, NULL, spawnReceivers, &atp))
	{
		closesocket(atp.bsiSocket);
		putSysErrmsg("tcpbsi can't create access thread", NULL);
		return 1;
	}

	/*	Now sleep until interrupted by SIGTERM, at which point
	 *	it's time to stop tcpbsi.				*/
{
    char    txt[500];

    if (atp.domain == AF_INET)
    {
        isprintf(txt, sizeof(txt),
           "[i] tcpbsi is running, spec=[%s:%d].", 
			inet_ntoa(atp.inetName->sin_addr), ntohs(portNbr));
        writeMemo(txt);
    }
    else if (atp.domain == AF_INET6)
    {
        char hostStr[INET6_ADDRSTRLEN];
        inet_ntop(atp.domain, hostAddr, hostStr, INET6_ADDRSTRLEN);

        isprintf(txt, sizeof(txt),
            "[i] tcpbsi is running, spec=[%s:%d].", 
            hostStr, ntohs(portNbr));
        writeMemo(txt);
    }
}

	ionPauseMainThread(-1);

	/*	Time to shut down.					*/

	atp.running = 0;

	/*	Wake up the access thread by connecting to it.		*/

	fd = socket(atp.domain, SOCK_STREAM, IPPROTO_TCP);
	if (fd >= 0)
	{
		oK(connect(fd, (struct sockaddr *) &(atp.socketName), sizeof(struct sockaddr_storage)));

		/*	Immediately discard the connected socket.	*/

		closesocket(fd);
	}

	pthread_join(accessThread, NULL);
	writeErrmsgMemos();
	writeMemo("[i] tcpbsi has ended.");
	ionDetach();
	return 0;
}
