/*
 *	tcpbso.c:	BSSP TCP-based link service output daemon.
 *			Dedicated to TCP blocks transmission to a 
 *			single remote BSSP engine.
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

static sm_SemId	tcpbsoSemaphore(sm_SemId *semid)
{
	long		temp;
	void		*value;
	sm_SemId	semaphore;

	if (semid)			/*	Add task variable.	*/
	{
		temp = *semid;
		value = (void *) temp;
		value = sm_TaskVar(&value);
	}
	else				/*	Retrieve task variable.	*/
	{
		value = sm_TaskVar(NULL);
	}

	temp = (long) value;
	semaphore = temp;
	return semaphore;
}

static void	shutDownBso()	/*	Commands CLO termination.	*/
{
	isignal(SIGTERM, shutDownBso);
	sm_SemEnd(tcpbsoSemaphore(NULL));
}

/*	*	*	Keepalive thread functions	*	*	*/

typedef struct
{
	int		*bsoRunning;
	pthread_mutex_t	*mutex;
	struct sockaddr_storage	*socketName;
	int		*flowSocket;
} KeepaliveThreadParms;

static void	*sendKeepalives(void *parm)
{
	KeepaliveThreadParms	*parms = (KeepaliveThreadParms *) parm;
	int			count = KEEPALIVE_PERIOD;
	int			bytesSent;

	iblock(SIGTERM);
	while (*(parms->bsoRunning))
	{
		snooze(1);
		count++;
		if (count < KEEPALIVE_PERIOD)
		{
			continue;
		}

		/*	Time to send a keepalive.  Note that the
		 *	interval between keepalive attempts will be
		 *	KEEPALIVE_PERIOD plus (if the remote inflow
		 *	is not reachable) the length of time taken
		 *	by TCP to determine that the connection
		 *	attempt will not succeed (e.g., 3 seconds).	*/

		count = 0;
		pthread_mutex_lock(parms->mutex);
		bytesSent = sendBlockByTCP((struct sockaddr *) &(parms->socketName),
				parms->flowSocket, 0, NULL);
		pthread_mutex_unlock(parms->mutex);
		if (bytesSent < 0)
		{
			shutDownBso();
			break;
		}
	}

	return NULL;
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined (ION_LWT)
int	tcpbso(int a1, int a2, int a3, int a4, int a5,
		int a6, int a7, int a8, int a9, int a10)
{
	char	*flowName = (char *) a1;
	uvast	remoteEngineId = a2 != 0 ? strtouvast((char *) a2) : 0;
#else
int	main(int argc, char *argv[])
{
	char	*flowName = (argc > 1 ? argv[1] : NULL);
	uvast	remoteEngineId = argc > 2 ? strtouvast(argv[2]) : 0;
#endif
	Sdr			sdr;
	BsspVspan		*vspan;
	PsmAddress		vspanElt;
	char			*hostName;
	unsigned short		portNbr;
	// unsigned int		hostNbr;
	unsigned char 		hostAddr[sizeof(struct in6_addr)];
	struct sockaddr_storage		socketName;
	struct sockaddr_in	*inetName;
	struct sockaddr_in6	*inet6Name;
	int 		domain;
	int			running = 1;
	pthread_mutex_t		mutex;
	KeepaliveThreadParms	parms;
	pthread_t		keepaliveThread;
	int			blockLength;
	char			*block;
	int			flowSocket = -1;
	int			bytesSent;

	if (remoteEngineId == 0 || flowName == NULL)
	{
		PUTS("Usage: tcpbso <remote host name>[:<port number>] <remote \
engine number>");
		return 0;
	}

	if (bsspInit(0) < 0)
	{
		putErrmsg("tcpbso can't initialize BSSP.", NULL);
		return 1;
	}

	sdr = getIonsdr();
	CHKZERO(sdr_begin_xn(sdr));	/*	Just to lock memory.	*/
	findSpan(remoteEngineId, &vspan, &vspanElt);
	if (vspanElt == 0)
	{
		sdr_exit_xn(sdr);
		putErrmsg("No such engine in database.", itoa(remoteEngineId));
		return 1;
	}

	if (vspan->bsoRLPid != ERROR && vspan->bsoRLPid != sm_TaskIdSelf())
	{
		sdr_exit_xn(sdr);
		putErrmsg("TCP-BSO task is already started for this span.",
				itoa(vspan->bsoRLPid));
		return 1;
	}

	sdr_exit_xn(sdr);

	/*	All command-line arguments are now validated.		*/

	hostName = flowName;
	domain = parseSocketSpec(flowName, &portNbr, hostAddr);
	if (portNbr == 0)
	{
		portNbr = bsspTcpDefaultPortNbr;
	}

	portNbr = htons(portNbr);
	// if (hostNbr == 0)
	if ((domain == AF_INET && (unsigned int *) hostAddr == INADDR_ANY)
		|| (domain == AF_INET6 && memcmp(hostAddr, &in6addr_any, 16) == 0))
	{
		putErrmsg("Can't get IP address for host.", hostName);
		return -1;
	}

	memset((char *) &socketName, 0, sizeof socketName);
	if (domain == AF_INET)
	{
		inetName = (struct sockaddr_in *) &socketName;
		inetName->sin_family = AF_INET;
		inetName->sin_port = portNbr;
		memcpy((char *) &(inetName->sin_addr.s_addr), (char *) hostAddr, 4);
	}
	else if (domain == AF_INET6)
	{
		inet6Name = (struct sockaddr_in6 *) &socketName;
		inet6Name->sin6_family = AF_INET6;
		inet6Name->sin6_port = portNbr;
		memcpy((char *) &(inet6Name->sin6_addr.s6_addr), (char *) hostAddr, 16);
	}

	/*	Set up signal handling.  SIGTERM is shutdown signal.	*/

	oK(tcpbsoSemaphore(&(vspan->rlSemaphore)));
	isignal(SIGTERM, shutDownBso);
#ifndef mingw
	isignal(SIGPIPE, itcp_handleConnectionLoss);
#endif

	/*	Start the keepalive thread to manage the connection.	*/

	parms.bsoRunning = &running;
	pthread_mutex_init(&mutex, NULL);
	parms.mutex = &mutex;
	parms.socketName = &socketName;
	parms.flowSocket = &flowSocket;
	if (pthread_begin(&keepaliveThread, NULL, sendKeepalives, &parms))
	{
		putSysErrmsg("tcpbso can't create keepalive thread", NULL);
		pthread_mutex_destroy(&mutex);
		return 1;
	}

	/*	Can now begin transmitting to remote flow.		*/

	{
		char    txt[500];

		if (domain == AF_INET)
		{
			isprintf(txt, sizeof(txt),
				"[i] tcpbso is running, spec=[%s:%d].", 
				inet_ntoa(inetName->sin_addr), ntohs(portNbr));
			writeMemo(txt);
		}
		else if (domain == AF_INET6)
		{
			char hostStr[INET6_ADDRSTRLEN];
			inet_ntop(domain, hostAddr, hostStr, INET6_ADDRSTRLEN);

			isprintf(txt, sizeof(txt),
				"[i] tcpbso is running, spec=[%s:%d].", 
				hostStr, ntohs(portNbr));
			writeMemo(txt);
		}
	}

	while (!(sm_SemEnded(tcpbsoSemaphore(NULL))))
	{
		
		blockLength = bsspDequeueRLOutboundBlock(vspan, &block);
		if (blockLength < 0)
		{
			sm_SemEnd(tcpbsoSemaphore(NULL));/*	Stop BSO.*/
			continue;
		}

		if (blockLength == 0)		/*	Interrupted.	*/
		{
			continue;
		}

		if (blockLength > TCPBSA_BUFSZ)
		{
			putErrmsg("Block is too big for TCP BSO.",
					itoa(blockLength));
			sm_SemEnd(tcpbsoSemaphore(NULL));/*	Stop BSO.*/
		}
		else
		{
			pthread_mutex_lock(&mutex);
			bytesSent = sendBlockByTCP((struct sockaddr *) &socketName, &flowSocket,
					blockLength, block);
			pthread_mutex_unlock(&mutex);
			if (bytesSent < blockLength)	/*	Stop BSO.*/
			{
				sm_SemEnd(tcpbsoSemaphore(NULL));
				continue;
			}
		}
		
		/*	Make sure other tasks have a chance to run.	*/

		sm_TaskYield();
	}

	running = 0;		/*	Terminate keepalive thread.	*/
	pthread_join(keepaliveThread, NULL);
	if (flowSocket != -1)
	{
		closesocket(flowSocket);
	}

	pthread_mutex_destroy(&mutex);
	writeErrmsgMemos();
	writeMemo("[i] tcpbso has ended.");
	return 0;
}
