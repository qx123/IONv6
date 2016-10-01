/*
 *	udpbsi.c:	BSSP UDP-based link service input daemon.
 *
 *	Authors: Sotirios-Angelos Lenas, SPICE
 *		 Scott Burleigh, JPL
 *
 *	Copyright (c) 2013, California Institute of Technology.
 *	Copyright (c) 2013, Space Internetworking Center,
 *	Democritus University of Thrace.
 *	
 *	All rights reserved. U.S. Government and E.U. Sponsorship acknowledged.
 */

#include "udpbsa.h"

static void	interruptThread()
{
	isignal(SIGTERM, interruptThread);
	ionKillMainThread("udpbsi");
}

/*	*	*	Receiver thread functions	*	*	*/

typedef struct
{
	int		linkSocket;
	int		running;
} ReceiverThreadParms;

static void	*handleDatagrams(void *parm)
{
	/*	Main loop for UDP datagram reception and handling.	*/

	ReceiverThreadParms	*rtp = (ReceiverThreadParms *) parm;
	char			*procName = "udpbsi";
	char			*buffer;
	int			blockLength;
	struct sockaddr_in	fromAddr;
	socklen_t		fromSize;

	snooze(1);	/*	Let main thread become interruptable.	*/
	buffer = MTAKE(UDPBSA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("udpbsi can't get UDP buffer.", NULL);
		ionKillMainThread(procName);
		return NULL;
	}

	/*	Can now start receiving bundles.  On failure, take
	 *	down the BSI.						*/

	while (rtp->running)
	{	
		fromSize = sizeof fromAddr;
		blockLength = irecvfrom(rtp->linkSocket, buffer, UDPBSA_BUFSZ,
				0, (struct sockaddr *) &fromAddr, &fromSize);
		switch (blockLength)
		{
		case -1:
			putSysErrmsg("Can't acquire block", NULL);
			ionKillMainThread(procName);

			/*	Intentional fall-through to next case.	*/

		case 1:				/*	Normal stop.	*/
			rtp->running = 0;
			continue;
		}

		if (bsspHandleInboundBlock(buffer, blockLength) < 0)
		{
			putErrmsg("Can't handle inbound block.", NULL);
			ionKillMainThread(procName);
			rtp->running = 0;
			continue;
		}

		/*	Make sure other tasks have a chance to run.	*/

		sm_TaskYield();
	}

	writeErrmsgMemos();
	writeMemo("[i] udpbsi receiver thread has ended.");

	/*	Free resources.						*/

	MRELEASE(buffer);
	return NULL;
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined (ION_LWT)
int	udpbsi(int a1, int a2, int a3, int a4, int a5,
		int a6, int a7, int a8, int a9, int a10)
{
	char	*endpointSpec = (char *) a1;
#else
int	main(int argc, char *argv[])
{
	char	*endpointSpec = (argc > 1 ? argv[1] : NULL);
#endif
	BsspVdb			*vdb;
	unsigned short		portNbr = 0;
	unsigned int		ipAddress = INADDR_ANY;
	unsigned char 		hostAddr[sizeof(struct in6_addr)];
	struct sockaddr_storage		socketName;
	struct sockaddr_in	*inetName;
	struct sockaddr_in6	*inet6Name;
	int 				domain;
	ReceiverThreadParms	rtp;
	socklen_t		nameLength;
	pthread_t		receiverThread;
	int			fd;
	char			quit = '\0';

	/*	Note that bsspadmin must be run before the first
	 *	invocation of bsspbsi, to initialize the BSSP database
	 *	(as necessary) and dynamic database.			*/ 

	if (bsspInit(0) < 0)
	{
		putErrmsg("udpbsi can't initialize BSSP.", NULL);
		return 1;
	}

	vdb = getBsspVdb();
	if (vdb->beBsiPid != ERROR && vdb->beBsiPid != sm_TaskIdSelf())
	{
		putErrmsg("BE-BSI task is already started.",
				itoa(vdb->beBsiPid));
		return 1;
	}

	/*	All command-line arguments are now validated.		*/

	if (endpointSpec)
	{
		if((domain = parseSocketSpec(endpointSpec, &portNbr, hostAddr)) < 0)
		{
			putErrmsg("BE-BSI Can't get IP/port for endpointSpec.",
					endpointSpec);
			return -1;
		}
	}
	if (portNbr == 0)
	{
		portNbr = BsspUdpDefaultPortNbr;
	}
	portNbr = htons(portNbr);

	memset((char *) &socketName, 0, sizeof socketName);
	if (domain == AF_INET)
	{
		inetName = (struct sockaddr_in *) &socketName;
		inetName->sin_family = AF_INET;
		inetName->sin_port = portNbr;
		memcpy((char *) &(inetName->sin_addr.s_addr), (char *) hostAddr, 4);
		rtp.linkSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (domain == AF_INET6)
	{
		inet6Name = (struct sockaddr_in6 *) &socketName;
		inet6Name->sin6_family = AF_INET6;
		inet6Name->sin6_port = portNbr;
		memcpy((char *) &(inet6Name->sin6_addr.s6_addr), (char *) hostAddr, 16);
		rtp.linkSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	if (rtp.linkSocket < 0)
	{
		putSysErrmsg("BE-BSI can't open UDP socket", NULL);
		return -1;
	}

	nameLength = sizeof(struct sockaddr_storage);
	if (reUseAddress(rtp.linkSocket)
	|| bind(rtp.linkSocket, (struct sockaddr *) &socketName, nameLength) < 0
	|| getsockname(rtp.linkSocket, (struct sockaddr *) &socketName, &nameLength) < 0)
	{
		closesocket(rtp.linkSocket);
		putSysErrmsg("BE-BSI Can't initialize socket", NULL);
		return 1;
	}

	/*	Set up signal handling; SIGTERM is shutdown signal.	*/

	ionNoteMainThread("udpbsi");
	isignal(SIGTERM, interruptThread);

	/*	Start the receiver thread.				*/

	rtp.running = 1;
	if (pthread_begin(&receiverThread, NULL, handleDatagrams, &rtp))
	{
		closesocket(rtp.linkSocket);
		putSysErrmsg("udpbsi can't create receiver thread", NULL);
		return 1;
	}

	/*	Now sleep until interrupted by SIGTERM, at which point
	 *	it's time to stop the link service.			*/

	{
		char    txt[500];

		if (domain == AF_INET)
		{
			isprintf(txt, sizeof(txt),
				"[i] udpbsi is running, spec=[%s:%d].", 
				inet_ntoa(inetName->sin_addr), ntohs(portNbr));
			writeMemo(txt);
		}
		else if (domain == AF_INET6)
		{
			char hostStr[INET6_ADDRSTRLEN];
			inet_ntop(domain, hostAddr, hostStr, INET6_ADDRSTRLEN);

			isprintf(txt, sizeof(txt),
				"[i] udpbsi is running, spec=[%s:%d].", 
				hostStr, ntohs(portNbr));
			writeMemo(txt);
		}
	}

	/*	Time to shut down.					*/

	rtp.running = 0;

	/*	Wake up the receiver thread by sending it a 1-byte
	 *	datagram.						*/

	fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
	if (fd >= 0)
	{
		isendto(fd, &quit, 1, 0, (struct sockaddr *) &socketName, sizeof(struct sockaddr_storage));
		closesocket(fd);
	}

	pthread_join(receiverThread, NULL);
	closesocket(rtp.linkSocket);
	writeErrmsgMemos();
	writeMemo("[i] udpbsi has ended.");
	ionDetach();
	return 0;
}
