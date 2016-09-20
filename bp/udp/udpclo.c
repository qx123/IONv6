/*
	udpclo.c:	BP UDP-based convergence-layer output
			daemon.  Note that this convergence-layer
			output daemon is a "promiscuous" CLO daemon
			which can transmit bundles to any number of
			different peers.

	Author: Ted Piotrowski, APL
		Scott Burleigh, JPL

	Copyright (c) 2006, California Institute of Technology.
	ALL RIGHTS RESERVED.  U.S. Government Sponsorship
	acknowledged.
	
									*/
#include "udpcla.h"

static sm_SemId		udpcloSemaphore(sm_SemId *semid)
{
	static sm_SemId	semaphore = -1;
	
	if (semid)
	{
		semaphore = *semid;
	}

	return semaphore;
}

static void	shutDownClo()	/*	Commands CLO termination.	*/
{
	sm_SemEnd(udpcloSemaphore(NULL));
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined (ION_LWT)
int	udpclo(int a1, int a2, int a3, int a4, int a5,
		int a6, int a7, int a8, int a9, int a10)
{
#else
int	main(int argc, char *argv[])
{
#endif
	unsigned char		*buffer;
	VOutduct		*vduct;
	PsmAddress		vductElt;
	Sdr			sdr;
	Outduct			outduct;
	ClProtocol		protocol;
	Outflow			outflows[3];
	int			i;
    int         domain;
	unsigned short		portNbr;
	unsigned int		hostNbr, *pHostNbr;
    unsigned char       hostAddr[sizeof(struct in6_addr)];
	struct sockaddr_storage		socketName;
	Object			bundleZco;
	BpExtendedCOS		extendedCOS;
	char			destDuctName[MAX_CL_DUCT_NAME_LEN + 1];
	unsigned int		bundleLength;
	int			ductSocket = -1;
	int			bytesSent;

	if (bpAttach() < 0)
	{
		putErrmsg("udpclo can't attach to BP.", NULL);
		return -1;
	}

	buffer = MTAKE(UDPCLA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("No memory for UDP buffer in udpclo.", NULL);
		return -1;
	}

	findOutduct("udp", "*", &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such udp duct.", "*");
		MRELEASE(buffer);
		return -1;
	}

	if (vduct->cloPid != ERROR && vduct->cloPid != sm_TaskIdSelf())
	{
		putErrmsg("CLO task is already started for this duct.",
				itoa(vduct->cloPid));
		MRELEASE(buffer);
		return -1;
	}

	/*	All command-line arguments are now validated.		*/

	sdr = getIonsdr();
	CHKZERO(sdr_begin_xn(sdr));
	sdr_read(sdr, (char *) &outduct, sdr_list_data(sdr, vduct->outductElt),
			sizeof(Outduct));
	sdr_read(sdr, (char *) &protocol, outduct.protocol, sizeof(ClProtocol));
	sdr_exit_xn(sdr);
	memset((char *) outflows, 0, sizeof outflows);
	outflows[0].outboundBundles = outduct.bulkQueue;
	outflows[1].outboundBundles = outduct.stdQueue;
	outflows[2].outboundBundles = outduct.urgentQueue;
	for (i = 0; i < 3; i++)
	{
		outflows[i].svcFactor = 1 << i;
	}

	/*	Set up signal handling.  SIGTERM is shutdown signal.	*/

	oK(udpcloSemaphore(&(vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);

	/*	Can now begin transmitting to remote duct.		*/

	writeMemo("[i] udpclo is running.");
	while (!(sm_SemEnded(vduct->semaphore)))
	{
		if (bpDequeue(vduct, outflows, &bundleZco, &extendedCOS,
				destDuctName, outduct.maxPayloadLen, 0) < 0)
		{
			putErrmsg("Can't dequeue bundle.", NULL);
			break;
		}

		if (bundleZco == 0)	/*	Outduct closed.		*/
		{
			writeMemo("[i] udpclo outduct closed.");
			sm_SemEnd(udpcloSemaphore(NULL));/*	Stop.	*/
			continue;
		}

		domain = parseSocketSpec(destDuctName, &portNbr, hostAddr);
		if (portNbr == 0)
		{
			portNbr = BpUdpDefaultPortNbr;
		}

		portNbr = htons(portNbr);
        memset((char *) &socketName, 0, sizeof socketName);

        if (domain == AF_INET)
        {
            struct sockaddr_in *inetName = (struct sockaddr_in *) &socketName;
            pHostNbr = &hostNbr;
            memcpy((char *) pHostNbr, (char *) hostAddr, 4);
            if (hostNbr == 0)	/*	Can't send bundle.	*/
            {
                writeMemoNote("[?] Can't get IP address for host",
                        destDuctName);
                CHKZERO(sdr_begin_xn(sdr));
                zco_destroy(sdr, bundleZco);
                if (sdr_end_xn(sdr) < 0)
                {
                    putErrmsg("Can't destroy ZCO reference.", NULL);
                    sm_SemEnd(udpcloSemaphore(NULL));
                }

                continue;
            }
			
            inetName->sin_family = AF_INET;
            inetName->sin_port = portNbr;
            memcpy((char *) &(inetName->sin_addr.s_addr), (char *) hostAddr, 4);
        }
        else if (domain == AF_INET6)
        {
            struct sockaddr_in6 *inet6Name = (struct sockaddr_in6 *) &socketName;
            pHostNbr = &hostNbr;
            memcpy((char *) pHostNbr, (char *) hostAddr, 4);
            if ((struct in6_addr *) hostAddr == in6addr_any)	/*	Can't send bundle.	*/
            {
                writeMemoNote("[?] Can't get IP address for host",
                        destDuctName);
                CHKZERO(sdr_begin_xn(sdr));
                zco_destroy(sdr, bundleZco);
                if (sdr_end_xn(sdr) < 0)
                {
                    putErrmsg("Can't destroy ZCO reference.", NULL);
                    sm_SemEnd(udpcloSemaphore(NULL));
                }

                continue;
            }

            inet6Name->sin6_family = AF_INET6;
            inet6Name->sin6_port = portNbr;
            memcpy((char *) &(inet6Name->sin6_addr.s6_addr), (char *) hostAddr, 16);
        }

		CHKZERO(sdr_begin_xn(sdr));
		bundleLength = zco_length(sdr, bundleZco);
		sdr_exit_xn(sdr);
		bytesSent = sendBundleByUDP((struct sockaddr *) &socketName, &ductSocket,
				bundleLength, bundleZco, buffer);
		if (bytesSent < bundleLength)
		{
			sm_SemEnd(udpcloSemaphore(NULL));/*	Stop.	*/
			continue;
		}

		/*	Make sure other tasks have a chance to run.	*/

		sm_TaskYield();
	}

	if (ductSocket != -1)
	{
		closesocket(ductSocket);
	}

	writeErrmsgMemos();
	writeMemo("[i] udpclo duct has ended.");
	MRELEASE(buffer);
	ionDetach();
	return 0;
}
