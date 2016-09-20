# IONv6

## Introduction

Interplanetary Overlay Network (ION) software distribution is an implementation of Delay-Tolerant Networking (DTN) architecture as described in Internet RFC 4838.

This is a suite of communication protocol implementations designed to support mission operation communications across an end-to-end interplanetary network, which might include on-board (flight) subnets, in-situ planetary or lunar networks, proximity links, deep space links, and terrestrial internets.

Included in the ION software distribution are the following packages:

* ici (interplanetary communication infrastructure) a set of libraries that provide flight-software-compatible support for functions on which the other packages rely.
* bp (bundle protocol), an implementation of the Delay-Tolerant Networking (DTN) architecture's Bundle Protocol.
* dgr (datagram retransmission), a UDP reliability system that implements congestion control and is designed for relatively high performance.
* ltp (licklider transmission protocol), a DTN convergence layer for reliable transmission over links characterized by long or highly variable delay.
* ams - an implementation of the CCSDS Asynchronous Message Service.
* cfdp - a class-1 (Unacknowledged) implementation of the CCSDS File Delivery Protocol.