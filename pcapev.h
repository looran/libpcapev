/* libpcapev - libpcap helper using libevent */

/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LIBPCAPEV_H_
#define _LIBPCAPEV_H_

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>

#include "queue.h"

#define PCAPEV_PROMISC 1
#define PCAPEV_NOPROMISC 0
#define PCAPEV_NOFILTER NULL
#define PCAPEV_VERBOSE 1
#define PCAPEV_NOVERBOSE 0

struct pcapev {
	pcap_t		*pcap;
	struct event	*ev;
	pcap_handler	 handler;
	int		 verbose;
	int		 pinvalid;
	int		 ptruncated;
	int		 pfragmented;
	LIST_HEAD(, pcapev_cb) cbusr_ether;
	LIST_HEAD(, pcapev_cb) cbusr_arp;
	LIST_HEAD(, pcapev_cb) cbusr_ip;
	LIST_HEAD(, pcapev_cb) cbusr_tcp;
	LIST_HEAD(, pcapev_cb) cbusr_udp;
	LIST_HEAD(, pcapev_cb) cbusr_icmp;
};

struct pcapev_cb {
	LIST_ENTRY(pcapev_cb) entry;
	union {
		struct {
			int (*func)(struct pcapev *, struct ether_header *, int);
		} ether;
		struct {
			int (*func)(struct pcapev *, struct arphdr *, int, struct ether_header *);
		} arp;
		struct {
			int (*func)(struct pcapev *, struct ip *, int, struct ether_header *);
		} ip;
		struct {
			int (*func)(struct pcapev *, struct tcphdr *, int, struct ip *, struct ether_header *);
			int flags;
		} tcp;
		struct {
			int (*func)(struct pcapev *, struct udphdr *, int, struct ip *, struct ether_header *);
		} udp;
		struct {
			int (*func)(struct pcapev *, struct icmphdr *, int, struct ip *, struct ether_header *);
		} icmp;
	} cb;
};

struct pcapev	*pcapev_new(struct event_base *ev_base, char *iface, int snaplen, int promisc, char *filter, int verbose);
int		 pcapev_start(struct pcapev *cap);
void		 pcapev_stop(struct pcapev *cap);
void		 pcapev_free(struct pcapev *cap);

void		 pcapev_addcb_ether(struct pcapev *cap,
			int (*)(struct pcapev *, struct ether_header *, int));
void		 pcapev_addcb_arp(struct pcapev *cap,
			int (*)(struct pcapev *, struct arphdr *, int, struct ether_header *));
void		 pcapev_addcb_ip(struct pcapev *cap,
			int (*)(struct pcapev *, struct ip *, int, struct ether_header *));
void		 pcapev_addcb_tcp(struct pcapev *cap, int flags,
			int (*)(struct pcapev *, struct tcphdr *, int, struct ip *, struct ether_header *));
void		 pcapev_addcb_udp(struct pcapev *cap,
			int (*)(struct pcapev *, struct udphdr *, int, struct ip *, struct ether_header *));
void		 pcapev_addcb_icmp(struct pcapev *cap,
			int (*)(struct pcapev *, struct icmphdr *, int, struct ip *, struct ether_header *));

#endif /* _LIBPCAPEV_H_ */
