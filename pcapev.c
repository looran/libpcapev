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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>

#if !defined(__OpenBSD__)
#define __FAVOR_BSD
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in_systm.h>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <err.h>

#include <pcap.h>
#if defined(__linux__)
#include <pcap/sll.h>
#endif
#include <event.h>

#include "pcapev.h"

#define NOTCAPTURED(v) ((u_char *)v > (u_char *)pend - sizeof(*v))
#define NOTRECEIVED(v) (wirelen < sizeof(v))
#define LOG(x, ...) printf(x, ##__VA_ARGS__)
#define LOG_DEBUG(x, ...) if (cap->verbose) printf(x, ##__VA_ARGS__);
#define LOG_PINVALID(x, ...) printf("Invalid packet: " x, ##__VA_ARGS__);
#define ERR_RETURN(retval, x, ...) { printf("Error: " x, ##__VA_ARGS__); return retval; }

struct phandler {
	pcap_handler f;
	int type;
};

static pcap_t		*_my_pcap_open_live(const char *, int, int, int, char *, u_int, u_int);
static void	 	_cb_pcap(int, short, void *);
static pcap_handler	_phandler_lookup(int);
static void		_phandler_ether(u_char *, const struct pcap_pkthdr *, const u_char *);
#if defined(__OpenBSD__)
static void		_phandler_loop(u_char *, const struct pcap_pkthdr *, const u_char *);
#endif
#if defined(__linux__)
static void		_phandler_sll(u_char *, const struct pcap_pkthdr *, const u_char *);
#endif
static void		_ether(struct pcapev *, struct ether_header *, const u_char *, u_int);
static void		_ip(struct pcapev *, struct ip *, const u_char *, u_int, struct ether_header *);

static struct phandler phandlers[] = {
	{ _phandler_ether, DLT_EN10MB },
	{ _phandler_ether, DLT_IEEE802 },
#if defined(__OpenBSD__)
	{ _phandler_loop,  DLT_LOOP },
#endif
#if defined(__linux__)
	{ _phandler_sll,   DLT_LINUX_SLL },
#endif
	{ NULL,           0 },
};

struct pcapev *
pcapev_new(struct event_base *ev_base,
	char *iface, int snaplen, int promisc, char *filter, int verbose)
{
	struct pcapev *cap;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bprog;
	pcap_t *pcap;

	cap = calloc(1, sizeof(struct pcapev));
	if (!cap)
		return NULL;

#if defined(__OpenBSD__)
	if (!iface)
		ERR_RETURN(NULL, "On OpenBSD you cannot listen on ANY interface");
#endif
	// XXX not clear why i have to use a timeout here
	pcap = _my_pcap_open_live(iface, snaplen, promisc, 300, errbuf, -1, 0);
	if (!pcap)
		ERR_RETURN(NULL, "pcap_open_live failed on interface %s with snaplen %d : %s\n",
				iface, snaplen, errbuf);
	if (filter) {
		if (pcap_compile(pcap, &bprog, filter, 0, 0) < 0)
			ERR_RETURN(NULL, "pcap_compile failed with filter %s : %s",
					filter, pcap_geterr(pcap));
		if (pcap_setfilter(pcap, &bprog) < 0)
			ERR_RETURN(NULL, "pcap_setfilter failed : %s",
					pcap_geterr(pcap));
	}

	cap->handler = _phandler_lookup(pcap_datalink(pcap));
	pcap_setnonblock(pcap, 1, errbuf);
	//pcap_set_buffer_size(pcap, 100000);
	cap->pcap = pcap;
	cap->ev = event_new(ev_base, pcap_get_selectable_fd(pcap), EV_READ|EV_PERSIST,
			_cb_pcap, cap);
	cap->verbose = verbose;

	return cap;
}

int
pcapev_start(struct pcapev *cap)
{
	return event_add(cap->ev, NULL);
}

void
pcapev_stop(struct pcapev *cap)
{
	event_del(cap->ev);
}

void
pcapev_free(struct pcapev *cap)
{
	event_del(cap->ev);
	pcap_close(cap->pcap);
}

void pcapev_addcb_ether(struct pcapev *cap,
			int (*func)(struct pcapev *, struct ether_header *, int, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.ether.func = func;
	LIST_INSERT_HEAD(&cap->cbusr_ether, cbusr, entry);
	cbusr->arg = arg;
}

void pcapev_addcb_arp(struct pcapev *cap,
			int (*func)(struct pcapev *, struct arphdr *, int, struct ether_header *, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.arp.func = func;
	LIST_INSERT_HEAD(&cap->cbusr_arp, cbusr, entry);
	cbusr->arg = arg;
}

void pcapev_addcb_ip(struct pcapev *cap,
			int (*func)(struct pcapev *, struct ip *, int, struct ether_header *, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.ip.func = func;
	LIST_INSERT_HEAD(&cap->cbusr_ip, cbusr, entry);
	cbusr->arg = arg;
}

void pcapev_addcb_tcp(struct pcapev *cap, int flags,
			int (*func)(struct pcapev *, struct tcphdr *, int, struct ip *, struct ether_header *, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.tcp.func = func;
	cbusr->cb.tcp.flags = flags;
	LIST_INSERT_HEAD(&cap->cbusr_tcp, cbusr, entry);
	cbusr->arg = arg;
}

void pcapev_addcb_udp(struct pcapev *cap,
			int (*func)(struct pcapev *, struct udphdr *, int, struct ip *, struct ether_header *, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.udp.func = func;
	LIST_INSERT_HEAD(&cap->cbusr_udp, cbusr, entry);
	cbusr->arg = arg;
}

void pcapev_addcb_icmp(struct pcapev *cap,
			int (*func)(struct pcapev *, struct icmphdr *, int, struct ip *, struct ether_header *, void *),
			void *arg)
{
	struct pcapev_cb *cbusr;

	cbusr = calloc(1, sizeof(struct pcapev_cb));
	cbusr->cb.icmp.func = func;
	LIST_INSERT_HEAD(&cap->cbusr_icmp, cbusr, entry);
	cbusr->arg = arg;
}

/*
 * reimplement pcap_open_live with more restrictions on the bpf fd :
 * - open device read only
 * - lock the fd
 * based on OpenBSD tcpdump, privsep_pcap.c v1.16
 */
static pcap_t *
_my_pcap_open_live(const char *dev, int slen, int promisc, int to_ms,
		char *ebuf, u_int dlt, u_int dirfilt)
{
#if defined(__OpenBSD__)
	struct bpf_version bv;
	u_int v;
	pcap_t *p;
	char		bpf[sizeof "/dev/bpf0000000000"];
	int		fd, n = 0;
	struct ifreq	ifr;

	p = xmalloc(sizeof(*p));
	bzero(p, sizeof(*p));

	/* priv part */

	do {
		snprintf(bpf, sizeof(bpf), "/dev/bpf%d", n++);
		fd = open(bpf, O_RDONLY);
	} while (fd < 0 && errno == EBUSY);
	if (fd < 0)
		return NULL;

	v = 32768;	/* XXX this should be a user-accessible hook */
	ioctl(fd, BIOCSBLEN, &v);

	strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) < 0)
		return NULL;

	if (dlt != (u_int) -1 && ioctl(fd, BIOCSDLT, &dlt))
		return NULL;

	if (promisc)
		/* this is allowed to fail */
		ioctl(fd, BIOCPROMISC, NULL);
	if (ioctl(fd, BIOCSDIRFILT, &dirfilt) < 0)
		return NULL;

	/* lock the descriptor */
	if (ioctl(fd, BIOCLOCK, NULL) < 0)
		return NULL;

	/* end of priv part */

	/* fd is locked, can only use 'safe' ioctls */
	if (ioctl(fd, BIOCVERSION, &bv) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCVERSION: %s",
				pcap_strerror(errno));
		return NULL;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
			bv.bv_minor < BPF_MINOR_VERSION) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
				"kernel bpf filter out of date");
		return NULL;
	}

	p->fd = fd;
	p->snapshot = slen;

	/* Get the data link layer type. */
	if (ioctl(fd, BIOCGDLT, &v) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCGDLT: %s",
				pcap_strerror(errno));
		return NULL;
	}
#if _BSDI_VERSION - 0 >= 199510
	/* The SLIP and PPP link layer header changed in BSD/OS 2.1 */
	switch (v) {

		case DLT_SLIP:
			v = DLT_SLIP_BSDOS;
			break;

		case DLT_PPP:
			v = DLT_PPP_BSDOS;
			break;
	}
#endif
	p->linktype = v;

	/* XXX hack from tcpdump */
	if (p->linktype == DLT_PFLOG && p->snapshot < 160)
		p->snapshot = 160;

	/* set timeout */
	if (to_ms != 0) {
		struct timeval to;
		to.tv_sec = to_ms / 1000;
		to.tv_usec = (to_ms * 1000) % 1000000;
		if (ioctl(p->fd, BIOCSRTIMEOUT, &to) < 0) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCSRTIMEOUT: %s",
					pcap_strerror(errno));
			return NULL;
		}
	}

	if (ioctl(fd, BIOCGBLEN, &v) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCGBLEN: %s",
				pcap_strerror(errno));
		return NULL;
	}
	p->bufsize = v;
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
				pcap_strerror(errno));
		return NULL;
	}
	return p;
#else
	return pcap_open_live(dev, slen, promisc, to_ms, ebuf);
#endif
}

static void
_cb_pcap(int fd, short why, void *data)
{
	struct pcapev *cap;

	cap = data;
	while (!pcap_dispatch(cap->pcap, 1, cap->handler, (u_char *)cap));
}

static pcap_handler
_phandler_lookup(int type)
{
	struct phandler *p;

	for (p = phandlers; p->f; ++p) {
		if (type == p->type)
			return p->f;
	}
	err(1, "user: unknown data link type 0x%x", type);
	/* NOTREACHED */
	return NULL;
}

static void
_phandler_ether(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	struct pcapev *cap;
	struct ether_header *ep;
	const u_char *pend;
	u_int	len;

	cap = (struct pcapev *)user;
	LOG_DEBUG("_phandler_ether\n");

	/* XXX here i assume that packets are alligned, which might not
	 * be the case when using dump files, says tcpdump sources */

	ep = (struct ether_header *)p;
	pend = p + h->caplen;
	len = h->len - sizeof(struct ether_header);

	_ether(cap, ep, pend, len);
}

/*
 * Handler for Linux cooked, used when capturing on any interface
 */
#if defined(__linux__)
#define LINUX_SLL_P_802_3	0x0001	/* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_ETHERNET	0x0003	/* Ethernet */
#define LINUX_SLL_P_802_2	0x0004	/* 802.2 frames (not D/I/X Ethernet) */
#define LINUX_SLL_P_PPPHDLC	0x0007	/* PPP HDLC frames */
#define LINUX_SLL_P_CAN		0x000C	/* Controller Area Network */
#define LINUX_SLL_P_IRDA_LAP	0x0017	/* IrDA Link Access Protocol */

static void
_phandler_sll(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	struct pcapev *cap;
	struct ip *ip;
	struct ether_header *ep;
	u_int family;
	const u_char *pend;
	u_int	len;

	cap = (struct pcapev *)user;
	LOG_DEBUG("_phandler_sll\n");

	/* XXX here i assume that packets are alligned, which might not
	 * be the case when using dump files, says tcpdump sources */

	pend = p + h->caplen;
	len = h->len - SLL_HDR_LEN;

	family = ntohs(p[14]);
	if (family < 1536) { /* linux and wireshark are good for you */
		switch (family) {
			case LINUX_SLL_P_ETHERNET:
				ep = (struct ether_header *)((u_char *)p + SLL_HDR_LEN);
				_ether(cap, ep, pend, len);
			default:
				LOG_DEBUG("unknown family %x !\n", family);
				break;
		}
	} else {
		ip = (struct ip *)(p + SLL_HDR_LEN);
		_ip(cap, ip, pend, len, NULL);
	}
}
#endif /* __linux__ */

/*
 * Handler for OpenBSD Loopback
 */
#if defined(__OpenBSD__)
#define NULL_HDRLEN 4

static void
_phandler_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	struct pcapev *cap;
	struct ip *ip;
	struct ether_header *ep;
	u_int family;
	const u_char *pend;
	u_int	len;

	LOG_DEBUG("_phandler_loop\n");
	cap = (struct pcapev *)user;

	/* XXX here i assume that packets are alligned, which might not
	 * be the case when using dump files, says tcpdump sources */

	pend = p + h->caplen;
	len = h->len - NULL_HDRLEN;

	memcpy((char *)&family, (char *)p, sizeof(family));
	family = ntohl(family);
	switch (family) {
		case AF_INET:
			LOG_DEBUG("loop family AF_INET\n");
			ip = (struct ip *)(p + NULL_HDRLEN);
			_ip(cap, ip, pend, len, ep);
			break;
		case AF_LINK:
			ep = (struct ether_header *)((u_char *)p + NULL_HDRLEN);
			_ether(cap, ep, pend, len);
			break;
		default:
			LOG_DEBUG("unknown family %x !\n", family);
			break;
	}
}
#endif /* __OpenBSD__ */

static void
_ether(struct pcapev *cap, struct ether_header *ether, const u_char *pend, u_int wirelen)
{
	struct ip *ip;
	u_short ether_type;
	struct arphdr *arp;
	struct pcapev_cb *cbusr;

	LIST_FOREACH(cbusr, &cap->cbusr_ether, entry)
		cbusr->cb.ether.func(cap, ether, wirelen, cbusr->arg);
	wirelen -= sizeof(struct ether_header);

	ether_type = ntohs(ether->ether_type);
	if (ether_type <= ETHERMTU) {
		LOG_DEBUG("llc packet !\n");
	} else {
		switch (ether_type) {
			case ETHERTYPE_IP:
				LOG_DEBUG("_ether: IP\n");
				ip = (struct ip *)((u_char *)ether + sizeof(struct ether_header));
				_ip(cap, ip, pend, wirelen, ether);
				break;
			case ETHERTYPE_ARP:
				if (LIST_EMPTY(&cap->cbusr_arp))
					break;
				LOG_DEBUG("_ether: ARP\n");
				arp = (struct arphdr *)((u_char *)ether + sizeof(struct ether_header));
				_arp(cap, arp, pend, wirelen, ether);
				break;
			default:
				LOG_DEBUG("loop non ip packet !\n");
				break;
		}
	}
}

static void
_arp(struct pcapev *cap, struct arphdr *arp, const u_char *pend, u_int wirelen,
	struct ether_header *ether)
{
	struct pcapev_cb *cbusr;

	if (NOTCAPTURED(arp)) {
		LOG_PINVALID("arp truncated !\n");
		return;
	}
	if (NOTRECEIVED(*arp)) {
		LOG_PINVALID("arp too small !\n");
	}
	LIST_FOREACH(cbusr, &cap->cbusr_arp, entry)
		cbusr->cb.arp.func(cap, arp, wirelen, ether, cbusr->arg);
}

/*
 * Parse an IP packet and descide what to do with it.
 * 'ip' is a pointer the the captured IP packet
 * 'pend' is a pointer to the end of the captured IP packet
 * 'wirelen' is the size of the IP packet off the wire
 */
static void
_ip(struct pcapev *cap, struct ip *ip, const u_char *pend, u_int wirelen,
	struct ether_header *ether)
{
	u_int		len, ip_hlen, off;
	const u_char	*cp;
	struct tcphdr	*tcph;
	struct udphdr	*udph;
	struct icmphdr	*icmp;
	struct pcapev_cb *cbusr;

	if (NOTCAPTURED(ip)) {
		LOG_PINVALID("user: ip truncated (ip %p pend %p sizeof(ip) %lx\n",
				ip, pend, sizeof(ip));
		cap->ptruncated++;
		return;
	}

	if (ip->ip_v != IPVERSION) {
		LOG_PINVALID("user: invalid ip version\n");
		cap->pinvalid++;
		return;
	}

	len = ntohs(ip->ip_len);
	if (wirelen < len) {
		LOG_PINVALID("user: ip too small, len=%d wirelen=%d\n", len, wirelen);
		cap->pinvalid++;
		len = wirelen;
	}

	ip_hlen = ip->ip_hl * 4;
	if (ip_hlen < sizeof(struct ip) || ip_hlen > len) {
		LOG_PINVALID("user: ip_hlen invalid, %d\n", ip_hlen);
		cap->pinvalid++;
		return;
	}
	LIST_FOREACH(cbusr, &cap->cbusr_ip, entry)
		cbusr->cb.ip.func(cap, ip, len, ether, cbusr->arg);
	len -= ip_hlen;

	off = ntohs(ip->ip_off);
	if ((off & IP_OFFMASK) == 0) {
		cp = (const u_char *)ip + ip_hlen;
		switch (ip->ip_p) {

			case IPPROTO_TCP:
				if (LIST_EMPTY(&cap->cbusr_tcp))
					break;
				tcph = (struct tcphdr *)cp;
				if (NOTCAPTURED(&tcph->th_flags)) {
					LOG_PINVALID("user: tcp truncated\n");
					cap->ptruncated++;
					return;
				}
				if (NOTRECEIVED(*tcph)) {
					LOG_PINVALID("user: tcp too small\n");
					cap->pinvalid++;
					return;
				}
				LIST_FOREACH(cbusr, &cap->cbusr_tcp, entry)
					if (!cbusr->cb.tcp.flags || cbusr->cb.tcp.flags == tcph->th_flags)
						cbusr->cb.tcp.func(cap, tcph, len, ip, ether, cbusr->arg);
				break;

			case IPPROTO_UDP:
				if (LIST_EMPTY(&cap->cbusr_udp))
					break;
				udph = (struct udphdr *)cp;
				if (NOTCAPTURED(&udph->uh_dport)) {
					LOG_PINVALID("user: udp truncated, "
							"ip %p, udph %p, uh_port %x, pend %p, ip_hlen %ux\n",
							ip, udph, udph->uh_dport, pend, ip_hlen);
					cap->ptruncated++;
					return;
				}
				if (NOTRECEIVED(*udph)) {
					LOG_PINVALID("user: udp too small\n");
					cap->pinvalid++;
					return;
				}
				LIST_FOREACH(cbusr, &cap->cbusr_udp, entry)
					cbusr->cb.udp.func(cap, udph, len, ip, ether, cbusr->arg);
				break;

			case IPPROTO_ICMP:
				if (LIST_EMPTY(&cap->cbusr_icmp))
					break;
				icmp = (struct icmphdr *)cp;
				if (NOTRECEIVED(*icmp)) {
					LOG_PINVALID("user: icmp too small\n");
					cap->pinvalid++;
					return;
				}
				LIST_FOREACH(cbusr, &cap->cbusr_icmp, entry)
					cbusr->cb.icmp.func(cap, icmp, len, ip, ether, cbusr->arg);
				break;

			default:
				LOG("user: unknown ip protocol !\n");
				break;
		}
	} else {
		/*
		 * if this isn't the first frag, we're missing the
		 * next level protocol header.
		 */
		LOG_DEBUG("user: got a fragmented ip packet !\n");
		cap->pfragmented++;
	}
}

