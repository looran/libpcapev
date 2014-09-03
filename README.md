libpcapev - libpcap helper using libevent
=========================================

### Example: capture IP packets on any interfaces

```
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <pcapev.h>

static int
_cb_ip(struct pcapev *cap, struct ip *ip, int len, struct ether_header *ether, void *arg)
{
	printf("%s\t -> ", inet_ntoa(ip->ip_src));
	printf("%s    (%x)\n", inet_ntoa(ip->ip_dst), ip->ip_p);
}

int
main(int argc, char *argv[])
{
	struct event_base *evb;
	struct pcapev *cap;

	evb = event_base_new();

	cap = pcapev_new(evb, "any", PCAPEV_SNAPLEN_DEFAULT, PCAPEV_NOPROMISC, PCAPEV_NOFILTER, PCAPEV_NOVERBOSE);
	pcapev_addcb_ip(cap, _cb_ip, NULL);
	pcapev_start(cap);

	event_base_dispatch(evb);
	pcapev_free(cap);
	return 0;
}
```

To test this:
```bash
make -C examples/ && sudo ./examples/dump_ip
```

### Install

```bash
make && sudo make install
```

### Dependencies

* libpcap
* libevent
* libbsd

### API

See https://github.com/looran/libpcapev/blob/master/pcapev.h
