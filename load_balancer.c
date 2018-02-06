#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <inttypes.h>
#include <netinet/in.h>

struct netmap_if *nifp;
struct netmap_ring *ring, *tring;
struct nmreq nmr;
struct pollfd fds;
int fd, length;

const char *dst_ip = "169.254.9.8";
const char *dst_mac = "00:aa:bb:cc:dd:03";


u_int get_vnet_hdr_len(struct nm_desc *nmd)
{
  struct nmreq req;
  int err;

  memset(&req, 0, sizeof(req));
  bcopy(nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
  req.nr_version = NETMAP_API;
  req.nr_cmd = NETMAP_VNET_HDR_GET;
  err = ioctl(nmd->fd, NIOCREGIF, &req);
  if (err) {
    printf("Unable to get virtio-net header length");
    return;
  }
  u_int virt_hdr_len = req.nr_arg1;
  return virt_hdr_len;

}

/*
 * Convert an ASCII representation of an ethernet address to
 * binary form.
 */
struct ether_addr *ether_aton(const char *a)
{
    int i;
    static struct ether_addr o;
    unsigned int o0, o1, o2, o3, o4, o5;

    i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

    if (i != 6)
        return (NULL);

    o.ether_addr_octet[0]=o0;
    o.ether_addr_octet[1]=o1;
    o.ether_addr_octet[2]=o2;
    o.ether_addr_octet[3]=o3;
    o.ether_addr_octet[4]=o4;
    o.ether_addr_octet[5]=o5;

    return ((struct ether_addr *)&o);
}

/* 
 * Change the destination mac field with ether_addr from given eth header
 */

void change_mac(struct ether_header **ethh, struct ether_addr *p) {
  (*ethh)->ether_dhost[0] = p->ether_addr_octet[0];
  (*ethh)->ether_dhost[1] = p->ether_addr_octet[1];
  (*ethh)->ether_dhost[2] = p->ether_addr_octet[2];
  (*ethh)->ether_dhost[3] = p->ether_addr_octet[3];
  (*ethh)->ether_dhost[4] = p->ether_addr_octet[4];
  (*ethh)->ether_dhost[5] = p->ether_addr_octet[5];
}

/*
 * Rewrites destination mac address and ip address and send the packet
 */

void send_packet(const unsigned char *buffer, struct ip *iph) {
  unsigned  char *dst = NETMAP_BUF(tring, tring->slot[tring->cur].buf_idx);
  uint16_t *s, *d;
  struct ether_addr *p;
  nm_pkt_copy(buffer, dst, length);
  s = (uint16_t *)buffer;
  d = (uint16_t *)dst;

  //rewrite destination mac and ip address */
  struct ether_header *ethh = (struct ether_header *)dst;
  p = ether_aton(dst_mac);
  change_mac(&ethh, p);
  struct ip *ipd = (struct ip *)(ethh + 1);
  //copy dst ip to packet ip
  inet_pton(AF_INET, dst_ip, &(ipd->ip_dst));
  // probably packet is ready to send*/
  tring->cur = nm_ring_next(tring, tring->cur);
  tring->head = tring->cur;
  ioctl(fd, NIOCTXSYNC, NULL);
}


void decode_ip(const unsigned char *buffer, struct ip *iph) {

	//print source and dest ip
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
	printf("source ip:%s\n", src_ip_str);
	printf("Dest ip:%s\n", dst_ip_str);

  switch (iph->ip_p) {
    case IPPROTO_UDP:
      send_packet(buffer, iph);
      break;

    case IPPROTO_TCP:
	    send_packet(buffer, iph);
      break;
    case IPPROTO_IPIP:
      /* tunneling */
      printf("it is ipinip\n");
      break;
    default:
      // We return 0 to indicate that the packet couldn't be balanced.
      break;
    }
}

void get_ether(const unsigned char *buffer) {
  struct ether_header *ethh = (struct ether_header *)buffer;
  
  //print src and dst mac
  printf("source mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_shost[0], ethh->ether_shost[1], ethh->ether_shost[2], ethh->ether_shost[3], ethh->ether_shost[4], ethh->ether_shost[5]);
  printf("dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_dhost[0], ethh->ether_dhost[1], ethh->ether_dhost[2], ethh->ether_dhost[3], ethh->ether_dhost[4], ethh->ether_dhost[5]);	

  switch (ntohs(ethh->ether_type)) {
    case ETHERTYPE_IP:
  	  printf("it is ip packet\n");
  	  decode_ip(buffer, (struct ip *)(ethh + 1));
      break;
    case ETHERTYPE_IPV6:
      printf("it is ipv6\n");
      break;
    case ETHERTYPE_VLAN:
		  printf("vlan\n");
      break;
    case ETHERTYPE_ARP:
      printf("arp\n");
      send_packet(buffer, (struct ip *)(ethh + 1));
    default:
      /* others */
      break;
    }

}

void receive_packets(void) {
    char *src, *dst;
    uint16_t *spkt, *dpkt;
    fd = open("/dev/netmap", O_RDWR);
    bzero(&nmr, sizeof(nmr));
    strcpy(nmr.nr_name, "eth1");
    nmr.nr_version = NETMAP_API;
    ioctl(fd, NIOCREGIF, &nmr);
    void *p = mmap(0, nmr.nr_memsize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    nifp = NETMAP_IF(p, nmr.nr_offset);
    ring = NETMAP_RXRING(nifp, 0);
    tring = NETMAP_TXRING(nifp, 0);
    fds.fd = fd;
    fds.events = POLLIN;
    int i, j;
    for(;;) {
      poll(&fds, 1, -1);
      i = ring->cur;
      length = ring->slot[i].len;
      src = NETMAP_BUF(ring, ring->slot[i].buf_idx);
		  printf("############################# packet received ###########################\n");
		  get_ether(src);
      printf("############################# packet sent #################################\n\n\n");
      ring->cur = nm_ring_next(ring, i);
      ring->head = ring->cur;
    }
	close(fd);
}


int main() {
	//source_hwaddr("netmap:eth1");
	receive_packets();
	return 0;
}
