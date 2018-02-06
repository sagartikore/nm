#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <inttypes.h>
struct netmap_if *nifp;
struct netmap_ring *ring, *tring;
struct nmreq nmr;
struct pollfd fds;
int fd, length;


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
            printf("it is udp\n");
            break;
        case IPPROTO_TCP:
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
            decode_ip(buffer, (struct ip *)(ethh + 1));
        default:
            /* others */
            break;
    }

}

void receive(void) {
    char *src, *dst;
    uint16_t *spkt, *dpkt;
    fd = open("/dev/netmap", O_RDWR);
    bzero(&nmr, sizeof(nmr));
    strcpy(nmr.nr_name, "eth2");
    nmr.nr_version = NETMAP_API;
    ioctl(fd, NIOCREGIF, &nmr);
    void *p = mmap(0, nmr.nr_memsize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    nifp = NETMAP_IF(p, nmr.nr_offset);
    ring = NETMAP_RXRING(nifp, 0);
    fds.fd = fd;
    fds.events = POLLIN;
    int i, j;
    for(;;) {
        poll(&fds, 1, -1);
        i = ring->cur;
        length = ring->slot[i].len;
        src = NETMAP_BUF(ring, ring->slot[i].buf_idx);
        printf("packet received\n");
        get_ether(src);
        ring->cur = nm_ring_next(ring, i);
        ring->head = ring->cur;
    }
    close(fd);
}


int main() {
    //source_hwaddr("netmap:eth1");
    receive();
    return 0;
}
