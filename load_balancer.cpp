#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_CACHE_LEN 200
#define BACKEND_SERVERS 1

struct netmap_if *nifp;
struct netmap_ring *send_ring, *receive_ring;
struct nm_desc *d;
struct nmreq nmr;
struct pollfd fds;
int fd, length;

const char *backend_pool_array[2] = {"169.254.78.236", "169.254.9.23"};
//const char *backend_mac_array[2] = { "00:aa:bb:cc:dd:06", "00:aa:bb:cc:dd:03"};
const char *dst_ip = "169.254.78.236";
const char *src_ip = "169.254.18.80";
//const char *dst_mac = "00:aa:bb:cc:dd:03";
const char *src_mac = "00:aa:bb:cc:dd:04";
int do_abort = 1;

/* Define a struct for ARP header */
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint32_t sender_ip;
  uint8_t target_mac[6];
  uint32_t target_ip;
} __attribute__((__packed__));

/* ARP packet */
struct arp_pkt {
    struct ether_header eh;
    arp_hdr ah;
} __attribute__((__packed__));

struct arp_cache_entry {
    uint32_t ip;
    struct ether_addr mac;
};

static struct arp_cache_entry arp_cache[ARP_CACHE_LEN];

/*  Function definitions */

void arp_init()
{
    memset(arp_cache, 0, ARP_CACHE_LEN * sizeof(struct arp_cache_entry));
}

void insert_arp_cache(uint32_t ip, struct ether_addr mac) {
    int i;
    struct arp_cache_entry *entry;
    char ip_str[INET_ADDRSTRLEN];
    for(i = 0; i < ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];
        if (entry->ip == ip) {
            //entry already exist
            //printf("arp entry already exists\n");
            return;
        }
        if (entry->ip == 0) {
            //make entry
            entry->ip = ip;
            entry->mac = mac;
            //printf("arp entry created\n");
            //inet_pton(AF_INET, ip, &(ip_str));
            //printf("arp entry created for ip : %s\n", ip_str);
            return;
        }

    }
    std::cout << "arp full" << std::endl;

}


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
    return -1;
  }
  u_int virt_hdr_len = req.nr_arg1;
  return virt_hdr_len;

}


/*
 * Convert an ASCII representation of an ethernet address to
 * binary form.
 */
struct ether_addr *ether_aton_dst(const char *a)
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

struct ether_addr *ether_aton_src(const char *a)
{
    int i;
    static struct ether_addr q;
    unsigned int o0, o1, o2, o3, o4, o5;

    i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

    if (i != 6)
        return (NULL);

    q.ether_addr_octet[0]=o0;
    q.ether_addr_octet[1]=o1;
    q.ether_addr_octet[2]=o2;
    q.ether_addr_octet[3]=o3;
    q.ether_addr_octet[4]=o4;
    q.ether_addr_octet[5]=o5;

    return ((struct ether_addr *)&q);
}

/* 
 * Change the destination mac field with ether_addr from given eth header
 */

void change_dst_mac(struct ether_header **ethh, struct ether_addr *p) {
  (*ethh)->ether_dhost[0] = p->ether_addr_octet[0];
  (*ethh)->ether_dhost[1] = p->ether_addr_octet[1];
  (*ethh)->ether_dhost[2] = p->ether_addr_octet[2];
  (*ethh)->ether_dhost[3] = p->ether_addr_octet[3];
  (*ethh)->ether_dhost[4] = p->ether_addr_octet[4];
  (*ethh)->ether_dhost[5] = p->ether_addr_octet[5];
}

/* 
 * Change the source mac field with ether_addr from given eth header
 */

void change_src_mac(struct ether_header **ethh, struct ether_addr *p) {
  (*ethh)->ether_shost[0] = p->ether_addr_octet[0];
  (*ethh)->ether_shost[1] = p->ether_addr_octet[1];
  (*ethh)->ether_shost[2] = p->ether_addr_octet[2];
  (*ethh)->ether_shost[3] = p->ether_addr_octet[3];
  (*ethh)->ether_shost[4] = p->ether_addr_octet[4];
  (*ethh)->ether_shost[5] = p->ether_addr_octet[5];
}

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
    uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static uint16_t
wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

/*---------------------------------------------------------------------*/
/*
 * Prepares ARP packet in the buffer passed as parameter
 */
void prepare_arp_packet(struct arp_pkt *arp_pkt, const uint32_t *src_ip, const uint32_t *dest_ip, struct ether_addr *src_mac, struct ether_addr *dest_mac, uint16_t htype) {
    memcpy(arp_pkt->eh.ether_shost, src_mac,  6);
    memcpy(arp_pkt->eh.ether_dhost, dest_mac,  6);
    arp_pkt->eh.ether_type = htons(ETHERTYPE_ARP);

    arp_pkt->ah.htype = htons (1);
    arp_pkt->ah.ptype =  htons (ETHERTYPE_IP);
    arp_pkt->ah.hlen = 6;
    arp_pkt->ah.plen = 4;
    arp_pkt->ah.opcode = htype;

    arp_pkt->ah.sender_ip = *src_ip;
    arp_pkt->ah.target_ip = *dest_ip;

    memcpy(arp_pkt->ah.sender_mac, src_mac,  6);
    if (ntohs(htype) == 1) {
        memset (arp_pkt->ah.target_mac, 0, 6 * sizeof (uint8_t));
    } else {
        memcpy(arp_pkt->ah.target_mac, dest_mac,  6);
    }
}


void arp_reply(struct arp_pkt *arppkt) {
    //printf("###########################\n");
    //printf("sending arp reply\n");
    unsigned  char *tx_buf = NETMAP_BUF(send_ring, send_ring->slot[send_ring->cur].buf_idx);
    struct netmap_slot *slot = &send_ring->slot[send_ring->cur];
    //struct arp_pkt *arp_reply = (struct arp_pkt *)(tx_buf - sizeof(struct ether_header));
    struct arp_pkt *arp_reply = (struct arp_pkt *)(tx_buf);
    struct ether_addr d;
    memcpy(&d, (struct ether_addr *)arppkt->ah.sender_mac, 6);
    struct ether_addr s = *ether_aton_src(src_mac);
    prepare_arp_packet(arp_reply, &arppkt->ah.target_ip, &arppkt->ah.sender_ip, &s, &d, htons(2));
    slot->len = sizeof(struct arp_pkt);
    // slot->flags = 0;
    // slot->flags |= NS_REPORT;
    send_ring->cur = nm_ring_next(send_ring, send_ring->cur);
    send_ring->head = send_ring->cur;
    ioctl(fds.fd, NIOCTXSYNC, NULL);
    //printf("arp source mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arp_reply->eh.ether_shost[0], arp_reply->eh.ether_shost[1],
    //      arp_reply->eh.ether_shost[2], arp_reply->eh.ether_shost[3], arp_reply->eh.ether_shost[4], arp_reply->eh.ether_shost[5]);
    //printf("arp dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arp_reply->eh.ether_dhost[0], arp_reply->eh.ether_dhost[1],
    //        arp_reply->eh.ether_dhost[2], arp_reply->eh.ether_dhost[3], arp_reply->eh.ether_dhost[4], arp_reply->eh.ether_dhost[5]);
    char arp_src_ip[INET_ADDRSTRLEN];
    char arp_target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(arp_reply->ah.target_ip), arp_target_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_reply->ah.sender_ip), arp_src_ip, INET_ADDRSTRLEN);
    //printf("arp target ip %s\n", arp_target_ip);
    //printf("arp source ip %s\n", arp_src_ip);
    //printf("#############################\n");
}

void arp_request(const uint32_t *dest_ip) {
    unsigned  char *tx_buf = NETMAP_BUF(send_ring, send_ring->slot[send_ring->cur].buf_idx);
    struct netmap_slot *slot = &send_ring->slot[send_ring->cur];
    struct arp_pkt *arp_request_pkt = (struct arp_pkt *)(tx_buf);
    uint32_t source_ip;
    inet_pton(AF_INET, src_ip, &(source_ip));
    struct ether_addr source_mac = *ether_aton_src(src_mac);
    struct ether_addr dest_mac = *ether_aton_dst("ff:ff:ff:ff:ff:ff");
    prepare_arp_packet(arp_request_pkt, &source_ip, dest_ip, &source_mac, &dest_mac, htons(1));

    slot->len = sizeof(struct arp_pkt);
    // slot->flags = 0;
    // slot->flags |= NS_REPORT;
    send_ring->cur = nm_ring_next(send_ring, send_ring->cur);
    send_ring->head = send_ring->cur;
    ioctl(fds.fd, NIOCTXSYNC, NULL);
}

uint16_t tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
         }
 
         if ( len & 1 )
                 sum += *((uint8_t *)buf);
 
         sum += *(ip_src++);
         sum += *ip_src;
         sum += *(ip_dst++);
         sum += *ip_dst;
         sum += htons(IPPROTO_TCP);
         sum += htons(length);
 
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);                          
         return ( (uint16_t)(~sum)  );
}

/*
 * Rewrites destination mac address and ip address and send the packet
 */

void send_udp_packet(const unsigned char *buffer, struct ip *iph) {

  unsigned  char *dst = NETMAP_BUF(send_ring, send_ring->slot[send_ring->cur].buf_idx);
  struct ether_addr *p;
  struct ether_addr *s;
  nm_pkt_copy(buffer, dst, length);
  struct ether_header *ethh = (struct ether_header *)dst;
  struct ip *ipd = (struct ip *)(ethh + 1);
  struct udphdr *udp = (struct udphdr *)(ipd + 1);

/* select backend from sport */
  char *backend_ip;
  //printf("Client port is:%d\n", htons(udp->source));
  int index = htons(udp->source) % 2;

  /*copy dst ip to packet ip*/
  inet_pton(AF_INET, backend_pool_array[index], &(ipd->ip_dst));

  /*probably packet is ready to send*/
  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ipd->ip_src), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ipd->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
  //printf("source ip:%s\n", src_ip_str);
  //printf("changed Dest ip:%s\n", dst_ip_str);


  struct ether_addr backend_mac;
  struct arp_cache_entry *entry;
  // check if arp entry for destination mac is present
  int i;
  uint32_t dst_ip;
  inet_pton(AF_INET, backend_pool_array[index], &(dst_ip));

  for (i = 0; i < ARP_CACHE_LEN; i++) {
      entry = &arp_cache[i];
      if (entry->ip == dst_ip) {
          //mac address exist
          //printf("MAC entry found for ip:%s \n", dst_ip_str);
          backend_mac = entry->mac;
          break;
      }
  }
  if(i == ARP_CACHE_LEN) {
      /* mac not in arp cache, send arp request to get destination mac */
      //printf("MAC entry not found for: %s sending ARP request\n", dst_ip_str);
      arp_request(&dst_ip);
      //printf("This packet is not sent, it needs to be deferred\n");
      return;
  }


  /*rewrite destination mac and ip address */
  s = ether_aton_src(src_mac);
  change_dst_mac(&ethh, &backend_mac);
  change_src_mac(&ethh, s);
  //printf("changed dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_dhost[0], ethh->ether_dhost[1], ethh->ether_dhost[2], ethh->ether_dhost[3], ethh->ether_dhost[4], ethh->ether_dhost[5]);

  //printf("ip checksum before:%x\n", ipd->ip_sum);
  ipd->ip_sum = 0x0000;
  ipd->ip_sum = wrapsum(checksum(ipd, sizeof(*ipd), 0));

  //printf("ip checksum after:%x\n", ipd->ip_sum);
  /* udp checksum disable */
  udp->uh_sum=0;
  send_ring->cur = nm_ring_next(send_ring, send_ring->cur);
  send_ring->head = send_ring->cur;
  ioctl(fds.fd, NIOCTXSYNC, NULL);
}

/*
 * Rewrites destination mac address and ip address and send the packet
 */

void send_tcp_packet(const unsigned char *buffer, struct ip *iph) {

  unsigned  char *dst = NETMAP_BUF(send_ring, send_ring->slot[send_ring->cur].buf_idx);
  struct ether_addr *p;
  struct ether_addr *s;
  nm_pkt_copy(buffer, dst, length);

  struct ether_header *ethh = (struct ether_header *)dst;
  struct ip *ipd = (struct ip *)(ethh + 1);
  struct tcphdr *tcp = (struct tcphdr *)(ipd + 1);

/* select backend from sport */
  char *backend_ip;
  //printf("Client port is:%d\n", htons(tcp->source));
  int index = htons(tcp->source) % BACKEND_SERVERS;

  /*copy dst ip to packet ip*/
  inet_pton(AF_INET, backend_pool_array[index], &(ipd->ip_dst));

  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ipd->ip_src), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ipd->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
  //printf("changed source ip:%s\n", src_ip_str);
  //printf("changed Dest ip:%s\n", dst_ip_str);

  /* Get mac of backend selected */

  // check if arp entry for destination mac is present
  int i;
  uint32_t dst_ip;
  inet_pton(AF_INET, backend_pool_array[index], &(dst_ip));
  struct ether_addr backend_mac;
  struct arp_cache_entry *entry;
  for (i = 0; i < ARP_CACHE_LEN; i++) {
      entry = &arp_cache[i];
      if (entry->ip == dst_ip) {
          //mac address exist
          //printf("MAC entry found for ip:%s \n", dst_ip_str);
          backend_mac = entry->mac;
          break;
      }
  }
  if(i == ARP_CACHE_LEN) {
      /* mac not in arp cache, send arp request to get destination mac */
      //printf("MAC entry not found for: %s sending ARP request\n", dst_ip_str);
      arp_request(&dst_ip);
      //printf("This packet is not sent, it needs to be deferred\n");
      /* For now relying on TCP retransmission */
      return;
  }

  /*rewrite destination mac  */
  s = ether_aton_src(src_mac);
  change_dst_mac(&ethh, &backend_mac);
  change_src_mac(&ethh, s);
  //printf("changed dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_dhost[0], ethh->ether_dhost[1], ethh->ether_dhost[2], ethh->ether_dhost[3], ethh->ether_dhost[4], ethh->ether_dhost[5]);

  /*probably packet is ready to send*/
  //printf("ip checksum before:%x\n", ipd->ip_sum);
  ipd->ip_sum = 0x0000;
  ipd->ip_sum = wrapsum(checksum(ipd, sizeof(*ipd), 0));

  //printf("ip checksum after:%x\n", ipd->ip_sum);
  //tcp checksum
  tcp->th_sum = 0;
  //tcp->th_sum = tcp_checksum(tcp, (ipd->ip_len- 4*ipd->ip_hl), ipd->ip_src.s_addr, ipd->ip_dst.s_addr);
  tcp->th_sum = tcp_checksum(tcp, (ntohs(ipd->ip_len) -4*ipd->ip_hl), ipd->ip_src.s_addr, ipd->ip_dst.s_addr);
  send_ring->cur = nm_ring_next(send_ring, send_ring->cur);
  send_ring->head = send_ring->cur;
  ioctl(fds.fd, NIOCTXSYNC, NULL);
}



void process_ip_packet(const unsigned char *buffer, struct ip *iph) {
  //printf("###########################################################################\n");
  //printf("packet received: IP packet\n");
  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
  //printf("source ip:%s\n", src_ip_str);
  //printf("Dest ip:%s\n", dst_ip_str);
  uint32_t source_ip;
  char *arp_buffer;
  inet_pton(AF_INET, dst_ip, &(source_ip));
  struct ether_addr dest_mac;
  int i;
  struct arp_cache_entry *entry;
  switch (iph->ip_p) {
    case IPPROTO_UDP:
        // check if arp entry for destination mac is present
        for (i = 0; i < ARP_CACHE_LEN; i++) {
            entry = &arp_cache[i];
            if (entry->ip == source_ip) {
                //mac address exist
                //printf("MAC entry found for ip:%s \n", dst_ip_str);
                dest_mac = entry->mac;
                break;
            }
        }
        if(i == ARP_CACHE_LEN) {
            /* mac not in arp cache, send arp request to get destination mac */
            //printf("MAC entry not found for:%s sending ARP request\n", dst_ip_str);
            arp_request(&source_ip);
            //printf("This packet is not sent, it needs to be deferred\n");
        }
        
        send_udp_packet(buffer, iph);
        //printf("##################################################################################\n");
       /*wait for arp reply */

       /* poll(&fds,  1, -1);
        arp_buffer = NETMAP_BUF(receive_ring, receive_ring->slot[receive_ring->cur].buf_idx);
        // check if arp reply
        struct ether_header *ethh = (struct ether_header *)arp_buffer;
        if(ntohs(ethh->ether_type) == ETHERTYPE_ARP) {
            printf("here\n");
            struct arp_pkt *arppkt = (struct arp_pkt *)arp_buffer;
            char arp_target_ip[INET_ADDRSTRLEN];
            char arp_source_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(arppkt->ah.target_ip), arp_target_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(arppkt->ah.sender_ip), arp_source_ip, INET_ADDRSTRLEN);

            if(strcmp(arp_target_ip, src_ip) == 0){
                if (ntohs(arppkt->ah.opcode) == ARP_REPLY) {
                    printf("************************");
                }
            }
        }
        */
        break;

    case IPPROTO_TCP:
        //printf("TCP packet\n");
        send_tcp_packet(buffer, iph);
        //printf("##################################################################################\n");

      break;
    case IPPROTO_IPIP:
      /* tunneling */
      //printf("it is ipinip\n");
      break;
    default:
      // We return 0 to indicate that the packet couldn't be balanced.
      break;
    }
}

void process_receive_buffer(const unsigned char *buffer) {
  struct ether_header *ethh = (struct ether_header *)buffer;
  //print src and dst mac
 // printf("source mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_shost[0], ethh->ether_shost[1], ethh->ether_shost[2], ethh->ether_shost[3], ethh->ether_shost[4], ethh->ether_shost[5]);
 // printf("dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", ethh->ether_dhost[0], ethh->ether_dhost[1], ethh->ether_dhost[2], ethh->ether_dhost[3], ethh->ether_dhost[4], ethh->ether_dhost[5]);	
struct arp_pkt *arppkt;
  switch (ntohs(ethh->ether_type)) {
    case ETHERTYPE_IP:
      process_ip_packet(buffer, (struct ip *)(ethh + 1));
      break;
    case ETHERTYPE_IPV6:
      printf("packet received: IPV6 packet\n");
      break;
    case ETHERTYPE_VLAN:
      printf("vlan\n");
      break;
    case ETHERTYPE_ARP:
      /*ARP packet */
     // printf("##################################################################################\n");
     // printf("Packet received: ARP packet\n");
      arppkt = (struct arp_pkt *)buffer;
      char arp_target_ip[INET_ADDRSTRLEN];
      char arp_sender_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(arppkt->ah.target_ip), arp_target_ip, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(arppkt->ah.sender_ip), arp_sender_ip, INET_ADDRSTRLEN);
      // make entry in arp cache
      struct ether_addr sender_mac;
      memcpy(&sender_mac, (struct ether_addr *)arppkt->ah.sender_mac, 6);
      insert_arp_cache(arppkt->ah.sender_ip, sender_mac);
      if(strcmp(arp_target_ip, src_ip) == 0){
        if (ntohs(arppkt->ah.opcode) == ARP_REQUEST) {
            //printf("ARP REQUEST packet from: %s\n", arp_sender_ip);
            /* send arp reply */
            arp_reply(arppkt);
        }
        if (ntohs(arppkt->ah.opcode) == ARP_REPLY) {
            //printf("ARP REPLY packet from: %s\n", arp_sender_ip);
            //printf("ARP REPLY sender mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arppkt->eh.ether_shost[0], arppkt->eh.ether_shost[1],
                //    arppkt->eh.ether_shost[2], arppkt->eh.ether_shost[3], arppkt->eh.ether_shost[4], arppkt->eh.ether_shost[5]);
        }
      }
      //printf("##################################################################################\n");
      break;
    default:
      /* others */
      break;
    }

}

/*
void receive_packets(void) {
    char *src, *dst;
    uint16_t *spkt, *dpkt;
    fd = open("/dev/netmap", O_RDWR);
    bzero(&nmr, sizeof(nmr));
    strcpy(nmr.nr_name, "eth6");
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
*/

static void
sigint_h(int sig)
{
    (void)sig;  /* UNUSED */
    do_abort = 1;
    nm_close(d);
    printf("file closed\n");
    signal(SIGINT, SIG_DFL);
}

int main()
{
    char *buf;
    struct nm_pkthdr h;
    struct nmreq base_req;
    char *src, *dst;
    uint16_t *spkt, *dpkt;
    struct ether_addr *p;
    uint32_t source_ip;
    struct arp_cache_entry *entry;
    arp_init();
    memset(&base_req, 0, sizeof(base_req));
    base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
    d = nm_open("netmap:eth6", &base_req, 0, 0);
    fds.fd = NETMAP_FD(d);
    fds.events = POLLIN;
    receive_ring = NETMAP_RXRING(d->nifp, 0);
    send_ring = NETMAP_TXRING(d->nifp, 0);
    int r, s;
    signal(SIGINT, sigint_h);
    while (do_abort) {
        poll(&fds,  1, -1);
        r = receive_ring->cur;
        length = receive_ring->slot[r].len;
        src = NETMAP_BUF(receive_ring, receive_ring->slot[r].buf_idx);
        process_receive_buffer(src);
        receive_ring->cur = nm_ring_next(receive_ring, r);
        receive_ring->head = receive_ring->cur;
     }
    nm_close(d);
}
