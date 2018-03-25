/* Load balance traffic on tcp port 8001 to multiple backend servers */


#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstdlib>
#include<netinet/if_ether.h>
//#include <stdlib.h>
#include <cstring>
#include <string>
#include<iostream>
using namespace std;
string load_balancer_ip = "169.254.18.80";
#define BACKEND_SERVERS 1
#define TCP 6
#define UDP 17
string backend_pool_array[2] = {"169.254.78.236", "169.254.9.23"};

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

/* Rewrrite destination ip, recalculate tcp checksum and send
 * the packet
 */
void send_tcp_packet(int sock_s, struct iphdr *ip, struct tcphdr *tcp) {
    unsigned short iphdrlen = ip->ihl*4;
    int tcplen = ntohs(ip->tot_len) - iphdrlen;

    //struct tcphdr *tcp = (struct tcphdr *)(ip + iphdrlen);
    int index;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->dest;
    cout << htons(tcp->dest) << endl;
    /* select backend server */
    index = ntohs(tcp->source) % BACKEND_SERVERS;
    sin.sin_addr.s_addr = inet_addr (backend_pool_array[index].c_str());
    //set destination ip
    ip->daddr = sin.sin_addr.s_addr;
    cout << "ip addr" << inet_ntoa(sin.sin_addr) << endl;
    tcp->check = 0;
    tcp->check = tcp_checksum(tcp, tcplen, ip->saddr, ip->daddr);
    int one = 1;
    const int *val = &one;
    /* since we already added ip header to our packet,
     * enabling 'ip_hdrincl' option tells kernel not to add ip header
     * */
    if (setsockopt (sock_s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");

    if (sendto (sock_s,        /* our socket */
                ip, /* the buffer containing headers and data */
                ntohs(ip->tot_len),  /* total length of packet */
                0,        /* routing flags, normally always 0 */
                (struct sockaddr *) &sin, /* socket addr, just like in */
                sizeof (sin)) < 0)        /* a normal send() */
        printf ("error\n");
}

/* Rewrrite destination ip and send
 * the packet
 */
void send_udp_packet(int sock_s, struct iphdr *ip, struct udphdr *udp) {
    //struct udphdr *udp = (struct udphdr *)(ip + iphdrlen);
    int index;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = udp->dest;
    /* select backend server */
    index = ntohs(udp->source) % 1;
    sin.sin_addr.s_addr = inet_addr (backend_pool_array[index].c_str());
    //set destination ip
    ip->daddr = sin.sin_addr.s_addr;
    udp->check = 0;
    int one = 1;
    const int *val = &one;
    /* since we already added ip header to our packet,
     * enabling 'ip_hdrincl' option tells kernel not to add ip header
     * */
    if (setsockopt (sock_s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");

    if (sendto (sock_s,        /* our socket */
                ip, /* the buffer containing headers and data */
                ntohs(ip->tot_len),  /* total length of packet */
                0,        /* routing flags, normally always 0 */
                (struct sockaddr *) &sin, /* socket addr, just like in */
                sizeof (sin)) < 0)        /* a normal send() */
        printf ("error\n");
}


int main(int argc, char *argv[]){
    int sock_r, sock_s;
    struct sockaddr_in dest;
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    int buflen;
    struct tcphdr *tcp;
    struct udphdr *udp;
    unsigned short iphdrlen;
    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    //sock_r=socket(AF_PACKET,SOCK_RAW,IPPROTO_TCP);

    if(sock_r<0)
    {
        printf("error in socket\n");
        return -1;
    }

    /*src.sin_addr.s_addr = inet_addr(load_balancer_ip.c_str());
    src.sin_family = AF_INET;
    src.sin_port = htons(8001);
    if (bind(sock_r, (struct sockaddr *)&src, sizeof(src)) <0) {
        printf("failed\n");
        exit(EXIT_FAILURE);
    }*/

    unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    memset(buffer,0,65536);
    //struct ethhdr *eth = (struct ethhdr *)(buffer);
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    memset(&dest, 0, sizeof(dest));
    while(1){
        /* receive packets*/
        buflen=recvfrom(sock_r,buffer,128,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        dest.sin_addr.s_addr = ip->daddr;
        string dst_addr_str = inet_ntoa(dest.sin_addr);
        iphdrlen = ip->ihl*4;
        if(dst_addr_str.compare(load_balancer_ip)==0){
            /* distribute packets to TCP backends */
            if (ip->protocol == TCP) {
                tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
                /* opens raw socket and send tcp packets to backend */
                sock_s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
                send_tcp_packet(sock_s, ip, tcp);
                close(sock_s);
            }
            /* distribute packets to UDP backends */
            else if(ip->protocol == UDP) {
                udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
                sock_s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
                send_udp_packet(sock_s, ip, udp);
                close(sock_s);
            }
        }
    }
  return 0;
}
