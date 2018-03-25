/* Load balance traffic on tcp port 8001 to multiple backend servers */


#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstdlib>
#include<netinet/if_ether.h>
//#include <stdlib.h>
#include <cstring>
#include <string>
#include<iostream>
using namespace std;
string load_balancer_ip = "169.254.18.80";
#define BACKEND_SERVERS 2
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

int main(int argc, char *argv[]){
    int sock_r, sock_s;
    unsigned short iphdrlen;
    struct sockaddr_in src, dest;
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    int buflen;

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
    uint32_t src_addr,dst_addr;
    uint16_t src_port,dst_port;
    int index;
    while(1){
        buflen=recvfrom(sock_r,buffer,128,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        /* check transport layer protocol UDP or TCP */

        dest.sin_addr.s_addr = ip->daddr;
        string dst_addr_str = inet_ntoa(dest.sin_addr);
        src_addr = ip->saddr;
        dst_addr = ip->daddr;
        /* getting actual size of IP header*/
        iphdrlen = ip->ihl*4;
        struct tcphdr *tcp=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        src_port = tcp->source;
        dst_port = tcp->dest;
        if(dst_addr_str.compare(load_balancer_ip)==0){
            /* distribute packets for only TCP */
            if (ip->protocol == TCP) {
                sock_s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);  /* open raw socket */
                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_port = tcp->dest;
                /* select backend server */
                index = ntohs(tcp->source) % BACKEND_SERVERS;
                sin.sin_addr.s_addr = inet_addr (backend_pool_array[index].c_str());
                //set destination ip
                ip->daddr = sin.sin_addr.s_addr;
                tcp->check = 0;
                tcp->check = tcp_checksum(tcp, (ntohs(ip->tot_len) -iphdrlen), ip->saddr, ip->daddr);
                int one = 1;
                const int *val = &one;
                if (setsockopt (sock_s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
                    printf ("Warning: Cannot set HDRINCL!\n");

                if (sendto (sock_s,        /* our socket */
                            ip, /* the buffer containing headers and data */
                            ntohs(ip->tot_len),  /* total length of our datagram */
                            0,        /* routing flags, normally always 0 */
                            (struct sockaddr *) &sin, /* socket addr, just like in */
                            sizeof (sin)) < 0)        /* a normal send() */
                    printf ("error\n");
                else
                    printf (".");
                close(sock_s);
            }
        }
    }
    return 0;
}
