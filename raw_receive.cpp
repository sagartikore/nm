#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
//#include <net/tcp.h>
#include <arpa/inet.h>
#include <cstdlib>
#include<netinet/if_ether.h>
//#include <stdlib.h>
#include <cstring>
#include <string>
#include<iostream>
using namespace std;

unsigned short      /* this function generates header checksums */
csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
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

void PrintInHex(char *mesg, unsigned char *p, int len)
{
	printf(mesg);

	while(len--)
	{
		printf("%.2X ", *p);
		p++;
	}

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

int main(int argc, char *argv[]){
    int sock_r;
    unsigned short iphdrlen;

    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    struct sockaddr_in sin, dest;
    if(sock_r<0)
    {
        printf("error in socket\n");
        return -1;
    }
    unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    struct ethhdr *eth = (struct ethhdr *)(buffer);

    memset(buffer,0,65536);
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    int buflen;
    while(1){
        buflen=recvfrom(sock_r,buffer,128,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;
        string dst_addr_str = inet_ntoa(dest.sin_addr);
        uint32_t src_addr,dst_addr;
        uint16_t src_port,dst_port;
        src_addr = ip->saddr;
        dst_addr = ip->daddr;
        /* getting actual size of IP header*/
        iphdrlen = ip->ihl*4;
        /* getting pointer to udp header*/
        struct tcphdr *tcp=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        src_port = tcp->source;
        dst_port = tcp->dest;
        if(dst_addr_str.compare("169.254.18.80")==0){
            if(ntohs(tcp->dest)==atoi(argv[2])){
                int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);  /* open raw socket */
                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_port = htons (atoi(argv[2]));
                sin.sin_addr.s_addr = inet_addr ("169.254.78.236");
                //set destination ip
                ip->daddr = sin.sin_addr.s_addr;
                tcp->check = 0;
                tcp->check = tcp_checksum(tcp, (ntohs(ip->tot_len) -iphdrlen), ip->saddr, ip->daddr);
                  //ip->check = csum ((unsigned short *) ip, ntohs(ip->tot_len) >> 1);
                /*int tcplen = (ip->tot_len - iphdrlen);
                tcp->check = tcp_v4_check(tcplen,
                        ip->saddr,
                        ip->daddr,
                        csum_partial((char *)tcp, tcplen, 0));
                */
                int one = 1;
                const int *val = &one;
                if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
                    printf ("Warning: Cannot set HDRINCL!\n");

                printf("total len:%d\n", ntohs(ip->tot_len));
                //sendto(s,buffer,128,0,&saddr,(socklen_t *)&saddr_len);
                if (sendto (s,        /* our socket */
                            ip, /* the buffer containing headers and data */
                            ntohs(ip->tot_len),  /* total length of our datagram */
                            0,        /* routing flags, normally always 0 */
                            (struct sockaddr *) &sin, /* socket addr, just like in */
                            sizeof (sin)) < 0)        /* a normal send() */
                    printf ("error\n");
                else
                    printf (".");
                close(s);
            }
    /*
            struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            dest.sin_addr.s_addr = ip->daddr;
            printf("\t|-Version : %d\n",(unsigned int)ip->version);

            printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);

            printf("\t|-Type Of Service : %d\n",(unsigned int)ip->tos);

            printf("\t|-Total Length : %d Bytes\n",ntohs(ip->tot_len));

            printf("\t|-Identification : %d\n",ntohs(ip->id));

            printf("\t|-Time To Live : %d\n",(unsigned int)ip->ttl);

            printf("\t|-Protocol : %d\n",(unsigned int)ip->protocol);

            printf("\t|-Header Checksum : %d\n",ntohs(ip->check));

            printf("\t|-Source IP : %s\n", inet_ntoa(source1.sin_addr));

            printf("\t|-Destination IP : %s\n",inet_ntoa(dest1.sin_addr));
      */
            }
        }
    return 0;
}
