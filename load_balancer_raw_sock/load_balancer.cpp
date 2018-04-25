/* Load balance traffic on tcp port 8001 to multiple backend servers */


#include <unistd.h>
#include <errno.h>
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
string load_balancer_ip = "192.168.122.247";
#define BACKEND_SERVERS 1
#define TCP 6
#define UDP 17
#define PORT 8003
string backend_pool_array[2] = {"192.168.122.35", "169.254.9.23"};
int tl;

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
    int total_len = ntohs(ip->tot_len);
    int tcplen = total_len- iphdrlen;
    //std::cout << ntohs(ip->tot_len) << std::endl;
    //struct tcphdr *tcp = (struct tcphdr *)(ip + iphdrlen);
    int index;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->dest;
    /* select backend server */
    index = ntohs(tcp->source) % BACKEND_SERVERS;
    sin.sin_addr.s_addr = inet_addr (backend_pool_array[index].c_str());
    //set destination ip
    ip->daddr = sin.sin_addr.s_addr;
    tcp->check = 0;
    tcp->check = tcp_checksum(tcp, tcplen, ip->saddr, ip->daddr);
    //std::cout << "length:" << tl << std::endl;
    //if(total_len > 1500)
     //   total_len = 1500;
    /*if(send(sock_s, ip, total_len, 0)) {
        printf ("error:%s\n", strerror(errno));
    }*/
    if (sendto (sock_s, ip, tl, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        printf ("error:%s\n", strerror(errno));
        //exit(EXIT_FAILURE);
    }   
    /*else {
        printf("sent\n");
    }*/
}

/*
void send_tcp_packet1(int sock_s, struct iphdr *ip, struct tcphdr *tcp) {
    unsigned short iphdrlen = ip->ihl*4;
    int total_len = ntohs(ip->tot_len);
    int tcplen = total_len- iphdrlen;
    //std::cout << ntohs(ip->tot_len) << std::endl;
    //struct tcphdr *tcp = (struct tcphdr *)(ip + iphdrlen);
    int index;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->dest;
   index = ntohs(tcp->source) % BACKEND_SERVERS;
    sin.sin_addr.s_addr = inet_addr (backend_pool_array[index].c_str());
    //set destination ip
    ip->daddr = sin.sin_addr.s_addr;
    tcp->check = 0;
    tcp->check = tcp_checksum(tcp, tcplen, ip->saddr, ip->daddr);
    int one = 1;
    const int *val = &one;
    //std::cout << "length:" << tl << std::endl;
    if (sendto (sock_s, ip, tl, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        printf ("error:%s\n", strerror(errno));
        //exit(EXIT_FAILURE);
    }   
    else {
        printf("sent\n");
    }
}*/


int main(int argc, char *argv[]){
    int sock_r, sock_s;
    struct sockaddr_in dest;
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    int buflen;
    struct tcphdr *tcp;
    struct udphdr *udp;
    unsigned short iphdrlen;
    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
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
    sock_s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
        int one = 1;
    const int *val = &one;
    /* since we already added ip header to our packet,
     * enabling 'ip_hdrincl' option tells kernel not to add ip header
     * */
    if (setsockopt (sock_s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");

    struct in_addr f;
    inet_aton(load_balancer_ip.c_str(), &f);
    unsigned char *buffer = (unsigned char *) malloc(2048); //to receive data
    memset(buffer,0,2048);
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    memset(&dest, 0, sizeof(dest));
    while(1){
        /* receive packets*/
        buflen=recvfrom(sock_r,buffer,2048,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        //std::cout << "buflen" << buflen << std::endl;
        tl = buflen - sizeof(struct ethhdr);
        dest.sin_addr.s_addr = ip->daddr;
        //string dst_addr_str = inet_ntoa(dest.sin_addr);
        iphdrlen = ip->ihl*4;

        if(dest.sin_addr.s_addr == f.s_addr) {
        //if(dst_addr_str.compare(load_balancer_ip)==0){
            /* distribute packets to TCP backends */
            if (ip->protocol == TCP) {

                tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
                /* opens raw socket and send tcp packets to backend */
                //std::cout << "port" << ntohs(tcp->dest) << std:: endl;
                if(ntohs(tcp->dest) == PORT) {
                    send_tcp_packet(sock_s, ip, tcp);
                    //send_tcp_packet1(sock_r, ip, tcp);
                }
                //close(sock_s);
            }
            /* distribute packets to UDP backends */
            /*else if(ip->protocol == UDP) {
                udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
                sock_s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
                send_udp_packet(sock_s, ip, udp);
                //close(sock_s);
            }*/
        }
    }
    close(sock_s);
  return 0;
}
