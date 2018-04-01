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
#include "lib.h"
using namespace std;
string load_balancer_ip = "169.254.18.80";
#define BACKEND_SERVERS 2
#define TCP 6
#define UDP 17
string backend_pool_array[2] = {"169.254.78.236", "169.254.9.23"};
struct my_pool{
//char* buf_val;
//char* dst1;
struct iphdr *ip1;
struct tcphdr *tcp1;
};
void process_receive_buffer(int fd1, int len, void* request, char *buffer);
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
void send_tcp_packet1(int fd1, int len, void* request, char *buffer){
	string bck_ip = buffer;
	 my_pool* buffer_request = static_cast<my_pool*>(request); 
	 struct iphdr *ip;
	  struct tcphdr *tcp;
	  ip = buffer_request->ip1;
	  tcp = buffer_request->tcp1;
	   unsigned short iphdrlen = ip->ihl*4;
	 int tcplen = ntohs(ip->tot_len) - iphdrlen;
	// cout<< (int)tcp->dest <<endl;
     int map_id = createClient(fd1, "169.254.18.80" ,bck_ip , tcp->dest, "tcp");
      //set destination ip
    ip->daddr = inet_addr(bck_ip.c_str());  
        tcp->check = 0;
    tcp->check = tcp_checksum(tcp, tcplen, ip->saddr, ip->daddr);
    int len1 = ntohs(ip->tot_len);
        sendData(fd1, map_id, (char*)ip, len1);
        registerCallback(fd1, -1, "read", process_receive_buffer);
    /* since we already added ip header to our packet,
     * enabling 'ip_hdrincl' option tells kernel not to add ip header
     * */
   
}
/* Rewrrite destination ip, recalculate tcp checksum and send
 * the packet
 */
void send_tcp_packet(int sock_s, struct iphdr *ip, struct tcphdr *tcp,  void* request) {
    unsigned short iphdrlen = ip->ihl*4;
    int tcplen = ntohs(ip->tot_len) - iphdrlen;
	my_pool* buffer_request = static_cast<my_pool*>(request);
	buffer_request->ip1 = ip;
	buffer_request->tcp1 = tcp;
    //struct tcphdr *tcp = (struct tcphdr *)(ip + iphdrlen);
    int index1;
    /* select backend server */
    index1 = ntohs(tcp->source) % BACKEND_SERVERS;
     getData(sock_s, 0, index1, "local", send_tcp_packet1);
    
}

void process_receive_buffer(int sock_s, int len, void* request, char *buffer) {
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct sockaddr_in dest;
    request = allocReqCtxt(sock_s, len, 1);
    my_pool* buf_req = static_cast<my_pool*>(request); 
    memset(&dest, 0, sizeof(dest));
    unsigned short iphdrlen;
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        dest.sin_addr.s_addr = ip->daddr;
        string dst_addr_str = inet_ntoa(dest.sin_addr);
        iphdrlen = ip->ihl*4;
        if(dst_addr_str.compare(load_balancer_ip)==0){
            /* distribute packets to TCP backends */
            if (ip->protocol == TCP) {
                tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
                /* opens raw socket and send tcp packets to backend */
                send_tcp_packet(sock_s, ip, tcp, request);
                //close(sock_s);
            }
        }
}

int main(int argc, char *argv[]){
 int sock_s;
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
     sock_s = createServer("eth6", "169.254.18.80", NULL, "tcp");
      registerCallback(sock_s, -1, "read", process_receive_buffer);
      int reqpool[1] = {128};
      initRequest(reqpool,1);
      setData(sock_s, 0, 0, "local", "169.254.78.236");
      setData(sock_s, 0, 1, "local", "169.254.9.23");
      cout<<"after set"<<endl;
      startEventLoop();
   
  return 0;
}
