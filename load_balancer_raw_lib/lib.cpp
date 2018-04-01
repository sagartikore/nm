#include"lib.h"
 int sock_r, sock_s;
struct nm_desc *lib_netmap_desc;
struct netmap_if *nifp;
struct netmap_ring *send_ring, *receive_ring;
struct nmreq nmr;
struct pollfd fds;
int fd, length;
int do_abort = 1;
const char *src_ip = "169.254.18.80";
const char *src_ip1;// = "169.254.18.80";
const char *src_mac = "00:aa:bb:cc:dd:04";
char* backend_mac_pool[2] = {"00:aa:bb:cc:dd:03", "00:aa:bb:cc:dd:06"};
unordered_map<int, fn> funct_ptr;
unordered_map<int, string> conn_map;
unordered_map<int, int> conn_map1;
int map_index=0;
//data store part
boost::simple_segregated_storage<std::size_t> storageds;  //memory pool for data store
std::vector<char> mp_ds(64*131072);  //assuming value size 64 TODO
unordered_map<int, void*> ds_map1;   //data store if option is local //TODO make it general using boost
unordered_map<void*, int>local_list; //local list of addr for clearing cache..local dnt remove
unordered_map<int, void*>cache_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>cache_void_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>reqptr_list;  //list of addr pointed in req object needed for clearing cache..pointed dnt remove
mutex mct,eparr,sock_c,f_ptr_lock,mp_lock,ds_lock,ds_conn_lock;
//this were per core variables
unordered_map<int, void*> mem_ptr;
unordered_map<int, int> client_list;
std::unordered_map<int,int>::const_iterator got;
boost::simple_segregated_storage<std::size_t> storage1; 
	boost::simple_segregated_storage<std::size_t> storage2;
	boost::simple_segregated_storage<std::size_t> storage3;
	boost::simple_segregated_storage<std::size_t> storage4;
	int memory_size[4];
//
int ds_size = 0; //to keep count. If exceeds threshold clear
int ds_threshold = 131072, ds_sizing=1;
int ds_portno[4] = {7000,7001,7002,7003}; 
/*
 * Convert an ASCII representation of an ethernet address to
 * binary form.
 */
 
void initRequest(int msize[], int m_tot){  //size of chunks for request pool and total number of sizes sizeof(msize[])
	int p = 1,i,j;
	 cout<<"reached here"<<endl;
	int temp_memory_size[4];
//	req_pool_needed = 1;
	if(m_tot>4){
		cout<<"Only 4 pools allowed"<<endl;
		return;  //TODO error handling
	}	
        for(i=0;i<m_tot;i++){
		p=1;
		temp_memory_size[i]=0;
		if (msize[i] && !(msize[i] & (msize[i] - 1))){
			temp_memory_size[i] = msize[i];
			continue;
		}
		while (p < msize[i]) 
			p <<= 1;
	
			temp_memory_size[i] = p;
	}
	cout<<"MEMORY_size is "<<temp_memory_size[0]<<endl; 
	for(i=0;i<MAX_THREADS;i++){
		for(j=0;j<m_tot;j++){
			memory_size[j] = temp_memory_size[j];	
		}
	}
/*        cout<<"reached here"<<endl;
	std::vector<char> v(memory_size*100);
	v.reserve(memory_size*100);
	storage.add_block(&v.front(), v.size(), memory_size);
        cout<<"reached here"<<endl;
*/	
}

void free_ds_pool(){
/*	std::unordered_map<void*,int>::const_iterator gotds;  //iterator over client_list
	BOOST_FOREACH(void *item, ds_map1)
    {
	gotds = local_list.find(item);
                if(got_ds == local_list.end()){
		     //   std::cout << "[" << item->num << "] ";
			key = cache_void_list[item];	
			cache_void_list.erase(item);
			cache_list.erase(key);
	       		storageds.free(item);
			
	 	}
    }*/
	std::unordered_map<void*,int>::const_iterator gotds;
	for ( auto it = cache_void_list.begin(); it != cache_void_list.end(); ++it ){
		gotds = reqptr_list.find(it->first);
		if(gotds == reqptr_list.end()){
			cache_list.erase(it->second);
			ds_map1.erase(it->second);
			storageds.free(it->first);
		}
	}
	cache_void_list.clear();
	ds_size = 0;
}
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

void registerCallback(int connID, int id, string event, void callbackFnPtr(int, int,  void*, char*))
{
    /*if(sock_count.find(connID)==sock_count.end())
     *  {
     *          //client sock not found
     *              //  cout<<"register call back reached here "<< connID << callbackFnPtr << endl;
     *                      funct_ptr[connID] = callbackFnPtr;
     *
     *                          }
     *                              else
     *                                  {
     *                                          //server sock found
     *                                                  for(int i=0;i<MAX_THREADS;i++){     //should be s_count check priya
     *                                                          //  cout<<"register call back sock"<<sock_count[0][i]<<endl;
     *                                                                      funct_ptr[sock_count[0][i]] = callbackFnPtr;
     *                                                                              }
     *                                                                                      
     *                                                                                          }*/
    if(id != -1)
        funct_ptr[connID] = callbackFnPtr;
    else
        funct_ptr[connID] = callbackFnPtr;

}
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
void insert_arp_cache(uint32_t ip, struct ether_addr mac) {
    int i;
    struct arp_cache_entry *entry;
    char ip_str[INET_ADDRSTRLEN];
    for(i = 0; i < ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];
        if (entry->ip == ip) {
            printf("arp entry already exists\n");
            return;
        }
        if (entry->ip == 0) {
            entry->ip = ip;
            entry->mac = mac;
            printf("arp entry created\n");
            return;

        }
    }
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
    printf("###########################\n");
    printf("sending arp reply\n");
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
    printf("arp source mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arp_reply->eh.ether_shost[0], arp_reply->eh.ether_shost[1],
          arp_reply->eh.ether_shost[2], arp_reply->eh.ether_shost[3], arp_reply->eh.ether_shost[4], arp_reply->eh.ether_shost[5]);
    printf("arp dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arp_reply->eh.ether_dhost[0], arp_reply->eh.ether_dhost[1],
            arp_reply->eh.ether_dhost[2], arp_reply->eh.ether_dhost[3], arp_reply->eh.ether_dhost[4], arp_reply->eh.ether_dhost[5]);
    char arp_src_ip[INET_ADDRSTRLEN];
    char arp_target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(arp_reply->ah.target_ip), arp_target_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_reply->ah.sender_ip), arp_src_ip, INET_ADDRSTRLEN);
    printf("arp target ip %s\n", arp_target_ip);
    printf("arp source ip %s\n", arp_src_ip);
    printf("#############################\n");
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
void handle_arp_packet(char* buffer){
	// make entry in arp cache
	struct arp_pkt *arppkt;
      struct ether_addr sender_mac;
       arppkt = (struct arp_pkt *)buffer;
      char arp_target_ip[INET_ADDRSTRLEN];
      char arp_sender_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(arppkt->ah.target_ip), arp_target_ip, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(arppkt->ah.sender_ip), arp_sender_ip, INET_ADDRSTRLEN);
      
      memcpy(&sender_mac, (struct ether_addr *)arppkt->ah.sender_mac, 6);
      insert_arp_cache(arppkt->ah.sender_ip, sender_mac);
      printf("after insert:%s\n", src_ip1);
      
      if(strcmp(arp_target_ip, src_ip) == 0){
      	printf("matched\n");
      	printf("arp code:%d\n", arppkt->ah.opcode);
        if (ntohs(arppkt->ah.opcode) == ARP_REQUEST) {
            printf("ARP REQUEST packet from: %s\n", arp_sender_ip);
            /* send arp reply */
            arp_reply(arppkt);
        }
        if (ntohs(arppkt->ah.opcode) == ARP_REPLY) {
            printf("ARP REPLY packet from: %s\n", arp_sender_ip);
            printf("ARP REPLY sender mac:%02x:%02x:%02x:%02x:%02x:%02x\n", arppkt->eh.ether_shost[0], arppkt->eh.ether_shost[1],
                    arppkt->eh.ether_shost[2], arppkt->eh.ether_shost[3], arppkt->eh.ether_shost[4], arppkt->eh.ether_shost[5]);
        }
      }
}
char* writePktmem(int id){
	char *dst = NETMAP_BUF(send_ring, send_ring->slot[send_ring->cur].buf_idx);
	return dst;
}
int createClient(int id, string local_ip , string remoteServerIP, int remoteServerPort, string protocol){
	//netmap fd passed instaed of id
	map_index = map_index + 1; 
	conn_map[map_index] = remoteServerIP;
	conn_map1[map_index] = remoteServerPort;
	return map_index;
}
void sendData(int connID, int id, char* packetToSend, int size){
	 struct sockaddr_in sin;
    sin.sin_family = AF_INET;
   sin.sin_port = conn_map1[id];
 sin.sin_addr.s_addr = inet_addr (conn_map[id].c_str());
 int one = 1;
    const int *val = &one;
 if (setsockopt (connID, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");

    if (sendto (connID,        /* our socket */
                packetToSend, /* the buffer containing headers and data */
                size,  /* total length of packet */
                0,        /* routing flags, normally always 0 */
                (struct sockaddr *) &sin, /* socket addr, just like in */
                sizeof (sin)) < 0)        /* a normal send() */
    {
        //printf ("error:%s\n", strerror(errno));
        //exit(EXIT_FAILURE);
    }
    else{
        //printf("sent\n");
    }

	
}
static void
sigint_h(int sig)
{
    (void)sig;  /* UNUSED */
    do_abort = 1;
    nm_close(lib_netmap_desc);
    printf("file closed\n");
    signal(SIGINT, SIG_DFL);
}
int createServer(string inter_face, string server_ip, int server_port, string protocol){
    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    sock_s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    memset(buffer,0,65536);
    if(sock_r<0)
    {
        printf("error in socket\n");
        return -1;
    }
     if(ds_sizing==1){
	        storageds.add_block(&mp_ds.front(), mp_ds.size(), 64);
		ds_sizing=0;
	}
	
    return sock_s;
}
void startEventLoop(){
    fn fn_ptr;
    int r;
    char *src;
   // int my_fd = fds.fd;
    signal(SIGINT, sigint_h);
    //datastore part
    std::vector<char> mp_v1;
	std::vector<char> mp_v2;
	std::vector<char> mp_v3;
	std::vector<char> mp_v4;
	if(memory_size[0] != 0){
	//std::vector<char> mp_v1(memory_size[0]*2097152);
	mp_v1.resize((memory_size[0])*2097152);
//	mp_v.resize(memory_size*1000000); //uncomment nov22
	cout<<"vector size is "<<mp_v1.size()<<endl;
        storage1.add_block(&mp_v1.front(), mp_v1.size(), memory_size[0]);  //uncomment nov22
	}
	if(memory_size[1]!=0){
        //std::vector<char> mp_v2(memory_size[1]*2097152);
	mp_v2.resize((memory_size[1])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v2.size()<<endl;
        storage2.add_block(&mp_v2.front(), mp_v2.size(), memory_size[1]);  //uncomment nov22
        }
	if(memory_size[2]!=0){
        //std::vector<char> mp_v3(memory_size[2]*2097152);
	mp_v3.resize((memory_size[2])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v3.size()<<endl;
        storage3.add_block(&mp_v3.front(), mp_v3.size(), memory_size[2]);  //uncomment nov22
        }
	if(memory_size[3]!=0){
        //std::vector<char> mp_v4(memory_size[3]*2097152);
	mp_v4.resize((memory_size[3])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v4.size()<<endl;
        storage4.add_block(&mp_v4.front(), mp_v4.size(), memory_size[3]);  //uncomment nov22
        }
    //
    int buflen;
    unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    memset(buffer,0,65536);
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    cout<<"before while"<<endl;
   while(1){
        /* receive packets*/
        buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        fn_ptr = funct_ptr[sock_s];
        mem_ptr[sock_s] = NULL; //memory for request object
        fn_ptr(sock_s, 0, NULL, buffer);
        //process_receive_buffer(sock_s, 0, NULL, buffer);
    }
}
void* allocReqCtxt(int alloc_sockid, int id, int index){
        client_list[alloc_sockid] = alloc_sockid;
	if(index==1){
	        mem_ptr[alloc_sockid] = static_cast<void*>(storage1.malloc());    //lock TODO
	}
	else if(index==2){
		mem_ptr[alloc_sockid] = static_cast<void*>(storage2.malloc());    //lock TODO
	}
	else if(index==3){
                mem_ptr[alloc_sockid] = static_cast<void*>(storage3.malloc());    //lock TODO
        }
	else if(index==4){
                mem_ptr[alloc_sockid] = static_cast<void*>(storage4.malloc());    //lock TODO
        }
        if(mem_ptr[alloc_sockid]==0){
              cout<<"could not malloc"<<endl;
       }
	return mem_ptr[alloc_sockid];

}
void freeReqCtxt(int alloc_sockid, int id, int index){
	 got = client_list.find(alloc_sockid);
         if (got == client_list.end()){
              //free(mem_ptr[events[i].data.sockid]);
              mem_ptr.erase(alloc_sockid);
             //storage1.free(mem_ptr[events[i].data.sockid]);
         }   //uncomment nov23
         else{
             //cout<<"address in erase is "<<newsockfd<<" "<<(void*)mem_ptr[newsockfd]<<endl;
	     if(index==1){
             	storage1.free(static_cast<void*>(mem_ptr[alloc_sockid]));
	     }
	     else if(index==2){
		storage2.free(static_cast<void*>(mem_ptr[alloc_sockid]));
	     }
	     else if(index==3){
                storage3.free(static_cast<void*>(mem_ptr[alloc_sockid]));
             }
	     else if(index==4){
                storage4.free(static_cast<void*>(mem_ptr[alloc_sockid]));
             }
             mem_ptr.erase(alloc_sockid);  //uncomment nov22
             client_list.erase(alloc_sockid);

         }

}

void setData(int connID, int id, int key, string localRemote, string value){
	if(localRemote=="local"){
	
		value = value + '\0';
		void* setds;
		ds_lock.lock();
		if(ds_size==ds_threshold){
                        free_ds_pool();
                }	
               // cout<<"setdata"<<endl;
		setds = storageds.malloc();
		ds_size++;
		//value = value + '\0';
                memcpy(setds,value.c_str(),value.length());
               // cout<<"setdata"<<endl;
                ds_map1[key] = setds;
                local_list[setds] = key;
		ds_lock.unlock();
		//ds_map[key]=value;
	}
}

void getData(int connID, int id, int key, string localRemote, void callbackFnPtr(int, int,  void*, char*)){
	registerCallback(connID, id, "read", callbackFnPtr);
	if(localRemote=="local"){
		
		 fn fn_ptr;
		 char* ds_value;
		 ds_lock.lock();
		 ds_value = static_cast<char*>(ds_map1[key]);
		 ds_lock.unlock();
		 //f_ptr_lock.lock(); //TODO add lock
                 fn_ptr = funct_ptr[connID];
                 //f_ptr_lock.unlock();
                 fn_ptr(connID, id, mem_ptr[connID], ds_value);
                
		
	}
}

