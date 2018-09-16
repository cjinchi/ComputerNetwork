#include "ping.h"

int running = 0;                    //the statement of PING

int packet_sent = 0;                //num of packet sent
int packet_received = 0;            //num of packet received 
int socket_fd = 0;                  //id of socket
struct sockaddr_ll dst_addr;        //the dst of packet
pid_t pid;                          //pid of main

char host_name[50]={0};             //buffer to save host_name,which will be printed later
unsigned char ip_addr[4]={0};       //buffer to save ip_addr,which will be printed later

struct timeval time_begin,time_end; //begin and end time of program
double min_time=99999,max_time=0;   //max and min time from send to receive, ms


#define BUFFER_SIZE 2048
#if PC_INDEX==1
    unsigned char dst_mac[6]={0x00,0x0c,0x29,0x54,0xd3,0xb3};
    unsigned char src_mac[6]={0x00,0x0c,0x29,0x7d,0x15,0xa1};
    const char src_ip[]="192.168.2.2";
#else
    unsigned char dst_mac[6]={0x00,0x0c,0x29,0x2e,0x97,0x1d};
    unsigned char src_mac[6]={0x00,0x0c,0x29,0xec,0xee,0x1c};
    const char src_ip[]="192.168.3.2";
#endif
char dest_ip[16]={'\0'};

int main(int argc,char* argv[])
{
    //init buffers
    memset(host_name,0,50);
    memset(ip_addr,0,50);
    
    //Invalid usage
    if(argc<2)
    {
        printf("Usage: ./ping destination\n");
        return -1;
    }

    unsigned int addr = inet_addr(argv[1]);
        
    //Set host name and ip
	memcpy(dest_ip,argv[1],strlen(argv[1]));
    memcpy(host_name,argv[1],strlen(argv[1]));
    memcpy(ip_addr,(unsigned char*)&addr,4);

    //PING begin
    printf("PING %s (%u.%u.%u.%u) 56(84) bytes of data.\n",host_name,ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
    running = 1;
    
    //system end when user enter Ctrl+c
    signal(SIGINT, final_print);

    //record current time as begin time
    gettimeofday(&time_begin,NULL);

    //get pid ,which will be icmp_header's id
    pid=getpid();                           
        
    //create socket
    socket_fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(socket_fd<0)
    {
        printf("Error when create socket!\n");
        return -1;
    }

    //enlarge socket's buffer
    unsigned int new_buffer_size = 128<<10;
    setsockopt(socket_fd,SOL_SOCKET,SO_RCVBUF,&new_buffer_size,sizeof(new_buffer_size));
    
	//send_packet();
    pthread_t send_id,receive_id;
    if(pthread_create(&send_id,NULL,(void*)send_packet,NULL)
        ||pthread_create(&receive_id,NULL,(void*)receive_packet,NULL))
    {
        printf("Error when create pthread!\n");
        return -1;
    }

    pthread_join(send_id,NULL);
    pthread_join(receive_id,NULL);


    close(socket_fd);
    return 0;
}


void send_packet()
{
    while(running==1)
    {
        //create buffer to save packet
        unsigned char buffer[BUFFER_SIZE];
        memset(buffer,0,BUFFER_SIZE);
        pack(buffer,packet_sent+1);

		    //write dest addr
    memset(&dst_addr,0,sizeof(dst_addr));   

	struct ifreq req;
	memset(&req,0,sizeof(req));
	
	strncpy(req.ifr_name,"eth0",IFNAMSIZ-1);
	ioctl(socket_fd,SIOCGIFINDEX,&req);
	
	dst_addr.sll_ifindex=req.ifr_ifindex;
	dst_addr.sll_halen=ETH_ALEN;
    dst_addr.sll_family = AF_PACKET;
	dst_addr.sll_protocol=htons(ETH_P_IP);
	
	memcpy(dst_addr.sll_addr,dst_mac,ETH_ALEN);
		
        if(sendto(socket_fd,(void*)(buffer),sizeof(struct ip)+TOTAL_LEN,0,(struct sockaddr*)(&dst_addr),sizeof(dst_addr))<0)   
        {
            printf("Error when send()\n");
        }
        else
        {
            packet_sent++;
            sleep(1);
        }
    }
}

void receive_packet()
{
    //select func wait for 500 microseconds
    struct timeval time_to_wait;
    time_to_wait.tv_sec = 0;
    time_to_wait.tv_usec = 100;

    while(running==1)
    {
        int packet_len = 0;
        unsigned char buffer[1024];
        memset(buffer,0,sizeof(buffer));
    
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(socket_fd, &fds);
        if(select(socket_fd+1, &fds, NULL, NULL, &time_to_wait)>0)          
        {
            packet_len = recv(socket_fd, buffer, sizeof(buffer), 0);
            if(unpack(buffer,packet_len)==0)
                packet_received++;
        }
    }
}

void pack(unsigned char *buffer,unsigned short seq)
{
	struct ip* iph=(struct ip*)buffer;
    struct icmp* icmph =(struct icmp*)(buffer+sizeof(struct ip));
    
	//printf("dest_ip:%s\nsrc_ip:%s\n",dest_ip,src_ip);

	iph->ip_off=ntohs(IP_DF);
	iph->ip_len=ntohs(BUFFER_SIZE);
	iph->ip_v=4;
	iph->ip_hl=5;
	iph->ip_tos=0;
	iph->ip_id=pid & 0xffff;
	iph->ip_ttl=64;
	iph->ip_p=1;
	iph->ip_sum=0;
	inet_aton(dest_ip,(struct in_addr *)(&iph->ip_dst));
    inet_aton(src_ip,(struct in_addr *)(&iph->ip_src));

    icmph->icmp_seq = seq ;
    icmph->icmp_code = 0;
    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_cksum = 0;           //init
    icmph->icmp_id = pid & 0xffff;
    
    //write send time to icmp_data
    memset(&icmph->icmp_data,0,sizeof(icmph->icmp_data));
    struct timeval send_time;
    gettimeofday(&send_time,NULL);
    memcpy(&icmph->icmp_data,&send_time,sizeof(send_time));
    
    //calculate checksum
    icmph->icmp_cksum = get_checksum((unsigned short*)icmph);
	iph->ip_sum=get_checksum((unsigned short*)iph);
	
}

int unpack(unsigned char *buffer,int packet_len)
{
    struct ip* iph = (struct ip*)buffer;
    struct icmp* icmph = (struct icmp*)(buffer+4*iph->ip_hl);
    if(packet_len-(4*iph->ip_hl)!=TOTAL_LEN)
    {
        //printf("Error,recv wrong packet!\n");
        return -1;
    }

    if(icmph->icmp_type!=ICMP_ECHOREPLY)
    {
        //printf("Error,invalid packet type!\n");
        return -1;
    }

    if(icmph->icmp_id!=pid&0xffff)
    {
        //printf("No my packet!\n");
        return -1;
    }
    
    //Get and show info here

    struct timeval send_time = *(struct timeval*)(icmph->icmp_data);
    struct timeval receive_time;
    gettimeofday(&receive_time,NULL);
    double times = (double)(receive_time.tv_usec)-(double)(send_time.tv_usec)+1000000*((double)receive_time.tv_sec-(double)send_time.tv_sec);
    times/=1000;    //from us to ms
    if(times>max_time)
        max_time = times;
    if(times<min_time)
        min_time = times;

    printf("64 bytes from %s (%u.%u.%u.%u): icmp_seq=%u ttl=128 time=%.1f ms\n",host_name,ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3],
            icmph->icmp_seq,times);
    return 0;
}


unsigned short get_checksum(unsigned short* buffer)
{
    int len = TOTAL_LEN;
    unsigned int result = 0;
    while(len/2>0)
    {
        result+=(*buffer);
        len-=2;
        buffer++;
    }
    if(len==1)
    {
        result+=*((unsigned char*)buffer);
    }

    result = (result&0xffff)+(result>>16);
    result+=(result>>16);
    return (unsigned short)(~result);
}


void final_print()
{
    //stop system
    running = 0;

    //record current time as end time
    gettimeofday(&time_end,NULL);

    double total_time = (double)(time_end.tv_usec)-(double)(time_begin.tv_usec)+1000000*((double)time_end.tv_sec-(double)time_begin.tv_sec);
    total_time/=1000;   //from us to ms

    printf("\n--- %s ping statistics ---\n",host_name);
    printf("%u packets transmitted, %u received, %.1f%%packet loss, time %.0fms\n",
        packet_sent,packet_received,(100*(double)(packet_sent-packet_received))/(double)packet_sent,total_time);
    printf("rtt min/max/ = %.3f/%.3f ms\n",min_time,max_time);
}
