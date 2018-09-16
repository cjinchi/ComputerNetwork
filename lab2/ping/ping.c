#include "ping.h"

int running = 0;                    //the statement of PING

int packet_sent = 0;                //num of packet sent
int packet_received = 0;            //num of packet received 
int socket_fd = 0;                  //id of socket
struct sockaddr_in dst_addr;        //the dst of packet
pid_t pid;                          //pid of main

char host_name[50]={0};             //buffer to save host_name,which will be printed later
unsigned char ip_addr[4]={0};       //buffer to save ip_addr,which will be printed later

struct timeval time_begin,time_end; //begin and end time of program
double min_time=99999,max_time=0;   //max and min time from send to receive, ms

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

    //write dest addr
    memset(&dst_addr,0,sizeof(dst_addr));   
    dst_addr.sin_family = AF_INET;
    unsigned int addr = inet_addr(argv[1]);
    if(addr==INADDR_NONE)
    {
        //argv[1] is not ip addr
        struct hostent* host = gethostbyname(argv[1]);
        if(host==NULL)
        {
            printf("connect: Invalid argument\n");
            return -1;
        }
        memcpy((unsigned char*)&dst_addr.sin_addr,host->h_addr,host->h_length);
        
        //Set host name and ip
        memcpy(host_name,host->h_name,strlen(host->h_name));
        memcpy(ip_addr,host->h_addr_list[0],4);
    }
    else
    {
        //argv[1] is ip addr
        memcpy((unsigned char*)&dst_addr.sin_addr,(unsigned char*)&addr,sizeof(addr));
        
        //Set host name and ip
        memcpy(host_name,argv[1],strlen(argv[1]));
        memcpy(ip_addr,(unsigned char*)&addr,4);
    }

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
    socket_fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(socket_fd<0)
    {
        printf("Error when create socket!\n");
        return -1;
    }

    //enlarge socket's buffer
    unsigned int new_buffer_size = 128<<10;
    setsockopt(socket_fd,SOL_SOCKET,SO_RCVBUF,&new_buffer_size,sizeof(new_buffer_size));
    
    
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
        unsigned char buffer[256];
        memset(buffer,0,256);
        pack((struct icmp*)buffer,packet_sent+1);

        if(sendto(socket_fd,(void*)(buffer),TOTAL_LEN,0,(struct sockaddr*)(&dst_addr),sizeof(dst_addr))<0)   
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

void pack(struct icmp* icmph,unsigned short seq)
{
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
}

int unpack(unsigned char *buffer,int packet_len)
{
    struct ip* iph = (struct ip*)buffer;
    struct icmp* icmph = (struct icmp*)(buffer+4*iph->ip_hl);
    if(packet_len-(4*iph->ip_hl)!=TOTAL_LEN)
    {
        printf("Error,recv wrong packet!\n");
        return -1;
    }

    if(icmph->icmp_type!=ICMP_ECHOREPLY)
    {
        printf("Error,invalid packet type!\n");
        return -1;
    }

    if(icmph->icmp_id!=pid&0xffff)
    {
        printf("No my packet!\n");
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