#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

#define PC_INDEX 2
#if PC_INDEX==1
    unsigned char dst_mac[6]={0x00,0x0c,0x29,0x54,0xd3,0xb3};
    unsigned char src_mac[6]={0x00,0x0c,0x29,0x7d,0x15,0xa1};
    const char src_ip[]="192.168.2.2";
#else
    unsigned char dst_mac[6]={0x00,0x0c,0x29,0x2e,0x97,0x1d};
    unsigned char src_mac[6]={0x00,0x0c,0x29,0xec,0xee,0x1c};
    const char src_ip[]="192.168.3.2";
#endif
#define BUFFER_MAX 2048


int sock_fd = 0;                  //id of socket
int sock_fd2 =0 ;
int num_read = 0;                   //len of packet received
char buffer[BUFFER_MAX]={};            //buffer to save packet
int my_index=0;

unsigned short get_checksum(unsigned short* buffer)
{
    int len = 20;
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

int main()
{
	sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_fd<0)
	{
		printf("Error create raw socket\n");
		return -1;
    }
	
	sock_fd2=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(sock_fd2<0)
    {
        printf("Error when create socket2!\n");
        return -1;
    }
	
	while(1)
	{
		num_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(num_read<42)
        {
            printf("Error when recv msg \n");
			continue;
        }
		
		int eth_header_len = sizeof(struct ethhdr);
		struct iphdr* iph = (struct iphdr*)(buffer+eth_header_len);
		struct in_addr ip_format_temp;
		ip_format_temp.s_addr=iph->daddr;
		char *dest_ip=inet_ntoa(ip_format_temp);
		if(strcmp(dest_ip,src_ip)==0)
		{
			my_index++;
			printf("TO_REPLY %d\n",my_index);
			//buffer+=eth_header_len;
			struct ip* iph=(struct ip*)(buffer+eth_header_len);
			struct in_addr temp;
			memcpy(&temp,&iph->ip_dst,sizeof(struct in_addr));
			memcpy(&iph->ip_dst,&iph->ip_src,sizeof(struct in_addr));
			memcpy(&iph->ip_src,&temp,sizeof(struct in_addr));
			
			iph->ip_sum=0;
			iph->ip_sum=get_checksum((unsigned short*)iph);
		
			struct icmp* icmph=(struct icmp*)(buffer+eth_header_len+sizeof(struct ip));
			icmph->icmp_type=ICMP_ECHOREPLY;
			
			
			struct ifreq req;
			memset(&req, 0, sizeof(req));
			strncpy(req.ifr_name, "eth0", IFNAMSIZ - 1);
			if(ioctl(sock_fd, SIOCGIFINDEX, &req)<0)
			{
				printf("Error when ioctl().\n");
				return -1;
			}
			int ifindex=req.ifr_ifindex;
			
			 struct sockaddr_ll dest_addr;
			memset(&dest_addr,0,sizeof(dest_addr)); 
			dest_addr.sll_family = AF_PACKET;
			dest_addr.sll_protocol = htons(ETH_P_IP);
			dest_addr.sll_halen = ETH_ALEN;
			dest_addr.sll_ifindex=ifindex;
			memcpy(dest_addr.sll_addr,dst_mac,ETH_ALEN);
	
			if (sendto(sock_fd2, iph, sizeof(struct ip)+64, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) ==-1)
			{
				printf("Error when send msg \n");
			}
		}
	}
	return 0;
	
}