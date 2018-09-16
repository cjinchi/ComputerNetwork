#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include "header.h"

#define BUFFER_MAX 2048

int main(int argc,char* argv[])
{
	int sock_fd;
	int n_read;
	char buffer[BUFFER_MAX];
	struct eth_header* ethh;
	unsigned int count=1;
	unsigned char *type;

	//create socket
	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
	{
		printf("Error create raw socket\n");
		return -1;
	}

	//packet capture begin here
	while(1)
	{
		//show basic info
		printf("---------------PACKET-");
		printf("%.4u",count);
		printf("------------------------\n");

		//capture
		n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read < 42)
		{
			printf("Error when recv msg \n");
			return -1;
		}

		//stpe.1 Ethernet
		ethh = (struct eth_header*)buffer;
		show_eth_header(ethh);

		//step.2
		if((ethh->type[0]==0x08)&&(ethh->type[1]==0x06))
		{	
			// ARP (0x0806)
			struct arphdr* arph = (struct arphdr*)(buffer+14);
			unsigned char* mac_and_ip = (unsigned char*)(buffer+14+8);
			show_arp_header(arph,mac_and_ip);
		}
		else if((ethh->type[0]==0x08)&&(ethh->type[1]==0x00))
		{
			//IP (0x0800)
			struct iphdr* iph = (struct iphdr*)(buffer+14);
			show_ip_header(iph);

			switch(iph->protocol)
			{
				case IPPROTO_ICMP:	
				{
					//ICMP
					struct icmphdr *icmph = (struct icmphdr*)(buffer+14+4*(iph->ihl));
					show_icmp_header(icmph);
					break;
				}	
				case IPPROTO_TCP:
				{
					//TCP
					struct tcphdr *tcph = (struct tcphdr*)(buffer+14+4*(iph->ihl));
					show_tcp_header(tcph);
					break;
				}
				case IPPROTO_UDP:
				{
					//UDP
					struct udphdr *udph = (struct udphdr*)(buffer+14+4*(iph->ihl));
					show_udp_header(udph);
					break;
				}
				case IPPROTO_IGMP:
				{
					//IGMP
					struct igmphdr *igmph = (struct igmphdr*)(buffer+14+4*(iph->ihl));
					show_igmp_header(igmph);
					break;
				}
				default:printf("NONE\n");break;
			}
		}
		else 
		{
			return -1;
		}
		printf("--------------------------------------------------\n");
		count++;
	}
	return -1;
}