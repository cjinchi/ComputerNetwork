#include<sys/socket.h>
#include<linux/ip.h>
#include<linux/if_arp.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/icmp.h>
#include<linux/igmp.h>

//Ethernet header,for reading mac addr and type
struct eth_header
{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned char type[2];
};

//show_xxx_header:to print basic infomation of xxx header
void show_eth_header(struct eth_header* ethh);
void show_ip_header(struct iphdr* iph);
void show_tcp_header(struct tcphdr* tcph);
void show_icmp_header(struct icmphdr* icmph);
void show_udp_header(struct udphdr* udph);
void show_igmp_header(struct igmphdr* igmph);
void show_arp_header(struct arphdr* arph,unsigned char* buffer);