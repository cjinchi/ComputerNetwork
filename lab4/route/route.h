#ifndef ROUTE_H
#define ROUTE_H

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



//Router ONE or Router TWO
#define ROUTER_INDEX 2

#define DEFAULT 20
#define MAX_ROUTE_INFO (DEFAULT)
#define MAX_ARP_SIZE (DEFAULT)
#define MAX_DEVICE (DEFAULT)

#define BUFFER_MAX 2048

//路由表表项
struct route_item
{
    char destination[16];		//目标IP
    char gateway[16];			//网关
    char netmask[16];			//子网掩码
    char interface[16];			//接口
};

//ARP表表项
struct arp_table_item
{
    char ip_addr[16];			//ip地址
    unsigned char mac_addr[6];	//MAC地址
};

//设备表表项
struct device_item
{
    char interface[16];			//接口
    unsigned char mac_addr[6];	//MAC地址
    int ifindex;				//接口的编号
};

//init three tables by reading files
int init_router();
//judge whether this packet should be transmitted, return 0 if true
int whether_should_transmit(char buffer[],struct sockaddr_ll addr);    
//to transmit the ip packet
void transmit_packet(char buffer[]);

//search tables,return -1 if not found
int search_route_table(char *dest_ip);
int search_arp_table(char gateway[]);
int search_dev_table(char interface[]);

unsigned short get_checksum(unsigned short* buffer,int length);


#endif
