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

#define MAX_DEVICE 20
#define BUFFER_MAX 2048

//设备表表项
struct device_item
{
    char interface[16];			//接口
    unsigned char mac_addr[6];	//MAC地址
    int ifindex;				//接口的编号
};

int init_router();
int init_socket();
int what_to_do(char buffer[],struct sockaddr_ll addr);    
unsigned short get_checksum(unsigned short* buffer,int length);
void repack_packet(char *buffer,char *new_buffer);


#endif
