#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>


#define PC_INDEX 2

//some info of packet
#define DATA_LEN 56                     
#define HEADER_LEN 8
#define TOTAL_LEN (DATA_LEN+HEADER_LEN)

//send and receive packet
void send_packet();
void receive_packet();

//pack and unpack packet
void pack(unsigned char* buffer,unsigned short seq);
int unpack(unsigned char *buffer,int packet_len);

//else
unsigned short get_checksum(unsigned short* buffer);    //calculate icmp_cksum
void final_print();                                     //print some info before exit program
