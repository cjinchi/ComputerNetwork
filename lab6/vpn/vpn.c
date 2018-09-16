#include "vpn.h"

//Router ONE or Router TWO
#define ROUTER_INDEX 1
#if ROUTER_INDEX==1
    //Router one
    #define INSIDE_IFINDEX (device_table[0].ifindex)
    #define OUTSIDE_IFINDEX (device_table[1].ifindex)
    #define CONFIG_FILENAME "VPNServer1"
#else
    //Router two
    #define INSIDE_IFINDEX (device_table[1].ifindex)
    #define OUTSIDE_IFINDEX (device_table[0].ifindex)
    #define CONFIG_FILENAME "VPNServer2"
#endif

char *outside_ip = 0;
char inside_mac_addr[6]={};

//Device table
struct device_item device_table[MAX_DEVICE];
int device_index=0;

int sock_fd = 0;                  //id of socket
int sock_fd2 =0;
int sock_fd3 =0;
int num_read = 0;                   //len of packet received
pid_t pid; 
char buffer[BUFFER_MAX];            //buffer to save packet
int repack_seq = 0;
int i=0;                        //just for "for loop"

int count1=0,count2=0;

int main()
{   
    if(init_socket()<0)
    {
        printf("Error when init socket\n");
        return -1;
    }
    if(init_router()<0)
    {
        printf("Error when init router\n");
		return -1;
    }
    pid=getpid();
    
    //packet sniff
    while(1)
    {
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t addr_len = sizeof(addr);	
        num_read = recvfrom(sock_fd,buffer,2048,0,(struct sockaddr *) &addr, &addr_len);

        //judge what should be done
        int ret=what_to_do(buffer,addr);
        if(ret==0)
        {
            //this packet comes from inner PC
            //should be repacked and sendted to internet
            char new_buffer[BUFFER_MAX];
            repack_packet(buffer,new_buffer);

            struct sockaddr_in dst_addr;
            memset(&dst_addr,0,sizeof(dst_addr));   
            dst_addr.sin_family = AF_INET;
        	unsigned int addr = inet_addr(outside_ip);
            memcpy((unsigned char*)&dst_addr.sin_addr,(unsigned char*)&addr,sizeof(addr));
            if(sendto(sock_fd2,(void*)(new_buffer),num_read-sizeof(struct ethhdr)+sizeof(struct icmphdr),0,(struct sockaddr*)(&dst_addr),sizeof(dst_addr))<0)   
            {
                printf("Error when sendto()\n");
            }
            else
            {
                printf("PC --->  Internet,NO %d\n",count1++);
            }

            
        }
        else if(ret==1)
        {
            //this packet comes from Internet
        	//should be unpacked and sended to inner PC

            struct sockaddr_ll dest_addr;
            memset(&dest_addr,0,sizeof(dest_addr)); 
            dest_addr.sll_family = AF_PACKET;
            dest_addr.sll_protocol = htons(ETH_P_IP);
            dest_addr.sll_halen = ETH_ALEN;
            dest_addr.sll_ifindex=INSIDE_IFINDEX;
            memcpy(dest_addr.sll_addr,inside_mac_addr,ETH_ALEN);

            if (sendto(sock_fd3, buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr), num_read-sizeof(struct ethhdr)-sizeof(struct iphdr)-sizeof(struct icmphdr), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) ==-1)
            {
                printf("Error when sendto() \n");
            }
            else
            {
                printf("Internet --->  PC,NO %d\n",count2++);
            }
        }
        else if(ret==2)
        {
            printf("Maybe the VPN Server should reply this packet\n");
        }
        else
        {
        	continue;
        }
    }
    return 0;
}


int init_router()
{
    FILE *config_file=NULL;
    config_file=fopen(CONFIG_FILENAME, "r");
    if(config_file==NULL)
    {
        printf("Error when open route table file.\n");
        return -1;
    }
    fscanf(config_file,"%s",outside_ip);
    fscanf(config_file,"%x:%x:%x:%x:%x:%x",&inside_mac_addr[0],&inside_mac_addr[1],&inside_mac_addr[2],&inside_mac_addr[3],&inside_mac_addr[4],&inside_mac_addr[5]);
    fclose(config_file);


    //init device table
    struct ifreq req;
    
    //eth0(interface,ifindex,mac)
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, "eth0", IFNAMSIZ - 1);
    if(ioctl(sock_fd, SIOCGIFADDR, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    char *eth0_interface=inet_ntoa(((struct sockaddr_in*)&(req.ifr_addr))->sin_addr);
    memcpy(device_table[device_index].interface,eth0_interface,strlen(eth0_interface));
    if(ioctl(sock_fd, SIOCGIFINDEX, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    device_table[device_index].ifindex = req.ifr_ifindex;
    if(ioctl(sock_fd, SIOCGIFHWADDR, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    memcpy(device_table[device_index].mac_addr, req.ifr_hwaddr.sa_data,6);
    device_index++;

    //eth1(interface,ifindex,mac)
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, "eth1", IFNAMSIZ - 1);
    if(ioctl(sock_fd, SIOCGIFADDR, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    char *eth1_interface=inet_ntoa(((struct sockaddr_in*)&(req.ifr_addr))->sin_addr);
    memcpy(device_table[device_index].interface,eth1_interface,strlen(eth1_interface));
    if(ioctl(sock_fd, SIOCGIFINDEX, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    device_table[device_index].ifindex = req.ifr_ifindex;
    if(ioctl(sock_fd, SIOCGIFHWADDR, &req)<0)
    {
        printf("Error when ioctl().\n");
        return -1;
    }
    memcpy(device_table[device_index].mac_addr, req.ifr_hwaddr.sa_data,6);
    device_index++;

    printf("Device table:\n");
    for(i=0;i<device_index;i++)
    {
        printf("%d %s %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\n",device_table[i].ifindex,device_table[i].interface,
            device_table[i].mac_addr[0],device_table[i].mac_addr[1],device_table[i].mac_addr[2],
            device_table[i].mac_addr[3],device_table[i].mac_addr[4],device_table[i].mac_addr[5]);
    }
    return 0;
}

int init_socket()
{
    //create socket
    sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sock_fd<0)
    {
        printf("Error create raw socket\n");
        return -1;
    }
    
    sock_fd2=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(sock_fd2<0)
    {
        printf("Error when create socket2!\n");
        return -1;
    }

    sock_fd3=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(sock_fd3<0)
    {
        printf("Error when create socket3!\n");
        return -1;
    }
    return 0;
}

int what_to_do(char buffer[],struct sockaddr_ll addr)
{
    if(num_read<42)
    {
        printf("Error when recv msg \n");
        return -1;
    }

    struct ethhdr* ehdr = (struct ethhdr*)buffer;
    if(ehdr->h_proto!=0x0008)
    {
        //No IP protocol,unnecessary to transmit
        return -2;
    }

    if(addr.sll_pkttype!=PACKET_HOST)
    {
        //unnecessary to transmit
        return -2;
    }

    if(addr.sll_ifindex==INSIDE_IFINDEX)
    {
        struct iphdr* iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));
        if(iph->daddr==inet_addr(device_table[0].interface)||iph->daddr==inet_addr(device_table[1].interface))
        {
            return 2;
        }
        else
        {
            return 0;
        }

    }
    else if(addr.sll_ifindex==OUTSIDE_IFINDEX)
    {
        if(num_read==98)
        {
            return 2;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        return -1;
    }

}

unsigned short get_checksum(unsigned short* buffer,int length)
{
    int len = length;
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

void repack_packet(char *buffer,char *new_buffer)
{
    memset(new_buffer,0,BUFFER_MAX);

    struct icmphdr* icmph=(struct icmphdr*)new_buffer;
    icmph->un.echo.sequence = repack_seq ;
    repack_seq++;
    icmph->code = 0;
    icmph->type = ICMP_ECHOREPLY;
    icmph->checksum = 0;           //init
    icmph->un.echo.id = pid & 0xffff;

    memcpy(new_buffer+sizeof(struct icmphdr),buffer+sizeof(struct ethhdr),num_read-sizeof(struct ethhdr));
    icmph->checksum = get_checksum((unsigned short*)new_buffer,num_read-sizeof(struct ethhdr)+sizeof(struct icmphdr)); 
}