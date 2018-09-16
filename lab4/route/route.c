#include "route.h"

#if ROUTER_INDEX==1
    //Router one
    const char* eth0_interface="192.168.2.1";
    const char* eth1_interface="192.168.4.1";
    const char* arp_table_filename="Router1_ARP_table";
    const char* route_table_filename="Router1_IP_table";
#else
    //Router two
    const char* eth0_interface="192.168.3.1";
    const char* eth1_interface="192.168.4.2";
    const char* arp_table_filename="Router2_ARP_table";
    const char* route_table_filename="Router2_IP_table";
#endif



//Route table
struct route_item route_table[MAX_ROUTE_INFO];
int route_index=0;
//ARP table
struct arp_table_item arp_table[MAX_ARP_SIZE];
int arp_index =0;
//Device table
struct device_item device_table[MAX_DEVICE];
int device_index=0;

int sock_fd = 0;                  //id of socket
int sock_fd2 =0 ;
int num_read = 0;                   //len of packet received
char buffer[BUFFER_MAX];            //buffer to save packet

int i=0;
int main()
{   
    //create socket
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

    //init three tables by reading files (Route table, ARP table) or function ioctl(dev table)
    if(init_router()<0)
    {
        printf("Error intit\n");
		return -1;
    }
    
    //packet sniff
    while(1)
    {
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t addr_len = sizeof(addr);	
        num_read = recvfrom(sock_fd,buffer,2048,0,(struct sockaddr *) &addr, &addr_len);
        if(num_read<42)
        {
            printf("Error when recv msg \n");
			continue;
        }

        //judge whether this packet should be transmitted by me
        if(whether_should_transmit(buffer,addr)<0)
        {
            continue;
        }

        //to transmit the ip packet
        transmit_packet(buffer);
    } 
}

int init_router()
{
    //init route table
    FILE *rt_file=NULL;
    rt_file=fopen(route_table_filename, "r");
    if(rt_file==NULL)
    {
        printf("Error when open route table file.\n");
        return -1;
    }
    printf("Route table:\n");
    while(!feof(rt_file))
    {
        fscanf(rt_file,"%s %s %s %s",route_table[route_index].destination,route_table[route_index].gateway,route_table[route_index].netmask,route_table[route_index].interface);
        printf("%s %s %s %s\n",route_table[route_index].destination,route_table[route_index].gateway,route_table[route_index].netmask,route_table[route_index].interface);
        route_index++;
    }
    fclose(rt_file);

    //init arp table
    FILE *at_file=NULL;
    at_file=fopen(arp_table_filename, "r");
    if(at_file==NULL)
    {
        printf("Error when open ARP table file.\n");
        return -1;
    }
    printf("ARP table:\n");
    while(!feof(at_file))
    {
        unsigned int temp_mac_addr[6]={};
        fscanf(at_file,"%s %x:%x:%x:%x:%x:%x",arp_table[arp_index].ip_addr,&temp_mac_addr[0],&temp_mac_addr[1],&temp_mac_addr[2],&temp_mac_addr[3],&temp_mac_addr[4],&temp_mac_addr[5]);
        for(i=0;i<6;i++)
        {
            arp_table[arp_index].mac_addr[i]=(unsigned char)temp_mac_addr[i];
        }

        printf("%s %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\n",arp_table[arp_index].ip_addr,
            arp_table[arp_index].mac_addr[0],arp_table[arp_index].mac_addr[1],arp_table[arp_index].mac_addr[2],
            arp_table[arp_index].mac_addr[3],arp_table[arp_index].mac_addr[4],arp_table[arp_index].mac_addr[5]);
        arp_index++;
    }
    fclose(at_file);

    //init device table
    struct ifreq req;
    
    memcpy(device_table[device_index].interface,eth0_interface,strlen(eth0_interface));
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, "eth0", IFNAMSIZ - 1);
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

    memcpy(device_table[device_index].interface,eth1_interface,strlen(eth1_interface));
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, "eth1", IFNAMSIZ - 1);
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

int whether_should_transmit(char buffer[],struct sockaddr_ll addr)
{
    struct ethhdr* ehdr = (struct ethhdr*)buffer;
    if(ehdr->h_proto!=0x0008)
    {
        printf("No IP protocol.\n");
        return -1;
    }

    if(addr.sll_pkttype!=PACKET_HOST)
    {
        //printf("No need to transmit.\n");
        return -1;
    }

    int eth_header_len = sizeof(struct ethhdr);
    struct iphdr* iph = (struct iphdr*)(buffer+eth_header_len);
    struct in_addr ip_format_temp;
    ip_format_temp.s_addr=iph->daddr;
    char *dest_ip=inet_ntoa(ip_format_temp);
    if(strcmp(dest_ip,eth0_interface)==0||strcmp(dest_ip,eth1_interface)==0)
    {
        printf("SHOULD REPLAY HERE\n");
		
		//exchange ip
		buffer+=eth_header_len;
		struct ip* iph=(struct ip*)buffer;
		struct in_addr temp;
		memcpy(&temp,&iph->ip_dst,sizeof(struct in_addr));
		memcpy(&iph->ip_dst,&iph->ip_src,sizeof(struct in_addr));
		memcpy(&iph->ip_src,&temp,sizeof(struct in_addr));
		
		struct icmp* icmph=(struct icmp*)(buffer+sizeof(struct ip));
		icmph->icmp_type=ICMP_ECHOREPLY;
		
		//modify checksum here
		icmph->icmp_cksum = 0;
		iph->ip_sum=0;
		icmph->icmp_cksum = get_checksum((unsigned short*)icmph,64);
		iph->ip_sum=get_checksum((unsigned short*)iph,20);
        return 0;
    }

    return 0;

}


//search tables,return -1 if not found
int search_route_table(char *dest_ip)
{
    int index=-1;
    for(i=0;i<route_index;i++)
    {
        if(strcmp(dest_ip,route_table[i].destination)==0)
        {
            index=i;
            break;
        }
    }
    return index;
}
int search_arp_table(char gateway[])
{
    int index=-1;
    for(i=0;i<arp_index;i++)
    {
        if(strcmp(gateway,arp_table[i].ip_addr)==0)
        {
            index=i;
            break;
        }
    }
    return index;
}
int search_dev_table(char interface[])
{
    int index=-1;
    for(i=0;i<device_index;i++)
    {
        if(strcmp(interface,device_table[i].interface)==0)
        {
            index=i;
            break;
        }
    }
    return index;
}

void transmit_packet(char buffer[])
{
    int eth_header_len = sizeof(struct ethhdr);
    struct ip* iph = (struct ip*)(buffer+eth_header_len);
    
    //search ip table by dest ip
    //struct in_addr ip_format_temp;
    //ip_format_temp.s_addr=(struct in_addr_t)iph->ip_dst;
    char *dest_ip=inet_ntoa(iph->ip_dst);
	printf("dest ip=%s\n",dest_ip);
    int rt_index = search_route_table(dest_ip);
    if(rt_index == -1)
    {
        printf("Not found in route table.\n");
        return;
    }

    //search ARP table by gateway
    int at_index = search_arp_table(route_table[rt_index].gateway);
    if(rt_index == -1)
    {
        printf("Not found in ARP table.\n");
        return;
    }

    //search DEV table by interface
    int dt_index = search_dev_table(route_table[rt_index].interface);
    if(dt_index == -1)
    {
        printf("Not found in DEV table.\n");
        return;
    }


    //send packet,finish transmitting
    struct sockaddr_ll dest_addr;
	memset(&dest_addr,0,sizeof(dest_addr)); 
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_IP);
    dest_addr.sll_halen = ETH_ALEN;
    dest_addr.sll_ifindex=device_table[dt_index].ifindex;
    memcpy(dest_addr.sll_addr,arp_table[at_index].mac_addr,ETH_ALEN);
	printf("dest mac=%x:%x:%x\n",arp_table[at_index].mac_addr[3],
	arp_table[at_index].mac_addr[4],arp_table[at_index].mac_addr[5]);
	
    if (sendto(sock_fd2, iph, sizeof(struct ip)+64, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) ==-1)
    {
        printf("Error when send msg \n");
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
