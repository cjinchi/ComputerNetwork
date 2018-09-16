#include "header.h"
#include<stdio.h>

void show_eth_header(struct eth_header* ethh)
{
    printf("Ethernet:\n");
    printf("    Source MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
        ethh->src_mac[0],ethh->src_mac[1],ethh->src_mac[2],ethh->src_mac[3],ethh->src_mac[4],ethh->src_mac[5]);
    printf("    Destination MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
        ethh->dst_mac[0],ethh->dst_mac[1],ethh->dst_mac[2],ethh->dst_mac[3],ethh->dst_mac[4],ethh->dst_mac[5]);
}

void show_ip_header(struct iphdr* iph)
{
    unsigned short ttl = (iph->tot_len<<8)|(iph->tot_len>>8);
    unsigned short hc = (iph->check<<8)|(iph->check>>8);
    printf("IP:\n");
    printf("    Version: %d\n",iph->version);
    printf("    Header Length: %d bytes\n",4*iph->ihl);
    printf("    Total Length: %hu\n",ttl);
    printf("    Identification: 0x%.2x%.2x\n",iph->id&0xff,(iph->id>>8)&0xff);
    printf("    Fragment Offset: %hu\n",iph->frag_off);
    printf("    Time to live: %hu\n",iph->ttl);
    printf("    Protocol: ");
    switch(iph->protocol)
    {
        case 1:printf("ICMP(1)\n");break;
        case 2:printf("IGMP(2)\n");break;
        case 6:printf("TCP(6)\n");break;
        case 17:printf("UDP(17)\n");break;
        default:break;
    }
    printf("    Header checksum: 0x%.4hx\n",hc);
    printf("    Source IP: %d.%d.%d.%d\n",
            (iph->saddr)&0xff,
            (iph->saddr>>8)&0xff,
            (iph->saddr>>16)&0xff,
            (iph->saddr>>24)&0xff);
    printf("    Destination IP: %d.%d.%d.%d\n",
            (iph->daddr)&0xff,
            (iph->daddr>>8)&0xff,
            (iph->daddr>>16)&0xff,
            (iph->daddr>>24)&0xff);
}

void show_tcp_header(struct tcphdr* tcph)
{
    unsigned short sp = (tcph->source<<8)|(tcph->source>>8);
    unsigned short dp = (tcph->dest<<8)|(tcph->dest>>8);
    unsigned int seq = ((tcph->seq>>24)&0xff)|((tcph->seq>>8)&0xff00)|((tcph->seq<<8)&0xff0000)|((tcph->seq<<24)&0xff000000);
    unsigned int ack = ((tcph->ack_seq>>24)&0xff)|((tcph->ack_seq>>8)&0xff00)|((tcph->ack_seq<<8)&0xff0000)|((tcph->ack_seq<<24)&0xff000000);
    unsigned short ws=(tcph->window<<8)|(tcph->window>>8);
    unsigned short cs=(tcph->check<<8)|(tcph->check>>8);
    unsigned short up=(tcph->urg_ptr<<8)|(tcph->urg_ptr>>8);
    printf("TCP:\n");
    printf("    Source port: %hu\n",sp);
    printf("    Destination prot: %hu\n",dp);
    printf("    Sequence number: %u\n",seq);
    printf("    Acknowledgment number: %u\n",ack);
    //Flags
    printf("    Window size value: %hu\n",ws);
    printf("    Checksum: 0x%.4hx\n",cs);
    printf("    Urgent Pointer: %hu\n",up);
}

void show_icmp_header(struct icmphdr* icmph)
{
    unsigned short cs=(icmph->checksum<<8)|(icmph->checksum>>8);
    unsigned short id=(icmph->un.echo.id<<8)|(icmph->un.echo.id>>8);
    unsigned short seq=(icmph->un.echo.sequence<<8)|(icmph->un.echo.sequence>>8);
    printf("ICMP:\n");
    printf("    Type: %u\n",icmph->type);
    printf("    Code: %u\n",icmph->code);
    printf("    Checksum: 0x%.4x\n",cs);
    printf("    Identification: %u\n",id);
    printf("    Sequence number: %u\n",seq);
}

void show_udp_header(struct udphdr* udph)
{
    unsigned short sp = (udph->source<<8)|(udph->source>>8);
    unsigned short dp = (udph->dest<<8)|(udph->dest>>8);
    unsigned short len = (udph->len<<8)|(udph->len>>8);
    unsigned short cs=(udph->check<<8)|(udph->check>>8);
    printf("UDP:\n");
    printf("    Source port: %hu\n",sp);
    printf("    Destination prot: %hu\n",dp);
    printf("    Header Length: %hu\n",len);
    printf("    Checksum: 0x%.4x\n",cs);
}

void show_arp_header(struct arphdr* arph,unsigned char* buffer)
{
    printf("ARP:\n");
    unsigned short ht = (arph->ar_hrd<<8)|(arph->ar_hrd>>8);
    unsigned short pt = (arph->ar_pro<<8)|(arph->ar_pro>>8);
    unsigned short opc = (arph->ar_op<<8)|(arph->ar_op>>8);

    if(ht==1)
    {
        printf("Hardware type: Ethernet (1)\n");
    }
    else
    {
        printf("Hardware type: %hu\n",ht);
    }

    if(pt==0x0800)
    {
        printf("Protocol type: IP(0x0800)\n");
    }
    else
    {
        printf("Protocol type: %.4x\n",pt);
    }

    printf("Hardware size: %u\n",arph->ar_hln);
    printf("Protocol size: %u\n",arph->ar_pln);

    if(opc==1)
    {
        printf("Opcode: request(1)\n");
    }
    else
    {
        printf("Opcode: %hu\n",arph->ar_op);
    }

    printf("    Sender MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
        buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
    buffer+=6;

    printf("    Sender IP: %d.%d.%d.%d\n",
        buffer[0],buffer[1],buffer[2],buffer[3]);
    buffer+=4;

    printf("    Target MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
        buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
    buffer+=6;

    printf("    Target IP: %d.%d.%d.%d\n",
        buffer[0],buffer[1],buffer[2],buffer[3]);
    buffer+=4;

}

void show_igmp_header(struct igmphdr* igmph)
{
    unsigned short cs=(igmph->csum<<8)|(igmph->csum>>8);
    printf("IGMP:\n");
    printf("    Type: %u\n",igmph->type);
    printf("    Code: %u\n",igmph->code);
    printf("    Checksum: 0x%.4x\n",cs);
}