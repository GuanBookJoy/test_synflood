#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#define MaxLength 100

//链路层数据包格式 14字节
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}EthHeader;

//IP头 20字节
typedef struct {
    u_char ver_length;     //版本-头长
    u_char tos;          //服务
    u_short total_len;     //总长
    u_short id;            //标识
    u_short foff;        //分片
    u_char ttl;            //生存时间
    u_char proto;        //协议
    u_short checksum;    //校验和
    u_char sourceIP[4];    //源ip
    u_char destIP[4];    //目的ip
}IPHeader;

typedef struct {
    u_short      sport;
    u_short      dport;
    u_int        seq;
    u_int        ack;
    u_char       lenres;
    u_char       flag;
    u_short      win;
    u_short      sum;
    u_short      urp;
}TCPHeader;

//协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};

char file[1024]; //文件名
int len;
int count = 0;



//回调函数
void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    EthHeader *eth_header = (EthHeader*)pkt_data;
    printf("\n\n---------------开始分析---------------\n\n");
    printf("包大小: %d \n",header->len);
    
    
    printf("---------------分析帧头---------------\n\n");
    printf("目的Mac地址：%02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);
    printf("  源MAC地址：%02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
    
    
    printf("\n---------------分析IP头---------------\n\n");
    
    //解析数据包IP头部
    if(header->len < 14){
        return;
    }
    
    IPHeader *ip_header = (IPHeader*)(pkt_data + 14);
    
    printf("版本：%d\n", (ip_header->ver_length) >> 4);
    printf("头部长度：%d\n", (ip_header->ver_length) & 15);
    printf("总长：%d\n", ntohs(ip_header->total_len));
    printf("标志：%d\n", ntohs(ip_header->id));
    printf("生存时间：%d\n", ip_header->ttl);
    
    int length = ((ip_header->ver_length) & 15) * 4;
    printf("len = %d\n", length);
    
    //解析协议类型
    char strType[MaxLength];
    
    if(ip_header->proto > 7)
    {
        strcpy(strType,"未知协议");
    }
    else 
    {
        strcpy(strType,Proto[ip_header->proto]);
    }
    printf("协议：%s\n",strType);

    printf("  源IP地址：%d.%d.%d.%d\n",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
    printf("目的IP地址：%d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);

    printf("\n---------------分析传输层---------------\n\n");
    TCPHeader* tcp_header = (TCPHeader*)(pkt_data + 34);
    
    u_short srcPort = ntohs(tcp_header->sport);
    u_short desPort = ntohs(tcp_header->dport);
    u_int a = tcp_header->flag;
    u_char  syn = (a >> 1) & 1;
    
    
    printf("  源端口：%d\n", srcPort);
    printf("目的端口：%d\n", desPort);
    printf("     syn：%d\n", syn);

    if (count < 20) {
        // 写入文件
        printf("\n---------------写入文件---------------\n\n");
        file[len] = count + 97;
        count++;
        FILE *fp;
        if((fp = fopen(file,"w")) == NULL)
        {
            printf("写入文件失败\n");
            return;
        }
        fprintf(fp,"  源IP地址：%d.%d.%d.%d\n",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        fprintf(fp,"目的IP地址：%d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        fprintf(fp,"目的Mac地址：%02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);
        fprintf(fp,"  源MAC地址：%02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        fprintf(fp,"  源端口：%d\n", srcPort);
        fprintf(fp,"目的端口：%d\n", desPort);
        fprintf(fp,"     syn：%d\n", syn);
        fclose(fp);
    }
    
    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *device="eth33";//linux下的默认网卡
    char errbuf[1024];
    pcap_t *phandle;

    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    int datalink;
    
    //查找网络设备
    if((device=pcap_lookupdev(errbuf))==NULL){
        perror(errbuf);
        return 1;
    }
    else
        printf("设备: %s\n",device);
    //打开设备
    phandle=pcap_open_live(device,200,0,500,errbuf);

    if(phandle==NULL){
        perror(errbuf);
        return 1;
    }
    //获得网络设备的网络号和掩码
    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return 1;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("inet_ntop error");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("inet_ntop error");
     //   printf("IP地址：%s\n", ip);
    }

    // 过滤信息
    if(pcap_compile(phandle,&fcode,"ip",0,ipmask)==-1) {
        return 1;
    }

    printf("输入捕包文件名: ");
    scanf("%s",file);
    int i;
    for (i = 0; file[i] != '\0'; i++) {
    }
    file[i] = '_';
    file[i + 2] = '\0';
    len = i + 1;
    
    //设置网络过滤器
    if(pcap_setfilter(phandle,&fcode)==-1){
        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
        return 1;
    }
    
    //link
    if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return 1;
    }
    
    //循环补包
    pcap_loop(phandle,-1,callback,NULL);
    //关闭捕包程序
    pcap_close((pcap_t *) phandle);

    return 0;
}
