//打开适配器并捕获数据包。在这讲中，我们会编写一个程序，将每一个通过适配器的数据包打印出来。
#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "pcap.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*
//pcap_open 打开设备
//返回值：A pointer to a 'pcap_t' which can be used as a parameter to the following calls (pcap_compile() and so on) 或者 NULL
pcap_t* pcap_open 	( 	const char *  	source,
int  	snaplen,		//制定要捕获数据包中的哪些部分。本例中值定为65535，它比我们能遇到的最大的MTU还要大。因此，我们确信我们总能收到完整的数据包。
int  	flags,			//flag用来指示适配器是否要被设置成混杂模式。如果是，那么不管这个数据包是不是发给我的，都会去捕获。
int  	read_timeout,	//定读取数据的超时时间，以毫秒计
struct pcap_rmtauth *  	auth,
char *  	errbuf
)
*/


/*
packet_handler指向一个可以接收数据包的函数。 这个函数会在收到每个新的数据包并收到一个通用状态时被libpcap所调用
//数据包的首部一般有一些诸如时间戳，数据包长度的信息，还有包含了协议首部的实际数据。 注意：冗余校验码CRC不再支持，因为帧到达适配器，并经过校验确认以后，适配器就会将CRC删除，
//pcap_loop()函数是基于回调的原理来进行数据捕获，这是一种精妙的方法，并且在某些场合中，它是一种很好的选择。
int pcap_loop 	( 	pcap_t *  	p,
int  	cnt,
pcap_handler  	callback,
u_char *  	user
)
*/
int main(){
pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
    
    // 获取本机设备列表 
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    // 打印列表 
    for(d=alldevs; d; d=d->next){
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if(i==0){
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i){
        printf("\nInterface number out of range.\n");
        // 释放设备列表 
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // 跳转到选中的适配器 
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    // pcap_open 打开设备 
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 保证能捕获到不同数据链路层上的每个数据包的全部内容
							  PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              )) == NULL){
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        // 释放设备列表 
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);
    
    // 释放设备列表 
    pcap_freealldevs(alldevs);
    
    // 开始捕获 
	//Collect a group of packets， keeps reading packets until cnt packets are processed or an error occurs.

    pcap_loop(adhandle, 0, packet_handler, NULL);
    
    return 0;
}


// 每次捕获到数据包时，libpcap都会自动调用这个回调函数 , 打印捕获的包的信息
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    
    // 将时间戳转换成可识别的格式 
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len); 
}