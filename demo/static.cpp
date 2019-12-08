//WinPcap的另一个高级特性：收集并统计网络流量。统计引擎利用了内核级的数据包过滤器，来有效地为收集到的数据包进行分类。
//打开一个适配器，并且，可以使用 pcap_setmode() 将它设置为统计模式(statistical mode)。
// 在启动统计模式前，用户需要设置一个过滤器，以定义要监听的数据流。详细内容请参考 过滤表达式语法 。如果没有设置过滤器，那么，所有的数据流量都将会被监听过程


#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

void usage();

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);


void main(int argc, char **argv){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct timeval st_ts;
	u_int netmask;
	struct bpf_program fcode;

	// 检查命令行参数的合法性 
	if (argc != 2){
		usage();
		return;
	}

	// 打开输出适配器 
	if ((fp = pcap_open(argv[1], 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open adapter %s.\n", errbuf);
		return;
	}

	//不用关心掩码，在这个过滤器中，它不会被使用
	netmask = 0xffffff;

	// 编译过滤器
	if (pcap_compile(fp, &fcode, "tcp", 1, netmask) <0){
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		//释放设备列表 
		return;
	}

	//设置过滤器
	if (pcap_setfilter(fp, &fcode)<0){
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_close(fp);
		// 释放设备列表 
		return;
	}

	//将接口设置为统计模式
	if (pcap_setmode(fp, MODE_STAT)<0){
		fprintf(stderr, "\nError setting the mode.\n");
		pcap_close(fp);
		//释放设备列表 
		return;
	}

	printf("TCP traffic summary:\n");

	// 开始主循环 
	pcap_loop(fp, 0, dispatcher_handler, (PUCHAR)&st_ts);

	pcap_close(fp);
	return;
}

void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data){
	struct timeval *old_ts = (struct timeval *)state;
	u_int delay;
	LARGE_INTEGER Bps, Pps;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	// 以毫秒计算上一次采样的延迟时间
	// 这个值通过采样到的时间戳获得 
	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	// 获取每秒的比特数b/s
	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
	/*                                            ^      ^
	|      |
	|      |
	|      |
	将字节转换成比特 --   |
	|
	延时是以毫秒表示的 --
	*/

	//得到每秒的数据包数量 
	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

	//将时间戳转化为可识别的格式 
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//打印时间戳
	printf("%s ", timestr);

	// 打印采样结果 
	printf("BPS=%I64u ", Bps.QuadPart);
	printf("PPS=%I64u\n", Pps.QuadPart);

	//存储当前的时间戳
	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
}


void usage(){
	printf("\nShows the TCP traffic load, in bits per second and packets per second.\nCopyright (C) 2002 Loris Degioanni.\n");
	printf("\nUsage:\n");
	printf("\t tcptop adapter\n");
	printf("\t You can use \"WinDump -D\" if you don't know the name of your adapters.\n");

	exit(0);
}