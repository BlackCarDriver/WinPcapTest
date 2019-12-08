#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"

int main(){
	pcap_if_t *alldevs;		//pcap_if_t is Item in a list of interfaces, used by pcap_findalldevs()
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE]; // PCAP_ERRBUF_SIZE 宏定义:libpcap错误信息缓存的大小 

	//获取本地机器设备列表 
	//Create a list of network devices that can be opened with pcap_open(). 
	//首先， pcap_findalldevs_ex() ，和其他libpcap函数一样，有一个 errbuf 参数。一旦发生错误，这个参数将会被libpcap写入字符串类型的错误信息。
	//不是所有的操作系统都支持libpcap提供的网络程序接口，因此，如果我们想编写一个可移植的应用程序，我们就必须考虑在什么情况下， description 是 null。
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	// 打印列表 
	for (d = alldevs; d != NULL; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	//当我们完成了设备列表的使用，我们要调用 pcap_freealldevs() 函数将其占用的内存资源释放。 
	pcap_freealldevs(alldevs);
	return 0;
}