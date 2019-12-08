//从一个选定的接口捕获数据包，并且将它们保存到用户指定的文件中。

#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "package.h"

// 回调函数原型 
void save_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void read_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int savePackage();	//保存包到离线文件
int readPackage();	//从离线文件读取包


pcap_if_t *alldevs;
pcap_if_t *d;
pcap_dumper_t *dumpfile;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
const char* offlinePath = "D:\\TEMP\\package.pkg";
int count = 0, capNum =30;

//=============== TEST =====================
package pcaptool;

//==========================================

int main(int argc, char **argv){
	int inum;
	int i = 0;
	// 获取本机设备列表 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	// 跳转到选中的适配器 
	for (d = alldevs, i = 0; i< 3; d = d->next, i++);
	// 打开适配器 
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//==================== main function ===============

	//savePackage();		//捕抓capNum个数据包并保存到 offlinePath
	readPackage();			//从 offlinePath 读取全部数据包并处理

	//==================================================

	// 释放设备列表 
	pcap_freealldevs(alldevs);
	return 0;
}

//从离线文件读取数据包并处理
int readPackage(){
	pcap_t *fp;
	char source[PCAP_BUF_SIZE];

	// 根据新WinPcap语法创建一个源字符串
	if (pcap_createsrcstr(source, PCAP_SRC_FILE, NULL, NULL, offlinePath, errbuf) != 0){
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}
	// 打开捕获文件 
	if ((fp = pcap_open(source,  65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the file %s.\n", errbuf);
		return -1;
	}
	pcap_loop(fp, 0, read_handler, NULL);
	return 0;
}

//保存包到离线文件
int savePackage(){
	dumpfile = pcap_dump_open(adhandle, offlinePath);
	if (dumpfile == NULL){
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}
	pcap_loop(adhandle, 0, save_handler, (unsigned char *)dumpfile);
	return 0;
}

// 回调函数-保存数据包
void save_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	count++;
	if (count >= 30){
		exit(0);
	}
	printf(".");
	// 保存数据包到堆文件
	pcap_dump(dumpfile, header, pkt_data);
}

//回调函数，打印数据包信息
void read_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	pcaptool.PrintPackage(pkt_data);
}