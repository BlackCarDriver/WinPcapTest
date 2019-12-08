#pragma once
#define HAVE_REMOTE
#pragma warning(disable : 4996)

#include "pcap.h"
#ifdef inline
#undef inline 
#endif

#include<stdio.h>
#include<iostream>
#include<vector>
#include<string.h>
#include<string>
#define MAXLEN 65536	//max length of all packages
#define MAXNUM 30		//max numbers of capture packages
using namespace std;

typedef vector<string*> strVec;
const char *mydevice = "rpcap://\\Device\\NPF_{B9DE4B63-3B8E-48A6-BC5D-A8C911A8D2B0}";
int packageCount = 0;

bool getDevNameList(strVec* vec);
void myPackageHandler1(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void myPackageHandler2(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void myPackageHandler3(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

// 4字节的IP地址 
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

// IPv4 首部 
typedef struct ip_header{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

// UDP 首部
typedef struct udp_header{
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;


//printf binary of a type
template<typename Ty>
void printBin(Ty p, int start, int end){
	int ULen = 8 * sizeof(p);
	unsigned l = 1 << (ULen - 1);
	for (int i = 0; i<ULen; i++) {
		if (i >= start && i < end) {
			printf("%d", (p&l ? 1 : 0));
		}
		l >>= 1;
	}
	return;
}


int main(){
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((adhandle = pcap_open(mydevice, MAXLEN, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		printf("Unable to open the adapter. %s is not supported by WinPcap\n", mydevice);
		return -1;
	}
	//start capturing
	pcap_loop(adhandle, 0, myPackageHandler2, NULL);

	return 0;
}


//printf header of package
void myPackageHandler2(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	packageCount++;
	if (packageCount > MAXNUM) exit(0);

	//parse an print time 
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("< No:%d >============[ time: %s.%d ]==============( length: %d )=============== \n",packageCount, timestr, header->ts.tv_usec/1000, header->len);
	 
	//get the position of ip header
	ih = (ip_header *)(pkt_data + 14); //14 is the header length of Ethernet

	//get the position of UTP package
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	printf("version:     \t\t");
	printBin(ih->ver_ihl, 0, 4);
	printf("\n");
	
	printf("head len:    \t\t");
	printBin(ih->ver_ihl, 4, 8);
	printf("\n");
	
	printf("service type: \t\t");
	printBin(ih->tos, 0, 8);
	printf("\n");

	printf("total length: \t\t");
	printBin(ih->tlen, 0, 16);
	printf("\n");

	printf("identifi:     \t\t");
	printBin(ih->identification, 0, 16);
	printf("\n");

	printf("flags:        \t\t");
	printBin(ih->flags_fo, 0, 3);
	printf("\n");

	printf("offeset:       \t\t");
	printBin(ih->flags_fo, 4, 16);
	printf("\n");

	printf("time to live:  \t\t");
	printBin(ih->ttl, 0, 4);
	printf("\n");

	printf("proto:         \t\t");
	printBin(ih->proto, 0, 4);
	printf("\n");

	printf("checksum:      \t\t");
	printBin(ih->crc, 0, 16);
	printf("\n");

	printf("source adress  \t\t%d.%d.%d.%d:%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(uh->sport));
	printf("destin adress  \t\t%d.%d.%d.%d:%d\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(uh->dport));


	printf("\n\n\n");

	/*
	char tmp[40];	//版本4bit
	itoa(ih->ver_ihl, tmp, 2);
	printf("version and type: \t\t\t\t %08s\n", tmp);
	itoa(ih->tlen, tmp, 2);
	printf("total length:\t\t\t\t %016s\n", tmp);
	itoa(ih->flags_fo, tmp, 2);
	printf("flags and offset: \t\t\t\t %019s\n", tmp);
	itoa(ih->ttl, tmp, 2);
	printf("TTL: \t\t\t\t %08s\n", tmp);
	itoa(ih->identification, tmp, 2);
	printf("identification: \t\t\t\t %.016s\n", tmp);
	printf("\n\n");
	*/
}


//get all device in localhost and write all device name into vec
bool getDevNameList(strVec* vec){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	//get all device
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}

	int count = 0;
	//write all device name into vec
	for (d = alldevs; d; d = d->next){
		count++;
		if (d->name != ""){
			vec->push_back(new string(d->name));
		}
		cout << d->name << endl << d->description << endl;
	}
	pcap_freealldevs(alldevs);
	return true;
}

//printf package in format: time, time stamp in hander, length
void myPackageHandler1(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	packageCount++;
	if (packageCount > MAXNUM) exit(0);

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf(" %d : ==========[ %s ]==========< %.6d >===========( len:%d )=========\n", packageCount, timestr, header->ts.tv_usec, header->len);
	printf("%d\n", pkt_data);
}

//printf data of package
void myPackageHandler3(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	packageCount++;
	if (packageCount > MAXNUM) exit(0);

	int len = header->len;
	printf("%d ==========[len: %d ]=======\n", len);
	u_char *tmp = (u_char*)pkt_data;
	for (int i = 0; i < len; i++){
		printf("%c", tmp + i);
	}
	printf("\n");
	return;
}
