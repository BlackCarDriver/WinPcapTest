#pragma once
#define HAVE_REMOTE
#pragma warning(disable : 4996)

#include "pcap.h"
#include "package.h"
#ifdef inline
#undef inline 
#endif

using namespace std;




package::package(){
}


package::~package(){
}

void package::PrintPackage(const u_char *pkt_data){
	this->ethe = (Ethernet_pak*)pkt_data;
	printfEthe();
	
	if (!isIPV4()) return;
	this->ip = (IP_Pak*)(pkt_data + 14);
	printfIP();

	if (isTCP()){
		tcp = (TCP_Pak*)(pkt_data + 14 + (ip->vers_len & 0x0f) * 4);
		printfTCP();
	}
	else if(isUDP()){
		udp = (UDP_Pak*)(pkt_data + 14 + (ip->vers_len & 0x0f) * 4);
		printfUDP();
	}

	printf("\n\n");
	return;
}

//print the message of a ethenet package head
void package::printfEthe(){
	printf("=============== Ethernet II =======================\n");
	printf("Source Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", 
		ethe->Destination[0], ethe->Destination[1], ethe->Destination[2], 
		ethe->Destination[3],ethe->Destination[4], ethe->Destination[5]);

	printf("Destin Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", 
		ethe->Source[0], ethe->Source[1], ethe->Source[2], 
		ethe->Source[3], ethe->Source[4], ethe->Source[5] );
	
	printf("Type: 0x%.2x%.2x %s\n", ethe->Type[0], ethe->Type[1], (isIPV4() ? "IPV4": "Other"));
	return;
}

void package::printfIP(){
	printf("======== IPV4 ========\n");
	printf("Version:  %d \n", (ip->vers_len >> 4) & 0x0f);
	printf("Head length:  %d \n", ((ip->vers_len) & 0x0f)*4);
	printf("Type of service:  %.2x \n", ip->service_type);
	printf("Total length:  %d \n", binToInt(ip->total_len, 2));
	printf("Identification:  0x%.2x%.2x    %d\n", ip->identifi[0], ip->identifi[1], binToInt(ip->identifi, 2));
	printf("Flages and fragment offset:  ");
	printBin(&ip->flags_fo);
	printf("Time to live:  %d \n", ip->ttl);
	printf("Protocol:    %d \n", ip->protocol);
	printf("Header checksum:  ");
	printBin(&ip->crc);
	printf("Source IP:   %d.%d.%d.%d\n", ip->source_ip[0], ip->source_ip[1], ip->source_ip[2], ip->source_ip[3]);
	printf("Destination IP:   %d.%d.%d.%d\n", ip->destin_ip[0], ip->destin_ip[1], ip->destin_ip[2], ip->destin_ip[3]);
}

void package::printfTCP(){
	printf("======== TCP ========\n");
	printf("Source port:   %d \n", ntohs(tcp->source_por));
	printf("Destin port:   %d \n", ntohs(tcp->destin_port));
	printf("Sequence Number:   %d \n", tcp->sequenceNum);
	printf("AcknowledgeMent Number:   %d \n", tcp->acknowledgeMent);
	printf("Data offset:    %d\n", (tcp->len_pad_flag[0]>>4));
	printf("Flages:  %s \t %s \t %s \t %s \t %s \t %s \n",
		tcp->len_pad_flag[1] & 0x20 ? "URG" : "xxx",
		tcp->len_pad_flag[1] & 0x10 ? "ACK" : "xxx",
		tcp->len_pad_flag[1] & 0x08 ? "RESET" : "xxxxx",
		tcp->len_pad_flag[1] & 0x04 ? "PUSH" : "xxxx",
		tcp->len_pad_flag[1] & 0x02 ? "SYN" : "xxx",
		tcp->len_pad_flag[1] & 0x01 ? "FIN" : "xxx"
		);
	printf("Windows:   %d \n", ntohs(tcp->windows));
	printf("CheckSum:   %d \n", ntohs(tcp->checkSum));
	printf("Urgent Pointer:   %d \n", ntohs(tcp->urgent));
}

void package::printfUDP(){
	printf("======== UDP ========\n");
	printf("Source port:   %d \n", ntohs(udp->source_port));
	printf("Destin port:   %d \n", ntohs(udp->destin_port));
	printf("UDP length:   %d \n", ntohs(udp->length));
	printf("UDP checkSum:   %d \n", ntohs(udp->checkSum));
}

bool package::isIPV4(){
	if ((int)ethe->Type[0] == 0x08 && (int)ethe->Type[1] == 0x00){
		return true;
	}
	return false;
}

bool package::isUDP(){
	if ((int)ip->protocol == 17) return true;
	return false;
}

bool package::isTCP(){
	if ((int)ip->protocol == 6) return true;
	return false;
}

//get the decimal value of a binary string
int package::binToInt(u_char* bs, int len){
	int result = 0;
	int magnify = ((len - 1) * 8);
	for (int i = 0; i<len; i++){
		result += int(bs[i]) << magnify;
		magnify -= 8;
	}
	return result;
}

//printf the binary of a struct
template<typename Ty>
void printBin(Ty *p){
	int size = sizeof(Ty);
	char *byteArray = new char[size];
	memmove(byteArray, p, size);
	for (int i = 0; i<size; i++) {
		unsigned short mask = 1 << 7;
		for (int j = 0; j<8; j++) {
			printf("%d", mask & byteArray[i] ? 1 : 0);
			mask >>= 1;
		}
	}
	printf("\n");
}

