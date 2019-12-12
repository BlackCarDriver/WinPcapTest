#pragma once
#define HAVE_REMOTE
#pragma warning(disable : 4996)
#ifdef inline
#undef inline 
#endif

#include "pcap.h"
#include "package.h"
using namespace std;

package::package(){}

package::~package(){}

//PrintPackage is the mainly funciton to handle the package
void package::PrintPackage(const u_char *pkt_data){
	this->ethe = (Ethernet_pak*)pkt_data;
	printfEthe();
	
	string protocolI = getTypeNameI();

	if (protocolI == "IPv4"){

		this->ip = (IP_Pak*)(pkt_data + 14);
		printfIP();

		string protocolAII = getTypeNameII();
		if (protocolAII == "TCP"){
			tcp = (TCP_Pak*)(pkt_data + 14 + (ip->vers_len & 0x0f) * 4);
			printfTCP();
		}
		else if (protocolAII == "UDP"){
			udp = (UDP_Pak*)(pkt_data + 14 + (ip->vers_len & 0x0f) * 4);
			printfUDP();
		}
	}
	else if (protocolI == "ARP"){
		this->arp = (ARP_Pak*)(pkt_data + 14);
		printfARP();
	}
	printf("\n\n");

	return;
}


//======================== private tools function ==================

//print the message of a ethenet package head
void package::printfEthe(){
	printf("=============== Ethernet II =======================\n");
	printf("Source Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", 
		ethe->destination[0], ethe->destination[1], ethe->destination[2],
		ethe->destination[3], ethe->destination[4], ethe->destination[5]);

	printf("Destin Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", 
		ethe->source[0], ethe->source[1], ethe->source[2],
		ethe->source[3], ethe->source[4], ethe->source[5]);
	
	u_short tmpVal = ntohs(ethe->etype);
	printf("Type: 0x%.2x%.2x  %s\n", (tmpVal >> 8) & 0x0f, tmpVal & 0x0f, getTypeNameI().c_str());
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

void package::printfARP(){
	printf("======== ARP ========\n");
	u_short tmpVal = ntohs(arp->hardwareType);
	printf("HardWare type:   %u   %s\n", tmpVal, tmpVal == 1 ? "Ethernet" : "other");

	tmpVal = ntohs(arp->protocolType);
	printf("Protocol type:   0x%.2x%.2x\n", tmpVal >> 8, tmpVal & 0x0f);

	printf("HardWare size:   %d\n", arp->hardwareSize);
	printf("Protocol size:   %d\n", arp->protocolSize);

	tmpVal = ntohs(arp->opcode);
	printf("Protocol type:  %d    %s\n", tmpVal,
		(tmpVal==1?"ARP-request":(tmpVal==2?"ARP-response":(tmpVal==3?"RARP-request":"RARP-response"))));

	printf("Sender Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		arp->senderMAC[0], arp->senderMAC[1], arp->senderMAC[2],
		arp->senderMAC[3], arp->senderMAC[4], arp->senderMAC[5]);

	printf("Sender IP:   %d.%d.%d.%d\n", arp->senderIP[0], arp->senderIP[1], arp->senderIP[2], arp->senderIP[3]);

	printf("Target Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		arp->targetMAC[0], arp->targetMAC[1], arp->targetMAC[2],
		arp->targetMAC[3], arp->targetMAC[4], arp->targetMAC[5]);

	printf("Target IP:   %d.%d.%d.%d\n", arp->targetIP[0], arp->targetIP[1], arp->targetIP[2], arp->targetIP[3]);
	return;
}

//======================== small tools function =====================

//get the protocol type name of level one
string package::getTypeNameI(){
	u_short val = ntohs(ethe->etype);
	if (val == 0x0800) return "IPv4";
	if (val == 0x0806) return "ARP";
	if (val == 0x86DD) return "IPv6";
	return "unknow";
}

//get the protocol type name of level one
string package::getTypeNameII(){
	u_int val = (int)ip->protocol;
	if (val == 17) return "UDP";
	if (val == 6) return "TCP";
	if (val == 1) return "ICMP";
	return "unknow";
}

bool package::isIPV4(){
	u_short val = ntohs(ethe->etype);
	if (val == 0x0800){
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

bool package::isARP(){
	u_short val = ntohs(ethe->etype);
	if (val == 0x0806){
		return true;
	}
	return false;
}

//=========================== friend functions ======================

//get the decimal value of a binary string
int binToInt(u_char* bs, int len){
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


//========================== testting functions ====================
void package::CreatePackage(u_char *p, string data){
	
	return;
}