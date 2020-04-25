#pragma once
#define HAVE_REMOTE
#pragma warning(disable : 4996)

#ifdef inline
#undef inline 
#endif

#include "pcap.h"
#include "package.h"
#include <algorithm>
#include <exception>
using namespace std;


//从字节数组中解析出一个完整的数据包对象
ComplatePacket* getCompletePacket(const u_char *data){
	ComplatePacket *making;
	int start = 0;
	try{
		unique_ptr<Ethernet_pak> Ethe(new Ethernet_pak);
		start += Ethe.get()->initialize(data);
		if (Ethernet_pak::getTypeName(*Ethe) == "IPV4"){	//Ethe->ipv4
			unique_ptr<IP_Pak> ipp(new IP_Pak);
			auto LenTuple = ipp.get()->initialize(data + start);
			start += get<0>(LenTuple);
			int IPtotalLen = get<1>(LenTuple);
			string method = IP_Pak::getTypeName(*ipp);

			if (method == "TCP"){	//Ethe->ipv4->TCP
				unique_ptr<TCP_Pak> tcp(new TCP_Pak);
				//读取TCP首部
				int tcpHeadLen = tcp.get()->initialize(data + start);
				start += tcpHeadLen;
				//获取TCP数据部分
				unique_ptr<u_char> tcpData(new u_char[IPtotalLen - tcpHeadLen + 1]);
				memcpy(tcpData.get(), data + start, IPtotalLen - tcpHeadLen);
				tcpData.get()[IPtotalLen - tcpHeadLen] = '\0';
				start += (IPtotalLen - tcpHeadLen);
				//读取以太帧尾部的CRC校验码
				memcpy(&Ethe.get()->crc, data + start, 4);
				//创建和组装完整的TCP报文
				CP_TCP *cpTcp = new CP_TCP;
				cpTcp->isValid = true;
				cpTcp->dataLen = IPtotalLen - tcpHeadLen + 1;
				cpTcp->ether_head = move(Ethe);
				cpTcp->ip_head = move(ipp);
				cpTcp->tcp_head = move(tcp);
				cpTcp->payLoad = move(tcpData);
				return cpTcp;
			}
			if (method == "UDP"){	//Ethe->ipv4->udp
				//读取UDP首部
				unique_ptr<UDP_Pak> udp(new UDP_Pak);
				int udpHeadLen = udp.get()->initialize(data + start);
				start += udpHeadLen;
				//读取UDP数据部分
				int payLoadLen = udp.get()->length - udpHeadLen;
				unique_ptr<u_char>tmpPayLoad;
				if (payLoadLen > 0){
					tmpPayLoad.reset(new u_char[payLoadLen+1]);
					memcpy(tmpPayLoad.get(), data, payLoadLen);
					tmpPayLoad.get()[payLoadLen] = '\0';
					start += payLoadLen;
				}
				//读取以太帧尾部的CRC校验码
				memcpy(&Ethe.get()->crc, data + start, 4);
				//组装完整的UDP数据包
				CP_UDP *cpUdp = new CP_UDP;
				cpUdp->dataLen = payLoadLen + 1;
				cpUdp->isValid = true;
				cpUdp->ether_head = move(Ethe);
				cpUdp->ip_head = move(ipp);
				cpUdp->udp_head = move(udp);
				cpUdp->payLoad = move(tmpPayLoad);
				return cpUdp;
			}
			return nullptr;
		}
	}
	catch (exception err){
		printf("exception catched by getCompletePacket: %s \n", err.what());
		return nullptr;
	}
	return nullptr;
}


//================== MAC ===================

int Ethernet_pak::initialize(const u_char* data){
	if (data == nullptr){
		throw exception(ERR_ARGU);
	}
	const int headLen = 14;
	memcpy(this, data, headLen);
	string upType = Ethernet_pak::getTypeName(*this);
	if (upType == "unknow"){
		throw exception(ERR_READ_FAIL);
	}
	if (upType == "IPV6"){
		throw exception(ERR_UNSUPPOSE);
	}
	return headLen;
}

void Ethernet_pak::printPacket(const Ethernet_pak &ethe){
	printf("=============== Ethernet II =======================\n");
	printf("Source Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		ethe.destination[0], ethe.destination[1], ethe.destination[2],
		ethe.destination[3], ethe.destination[4], ethe.destination[5]);

	printf("Destin Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		ethe.source[0], ethe.source[1], ethe.source[2],
		ethe.source[3], ethe.source[4], ethe.source[5]);

	u_short tmpVal = ntohs(ethe.etype);
	printf("Type: 0x%.2x%.2x  %s\n", (tmpVal >> 8) & 0x0f, tmpVal & 0x0f, getTypeName(ethe).c_str());

	printf("CRC:  %#08x\n", ethe.crc);
	return;
}

bool Ethernet_pak::isIPV4(const Ethernet_pak &ethe){
	u_short val = ntohs(ethe.etype);
	if (val == 0x0800){
		return true;
	}
	return false;
}

bool Ethernet_pak::isARP(const Ethernet_pak &ethe){
	u_short val = ntohs(ethe.etype);
	if (val == 0x0806){
		return true;
	}
	return false;
}

string Ethernet_pak::getTypeName(const Ethernet_pak &ethe){
	u_short val = ntohs(ethe.etype);
	if (val == 0x0800) return "IPV4";
	if (val == 0x0806) return "ARP";
	if (val == 0x86DD) return "IPv6";
	return "unknow";
}

//================== IP ===================

tuple<int,int> IP_Pak::initialize(const u_char* data){
	if (data == nullptr){
		throw exception(ERR_ARGU);
	}
	//处理固定部分长度
	const int minLen = 20;
	memcpy(this, data, minLen);
	int version = (this->vers_len >> 4) ;
	int headLen = (this->vers_len & 0x0f) * 4;
	int totalLen = globalFunc::binToInt(this->total_len, 2);
	if (version != 4 || headLen < 20 || totalLen < headLen){	//版本不是IPV4或首部长度小于20字节
		throw exception(ERR_READ_FAIL);
	}
	//处理可选部分长度
	if (headLen > minLen){
		this->option.reset(new u_char[headLen - minLen]);
		memcpy(this->option.get(), data + 20, headLen - minLen);
	}
	return make_tuple(headLen, totalLen);
}

void IP_Pak::printPacket(const IP_Pak &ipp){
	printf("======== IPV4 ========\n");
	printf("Version:  %d \n", (ipp.vers_len >> 4) & 0x0f);
	printf("Head length:  %d \n", ((ipp.vers_len) & 0x0f) * 4);
	printf("Type of service:  %.2x \n", ipp.service_type);
	printf("Total length:  %d \n", ipp.total_len[0] * 16 + ipp.total_len[1]);
	printf("Identification:  0x%.2x%.2x    %d\n", ipp.identifi[0], ipp.identifi[1], ipp.identifi[0] * 16 + ipp.identifi[1]);
	printf("Flages and fragment offset:  ");
	globalFunc::printBin(&ipp.flags_fo);
	printf("Time to live:  %d \n", ipp.ttl);
	printf("Protocol:    %d \n", ipp.protocol);
	printf("Header checksum:  ");
	globalFunc::printBin(&ipp.crc);
	printf("Source IP:   %d.%d.%d.%d\n", ipp.source_ip[0], ipp.source_ip[1], ipp.source_ip[2], ipp.source_ip[3]);
	printf("Destination IP:   %d.%d.%d.%d\n", ipp.destin_ip[0], ipp.destin_ip[1], ipp.destin_ip[2], ipp.destin_ip[3]);
}

bool IP_Pak::isUDP(const IP_Pak &ipp){
	if ((int)ipp.protocol == 17) return true;
	return false;
}

bool IP_Pak::isTCP(const IP_Pak &ipp){
	if ((int)ipp.protocol == 6) return true;
	return false;
}

string IP_Pak::getTypeName(const IP_Pak &ipp){
	u_int val = (int)ipp.protocol;
	if (val == 17) return "UDP";
	if (val == 6) return "TCP";
	if (val == 1) return "ICMP";
	return "unknow";
}

IP_Pak::IP_Pak(){}

IP_Pak::~IP_Pak(){
	u_char* dataP = option.release();
	if (dataP != nullptr){
		delete[] dataP;
	}
}

//================== TCP ===================

int TCP_Pak::initialize(const u_char* data){
	if (data==nullptr){
		throw exception(ERR_ARGU);
	}
	//处理首部固定部分
	const int minLen = 20;
	memcpy(this, data, minLen);
	int headLen = (this->len_pad_flag[0] & 0xf0) >> 2;	//左移4位再乘以4,即除以4
	if (headLen > 60 || headLen < minLen ){
		throw exception(ERR_READ_FAIL);
	}
	//处理首部可选部分
	if (headLen > minLen){
		this->option.reset(new u_char[headLen - minLen]);
		memcpy(this->option.get(), data + minLen, headLen-minLen);
	}
	return headLen;
}

void TCP_Pak::printPacket(const TCP_Pak &tcp){
	printf("======== TCP ========\n");
	printf("Source port:   %d \n", ntohs(tcp.source_por));
	printf("Destin port:   %d \n", ntohs(tcp.destin_port));
	printf("Sequence Number:   %u \n", globalFunc::binToInt(tcp.sequenceNum, 4));	//todo:....
	printf("AcknowledgeMent Number:   %u \n", globalFunc::binToInt(tcp.acknowledgeMent,4));
	printf("Data offset:    %d\n", (tcp.len_pad_flag[0] >> 4));
	printf("Flages:  %s \t %s \t %s \t %s \t %s \t %s \n",
		tcp.len_pad_flag[1] & 0x20 ? "URG" : "xxx",
		tcp.len_pad_flag[1] & 0x10 ? "ACK" : "xxx",
		tcp.len_pad_flag[1] & 0x08 ? "PUST" : "xxxx",
		tcp.len_pad_flag[1] & 0x04 ? "REST" : "xxxx",
		tcp.len_pad_flag[1] & 0x02 ? "SYN" : "xxx",
		tcp.len_pad_flag[1] & 0x01 ? "FIN" : "xxx"
		);
	printf("Windows:   %d \n", ntohs(tcp.windows));
	printf("CheckSum:   %d \n", ntohs(tcp.checkSum));
	printf("Urgent Pointer:   %d \n", ntohs(tcp.urgent));
}

TCP_Pak::TCP_Pak(){};

TCP_Pak::~TCP_Pak(){
	u_char* dataP = option.release();
	if (dataP != nullptr){
		delete[] dataP;
	}
}

//================== UDP ===================

int UDP_Pak::initialize(const u_char* data){
	if (data == nullptr){
		throw exception(ERR_ARGU);
	}
	const int headLen = 8;
	memcpy(this, data, headLen);
	if (length < headLen){
		throw exception(ERR_READ_FAIL);
	}
	return headLen;
}

void UDP_Pak::printPacket(const UDP_Pak &udp){
	printf("======== UDP ========\n");
	printf("Source port:   %d \n", ntohs(udp.source_port));
	printf("Destin port:   %d \n", ntohs(udp.destin_port));
	printf("UDP length:   %d \n", ntohs(udp.length));
	printf("UDP checkSum:   %d \n", ntohs(udp.checkSum));
}

UDP_Pak::UDP_Pak(){}

UDP_Pak::~UDP_Pak(){}

//================== ARP ===================

void ARP_Pak::printPacket(const ARP_Pak &arp){
	printf("======== ARP ========\n");
	u_short tmpVal = ntohs(arp.hardwareType);
	printf("HardWare type:   %u   %s\n", tmpVal, tmpVal == 1 ? "Ethernet" : "other");

	tmpVal = ntohs(arp.protocolType);
	printf("Protocol type:   0x%.2x%.2x\n", tmpVal >> 8, tmpVal & 0x0f);

	printf("HardWare size:   %d\n", arp.hardwareSize);
	printf("Protocol size:   %d\n", arp.protocolSize);

	tmpVal = ntohs(arp.opcode);
	printf("Protocol type:  %d    %s\n", tmpVal,
		(tmpVal == 1 ? "ARP-request" : (tmpVal == 2 ? "ARP-response" : (tmpVal == 3 ? "RARP-request" : "RARP-response"))));

	printf("Sender Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		arp.senderMAC[0], arp.senderMAC[1], arp.senderMAC[2],
		arp.senderMAC[3], arp.senderMAC[4], arp.senderMAC[5]);

	printf("Sender IP:   %d.%d.%d.%d\n", arp.senderIP[0], arp.senderIP[1], arp.senderIP[2], arp.senderIP[3]);

	printf("Target Mac address: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		arp.targetMAC[0], arp.targetMAC[1], arp.targetMAC[2],
		arp.targetMAC[3], arp.targetMAC[4], arp.targetMAC[5]);

	printf("Target IP:   %d.%d.%d.%d\n", arp.targetIP[0], arp.targetIP[1], arp.targetIP[2], arp.targetIP[3]);
	return;
}

//================== Ethe + IP + TCP ===================

void CP_TCP::printPacket(){
	if (!isValid){
		printf("Packet invalid...\n");
		return;
	}
	Ethernet_pak::printPacket(*ether_head.get());
	IP_Pak::printPacket(*ip_head.get());
	TCP_Pak::printPacket(*tcp_head.get());
	printf("======== PAYLOAD ========\n");
	printf("%s \n", payLoad.get());
	return;
}

CP_TCP::CP_TCP(){
	isValid = false;
	dataLen = 0;
}

CP_TCP::~CP_TCP(){
	u_char *dataP = payLoad.release();
	if (dataP != nullptr){
		delete[] dataP;
	}
}

//================== Ethe + IP + UDP ===================

void CP_UDP::printPacket(){
	if (!isValid){
		printf("Packet invalid...\n");
		return;
	}
	Ethernet_pak::printPacket(*ether_head.get());
	IP_Pak::printPacket(*ip_head.get());
	UDP_Pak::printPacket(*udp_head.get());

	return;
}

CP_UDP::CP_UDP(){
	isValid = false;
	dataLen = 0;
};

CP_UDP::~CP_UDP(){
	u_char *dataP = payLoad.release();
	if (dataP != nullptr){
		delete[] dataP;
	}
}


//========================== globle tools functions ====================

namespace globalFunc{

	//将字符串表示的16进制流解析到一个发送数组里面
	//格式实例：9cda3e10c0b114115dad23520800450001c115f2400
	int GetUcharsArray(string hexStream, vector<u_char> &result){
		result.clear();
		int i = 0;
		for (i = 0; i + 1 < hexStream.size(); i += 2){
			transform(hexStream.begin(), hexStream.end(), hexStream.begin(), ::tolower);
			int tmp = hexStream[i + 1] - (isdigit(hexStream[i + 1]) ? '0' : 'a' - 10);
			tmp += (hexStream[i] - (isdigit(hexStream[i]) ? '0' : 'a' - 10)) << 4;
			if (tmp<0 || tmp>UCHAR_MAX){
				printf("Unexpect thing happened! tmp=%d\n", tmp);
				return -1;
			}
			result.push_back(u_char(tmp));
		}
		if (i != hexStream.size()){
			printf("hexStream not legle, remain two 4 bit not used\n");
			return -1;
		}
		return 0;
	}

	//打印一个数据的二进制码数据
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

	//将用字节数组表示的二进制源码转换为整数
	template<typename T>
	u_int binToInt(const T *data, int len){
		u_char *bs = new u_char[len];
		memcpy(bs, data, len);
		int result = 0;
		for (int i = len - 1; i >= 0; i--){
			result += bs[i] << (len - i - 1) * 8;
		}
		delete[] bs;
		return result;
	}

	//释放数组回调函数
	template<typename T>
	void deleter(T* ary){
		delete[] ary;
	}
};

 