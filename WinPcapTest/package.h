#pragma once

#ifdef inline
#undef inline 
#endif


#include<string.h>
#include<string>
#include<iostream>
#include<vector>
#include <memory>
#include<tuple>
using namespace std;

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef vector<string> strVec;

#define ERR_READ_FAIL "explain binary data to struct fail"
#define ERR_ARGU	"unexpect argument"

//=============== tool function defination =================
namespace globalFunc{
	//字符串包数据处理
	int GetUcharsArray(string hexStream, vector<u_char> &result);

	//打印某数据的二进制表示
	template <typename Ty> void printBin(Ty*);

	//字节数组转整数
	int binToInt(u_char*, int);
}

//=============== some of the header struct ================
struct Ethernet_pak{
	u_char destination[6];
	u_char source[6];
	u_short etype;
	u_short crc[4];

	int initialize(const u_char*);
	//判断上层协议是否IPV4
	static bool isIPV4(const Ethernet_pak&);
	//判断上层协议是否ARP
	static bool isARP(const Ethernet_pak&);
	//打印数据包信息
	static void printPacket(const Ethernet_pak&);
	//获取上层协议名称
	static string getTypeName(const Ethernet_pak &);
};

struct IP_Pak {
	u_char vers_len;		//4 bits version and 4 bits length
	u_char service_type;	//services type
	u_char total_len[2];		//total length
	u_char identifi[2];		//identification
	u_short flags_fo;		//3 bits flags and 13 bits offset
	u_char ttl;		
	u_char protocol;
	u_short crc;
	u_char source_ip[4];
	u_char destin_ip[4];
	u_char *option;			//头部可选部分
	u_char *data;			//数据部分

	//根据字节数组初始化对象,返回头部长度和总长度
	tuple<int,int> initialize(const u_char* data);
	//判断上层协议是否TCP
	static bool isTCP(const IP_Pak &);
	//判断上层协议是否UDP
	static bool isUDP(const IP_Pak &);
	//打印数据报信息
	static void printPacket(const IP_Pak &);
	//获取上层协议名称
	static string getTypeName(const IP_Pak &);
};

struct TCP_Pak {
	u_short source_por;
	u_short destin_port;
	u_int  sequenceNum;
	u_int  acknowledgeMent;
	u_char len_pad_flag[2];		//4 bits headers length, 6 bits resever, 6 bits control
	u_short windows;
	u_short checkSum;
	u_short urgent;
	u_char *option;

	//根据字节数组构建对象，返回头部长度
	int initialize(const u_char*);
	//打印数据报信息
	static void printPacket(const TCP_Pak &);
};

struct UDP_Pak{
	u_short source_port;
	u_short destin_port;
	u_short length;
	u_short checkSum;

	//打印数据报信息
	static void printPacket(const UDP_Pak &);
};

struct ARP_Pak{
	u_short hardwareType;
	u_short protocolType;
	u_char hardwareSize;
	u_char protocolSize;
	u_short opcode;
	u_char senderMAC[6];
	u_char senderIP[4];
	u_char targetMAC[6];
	u_char targetIP[4];

	//打印数据报信息
	static void printPacket(const ARP_Pak &);
};

//============== mainly class =========================

class package{
	Ethernet_pak *ethe;
	IP_Pak *ip;
	TCP_Pak *tcp;
	UDP_Pak *udp;
	ARP_Pak *arp;

public:
	void PrintPackage(const u_char *pkt_data);

private:
	void printfEthe();
	void printfIP();
	void printfTCP();
	void printfUDP();
	void printfARP();
	bool isIPV4();
	bool isUDP();
	bool isTCP();
	bool isARP();
	
	string getTypeNameI();
	string getTypeNameII();

public:
	package();
	~package();
};


//============== some of the complete packet ==============


//基类：表示一个完整的数据包
class ComplatePacket {	
public:
	virtual void printPacket(){};
};


//一个完整的TCP数据包
class CP_TCP : public ComplatePacket{
public:
	unique_ptr<Ethernet_pak> ether_head;
	unique_ptr<IP_Pak> ip_head;
	unique_ptr<TCP_Pak> tcp_head;
	u_char *data = nullptr;

	void printPacket(){
		cout << "place holder \n";
		return;
	};

	~CP_TCP(){
		delete[]data;
	}
};


//生成一个完整的数据包对象
ComplatePacket* getCompletePacket(u_char *data);

