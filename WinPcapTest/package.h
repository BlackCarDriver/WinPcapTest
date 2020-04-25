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
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef vector<string> strVec;

#define ERR_READ_FAIL "explain binary data to struct fail"
#define ERR_ARGU	"unexpect argument"
#define ERR_UNSUPPOSE "unsupported features"

//=============== Э��ͷ�� =================

struct Ethernet_pak{
	u_char destination[6];
	u_char source[6];
	u_short etype;
	u_int crc;

	int initialize(const u_char*);
	//�ж��ϲ�Э���Ƿ�IPV4
	static bool isIPV4(const Ethernet_pak&);
	//�ж��ϲ�Э���Ƿ�ARP
	static bool isARP(const Ethernet_pak&);
	//��ӡ���ݰ���Ϣ
	static void printPacket(const Ethernet_pak&);
	//��ȡ�ϲ�Э������
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
	unique_ptr<u_char> option;	//ͷ����ѡ����

	//�����ֽ������ʼ������,����ͷ�����Ⱥ��ܳ���
	tuple<int,int> initialize(const u_char* data);
	//�ж��ϲ�Э���Ƿ�TCP
	static bool isTCP(const IP_Pak &);
	//�ж��ϲ�Э���Ƿ�UDP
	static bool isUDP(const IP_Pak &);
	//��ӡ���ݱ���Ϣ
	static void printPacket(const IP_Pak &);
	//��ȡ�ϲ�Э������
	static string getTypeName(const IP_Pak &);

	IP_Pak(const IP_Pak&) = delete;
	IP_Pak& operator = (const IP_Pak&) = delete;
	IP_Pak();
	~IP_Pak();
};

struct TCP_Pak {
	u_short source_por;
	u_short destin_port;
	u_char sequenceNum[4];
	u_char acknowledgeMent[4];
	u_char  len_pad_flag[2];		//4 bits headers length, 6 bits resever, 6 bits control
	u_short windows;
	u_short checkSum;
	u_short urgent;
	unique_ptr<u_char> option;

	//�����ֽ����鹹�����󣬷���ͷ������
	int initialize(const u_char*);
	//��ӡ���ݱ���Ϣ
	static void printPacket(const TCP_Pak &);

	TCP_Pak(const TCP_Pak&) = delete;
	TCP_Pak& operator = (const TCP_Pak&) = delete;
	TCP_Pak();
	~TCP_Pak();
};

struct UDP_Pak{
	u_short source_port;
	u_short destin_port;
	u_short length;
	u_short checkSum;

	//�����ֽ����鹹����󣬷��ر����ܳ���
	int initialize(const u_char* data);
	static void printPacket(const UDP_Pak &);

	UDP_Pak();
	~UDP_Pak();
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

	int initialize(const u_char* data);
	static void printPacket(const ARP_Pak &);

	ARP_Pak();
	~ARP_Pak();
};


//============== �������ݰ� ==============

//�������ݱ��Ļ���
class ComplatePacket {	
public:
	bool isValid;	//���ݱ��Ƿ�����
	int dataLen;	//���ݲ��ֳ���
	virtual void printPacket(){};
};

//һ��������TCP���ݰ�
class CP_TCP : public ComplatePacket{
public:
	unique_ptr<Ethernet_pak> ether_head;
	unique_ptr<IP_Pak> ip_head;
	unique_ptr<TCP_Pak> tcp_head;
	unique_ptr<u_char> payLoad;

	void printPacket();
	CP_TCP(const CP_TCP&) = delete;
	CP_TCP& operator = (const CP_TCP&) = delete;
	CP_TCP();
	~CP_TCP();
};

//һ��������UDP���ݱ�
class CP_UDP : public ComplatePacket{
public:
	unique_ptr<Ethernet_pak> ether_head;
	unique_ptr<IP_Pak> ip_head;
	unique_ptr<UDP_Pak> udp_head;
	unique_ptr<u_char> payLoad;

	CP_UDP(const CP_UDP&) = delete;
	CP_UDP& operator = (const CP_UDP&) = delete;

	void printPacket();
	CP_UDP();
	~CP_UDP();
};

//һ��������ARP���ݰ�
class CP_ARP :public ComplatePacket {
public:
	unique_ptr<Ethernet_pak> ether_head;
	unique_ptr<ARP_Pak> arp_head;

	CP_ARP(const CP_ARP&) = delete;
	CP_ARP& operator = (const CP_ARP&) = delete;

	void printPacket();
	CP_ARP();
	~CP_ARP();
};

//����һ�����������ݰ�����
ComplatePacket* getCompletePacket(const u_char *data);

namespace globalFunc{
	//�ַ��������ݴ���
	int GetUcharsArray(string hexStream, vector<u_char> &result);

	//��ӡĳ���ݵĶ����Ʊ�ʾ
	template <typename Ty> void printBin(Ty*);

	//�ֽ�����ת����
	template<typename T> u_int binToInt(const T*, int);

	//�ͷ�����ص�����
	template<typename T> void deleter(T* ary);
}