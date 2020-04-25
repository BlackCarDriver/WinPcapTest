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
	//�ַ��������ݴ���
	int GetUcharsArray(string hexStream, vector<u_char> &result);

	//��ӡĳ���ݵĶ����Ʊ�ʾ
	template <typename Ty> void printBin(Ty*);

	//�ֽ�����ת����
	int binToInt(u_char*, int);
}

//=============== some of the header struct ================
struct Ethernet_pak{
	u_char destination[6];
	u_char source[6];
	u_short etype;
	u_short crc[4];

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
	u_char *option;			//ͷ����ѡ����
	u_char *data;			//���ݲ���

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

	//�����ֽ����鹹�����󣬷���ͷ������
	int initialize(const u_char*);
	//��ӡ���ݱ���Ϣ
	static void printPacket(const TCP_Pak &);
};

struct UDP_Pak{
	u_short source_port;
	u_short destin_port;
	u_short length;
	u_short checkSum;

	//��ӡ���ݱ���Ϣ
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

	//��ӡ���ݱ���Ϣ
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


//���ࣺ��ʾһ�����������ݰ�
class ComplatePacket {	
public:
	virtual void printPacket(){};
};


//һ��������TCP���ݰ�
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


//����һ�����������ݰ�����
ComplatePacket* getCompletePacket(u_char *data);

