#pragma once

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

struct Ethernet_pak{
	u_char Destination[6];
	u_char Source[6];
	u_char Type[2];
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
};

struct UDP_Pak{
	u_short source_port;
	u_short destin_port;
	u_short length;
	u_short checkSum;
};

class package{
	Ethernet_pak *ethe;
	IP_Pak *ip;
	TCP_Pak *tcp;
	UDP_Pak *udp;

public:
	void PrintPackage(const u_char *pkt_data);
	
private:
	void printfEthe();
	void printfIP();
	void printfTCP();
	void printfUDP();
	bool isIPV4();
	bool isUDP();
	bool isTCP();
	int binToInt(u_char*, int);

	template <typename Ty>
	friend void printBin(Ty*);

public:
	package();
	~package();
};
