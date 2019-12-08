//��һ��ѡ���Ľӿڲ������ݰ������ҽ����Ǳ��浽�û�ָ�����ļ��С�

#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "package.h"

// �ص�����ԭ�� 
void save_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void read_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int savePackage();	//������������ļ�
int readPackage();	//�������ļ���ȡ��


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
	// ��ȡ�����豸�б� 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	// ��ת��ѡ�е������� 
	for (d = alldevs, i = 0; i< 3; d = d->next, i++);
	// �������� 
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//==================== main function ===============

	//savePackage();		//��ץcapNum�����ݰ������浽 offlinePath
	readPackage();			//�� offlinePath ��ȡȫ�����ݰ�������

	//==================================================

	// �ͷ��豸�б� 
	pcap_freealldevs(alldevs);
	return 0;
}

//�������ļ���ȡ���ݰ�������
int readPackage(){
	pcap_t *fp;
	char source[PCAP_BUF_SIZE];

	// ������WinPcap�﷨����һ��Դ�ַ���
	if (pcap_createsrcstr(source, PCAP_SRC_FILE, NULL, NULL, offlinePath, errbuf) != 0){
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}
	// �򿪲����ļ� 
	if ((fp = pcap_open(source,  65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the file %s.\n", errbuf);
		return -1;
	}
	pcap_loop(fp, 0, read_handler, NULL);
	return 0;
}

//������������ļ�
int savePackage(){
	dumpfile = pcap_dump_open(adhandle, offlinePath);
	if (dumpfile == NULL){
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}
	pcap_loop(adhandle, 0, save_handler, (unsigned char *)dumpfile);
	return 0;
}

// �ص�����-�������ݰ�
void save_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	count++;
	if (count >= 30){
		exit(0);
	}
	printf(".");
	// �������ݰ������ļ�
	pcap_dump(dumpfile, header, pkt_data);
}

//�ص���������ӡ���ݰ���Ϣ
void read_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	pcaptool.PrintPackage(pkt_data);
}