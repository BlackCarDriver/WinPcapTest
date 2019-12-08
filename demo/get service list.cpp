#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"

int main(){
	pcap_if_t *alldevs;		//pcap_if_t is Item in a list of interfaces, used by pcap_findalldevs()
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE]; // PCAP_ERRBUF_SIZE �궨��:libpcap������Ϣ����Ĵ�С 

	//��ȡ���ػ����豸�б� 
	//Create a list of network devices that can be opened with pcap_open(). 
	//���ȣ� pcap_findalldevs_ex() ��������libpcap����һ������һ�� errbuf ������һ��������������������ᱻlibpcapд���ַ������͵Ĵ�����Ϣ��
	//�������еĲ���ϵͳ��֧��libpcap�ṩ���������ӿڣ���ˣ�����������дһ������ֲ��Ӧ�ó������Ǿͱ��뿼����ʲô����£� description �� null��
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	// ��ӡ�б� 
	for (d = alldevs; d != NULL; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	//������������豸�б��ʹ�ã�����Ҫ���� pcap_freealldevs() ��������ռ�õ��ڴ���Դ�ͷš� 
	pcap_freealldevs(alldevs);
	return 0;
}