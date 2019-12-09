#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "package.h"

#define DEFAULT_DEV_INDX 4	//default devices index

package pcaptool;
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_dumper_t *dumpfile;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
//const char* offlinePath = "D:\\WorkPlace\\C++WorkPlace\\WinPcapTest\\offlinePackage\\package.pkg";
const char* offlinePath = "D:\\WorkPlace\\C++WorkPlace\\WinPcapTest\\offlinePackage\\Arpx3.pcapng";
int packCount = 0;
int capNum = 10000;		//dealine of packCount


void save_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void read_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int savePackage();	//save package to offline file
int readPackage();	//read package from offline file
int catchPackage();		//capture package and handle it 



int main(int argc, char **argv){
	int inum;
	int i = 0;
	// get devices list
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	// find the specified adapter
	for (d = alldevs, i = 0; i< DEFAULT_DEV_INDX -1 ; d = d->next, i++);
	// open the selected adapter 
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//==================== main function ===============

	catchPackage();
	//savePackage();		
	//readPackage();			

	//==================================================

	pcap_freealldevs(alldevs);
	return 0;
}


//capture pcakge by calling pcap_next_ex();
int catchPackage(){
	int res;
	const u_char *pkt_data;
	struct pcap_pkthdr *header;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
		if (res == 0)	continue;		//time out
		if (packCount++ > capNum) break;	//limit the package numbers;
		printf("No: %d\n", packCount);
		pcaptool.PrintPackage(pkt_data);
	}
	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}

//read package from offline file
int readPackage(){
	pcap_t *fp;
	char source[PCAP_BUF_SIZE];

	// create a source string
	if (pcap_createsrcstr(source, PCAP_SRC_FILE, NULL, NULL, offlinePath, errbuf) != 0){
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}
	// open and read offline package file
	if ((fp = pcap_open(source,  65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf )) == NULL){
		fprintf(stderr, "\nUnable to open the file %s.\n", errbuf);
		return -1;
	}
	pcap_loop(fp, 0, read_handler, NULL);
	return 0;
}

//save pacakge to offlie file
int savePackage(){
	dumpfile = pcap_dump_open(adhandle, offlinePath);
	if (dumpfile == NULL){
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}
	pcap_loop(adhandle, 0, save_handler, (unsigned char *)dumpfile);
	return 0;
}

//called by pcap_loop in savePackage
void save_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	packCount++;
	if (packCount >= capNum){
		exit(0);
	}
	printf(".");
	// save to heap file
	pcap_dump(dumpfile, header, pkt_data);
}

//printf he message of header, called by pcap_loop in readPackage
void read_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data){
	pcaptool.PrintPackage(pkt_data);
}