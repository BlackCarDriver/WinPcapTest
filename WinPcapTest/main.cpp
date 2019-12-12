
#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "package.h"
#include "mockPackage.h"

#define DEFAULT_DEV_INDX 4	//default devices index

package pcaptool;
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_dumper_t *dumpfile;
pcap_t *adhandle;				//adapter handler
char errbuf[PCAP_ERRBUF_SIZE];

int packCount = 0;
int capNum = 1000000;		//dealine of packCount
//const char* offlinePath = "D:\\WorkPlace\\C++WorkPlace\\WinPcapTest\\offlinePackage\\package.pkg";
const char* offlinePath = "D:\\WorkPlace\\C++WorkPlace\\WinPcapTest\\offlinePackage\\Arpx3.pcapng";

void save_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void read_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data);
void splitToVec(string &s, strVec &sv, char* delim);
int savePackage();	//save package to offline file
int readPackage();	//read package from offline file
int catchPackage();		//capture package and handle it 
int captureAndStatic();
int sendPack();

int main(int argc, char **argv){
	int inum;
	int i = 0;
	// get devices list
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	//printf the device
	for (d = alldevs, i = 0; d->next != NULL; d = d->next, i++){
		printf("No.%d ===> %s \n", i, d->name);
		printf("%s \n\n", d->description);
	}

	// find the specified adapter
	for (d = alldevs, i = 0; i< DEFAULT_DEV_INDX - 1; d = d->next, i++);
	// open the selected adapter 
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	//==================== main function ===============

	int res;
	res = sendPack();
	//res = captureAndStatic();
	//res = catchPackage();
	//res = savePackage();		
	//res = readPackage();			
	printf("Return result : %d\n", res);

	//==================================================
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);
	return 0;
}

int sendPack(){
	u_char pack[65536];
	int sendTimes = 100000;

	//select a package and 
	strVec tmpVec;
	splitToVec(ATCK_ARP2, tmpVec, " ");
	int size = tmpVec.size();
	//press the package into a char array
	for (int i = 0; i < tmpVec.size(); i++){
		sscanf(tmpVec[i].c_str(), "%x", &pack[i]);
	}
	//send package
	for (int i = 1; i <= sendTimes; i++){
		if (pcap_sendpacket(adhandle, pack, size) != 0){
			fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
			return -1;
		}
		if (i % 10 == 0) Sleep(300);
		printf("No.%d SendPackage success!\n", i);
	}
	return 0;
}

//capture and static 
int captureAndStatic(){
	u_int netmask = 0xffffff;
	struct bpf_program fcode; 
	struct timeval st_ts;
	// compile the filter
	if (pcap_compile(adhandle, &fcode, "tcp", 1, netmask) <0){
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	//set up the filter
	if (pcap_setfilter(adhandle, &fcode)<0){
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}

	//set interface as static model
	if (pcap_setmode(adhandle, MODE_STAT)<0){
		fprintf(stderr, "\nError setting the mode.\n");
		pcap_close(adhandle);
		return -1;
	}

	printf("TCP traffic summary:\n");
	pcap_loop(adhandle, 0, dispatcher_handler, (PUCHAR)&st_ts);
	pcap_close(adhandle);
	return 0;
}

//capture pcakge by calling pcap_next_ex and handle that by PrintPackage;
int catchPackage(){
	int res;
	const u_char *pkt_data;
	struct pcap_pkthdr *header;
	packCount = 0;
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
	if ((fp = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open the file %s.\n", errbuf);
		return -1;
	}
	pcap_loop(fp, 0, read_handler, NULL);
	return 0;
}

//capture and save pacakge to offlie file specified by $offlinePath
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

//display static data
void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data){
	struct timeval *old_ts = (struct timeval *)state;
	u_int delay;
	LARGE_INTEGER Bps, Pps;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	// calculated the delay time of the last sample in milliseconds
	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	// Gets the number of bits per second (b/s)
	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));

	//get the number of packets per second
	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

	//Convert the timestamp to a humanread format
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("%s \t\t BPS=%I64u \t\t PPS=%I64u\n", timestr, Bps.QuadPart,  Pps.QuadPart);

	//save current timestamp
	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
	return;
}


//===================== tools functions =====================\

//split a string by delim to a vector
void splitToVec(string &s, strVec &sv, char* delim) {
	sv.clear();
	char* buffer = new char[s.size() + 1];
	buffer[s.size()] = '\0';
	copy(s.begin(), s.end(), buffer);
	char* p = strtok(buffer, delim);
	do {
		sv.push_back(p);
	} while ((p = strtok(NULL, delim)));
	delete[] buffer;
	return;
}
