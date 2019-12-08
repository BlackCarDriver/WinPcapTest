//下面的代码展示了发送一个数据包的最简单的方式。打开适配器以后，调用 pcap_sendpacket() 来发送手工制作的数据包。
//pcap_sendpacket() 的参数有一个要包涵发送数据的缓冲区，缓冲的长度，以及用来发送数据的适配器。注意，缓冲数据将直接发送到网络，
//而不会进行任何加工和处理。这就意味着应用程序需要创建一个正确的协议首部，来使这个数据包更有意义。

#define HAVE_REMOTE
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>


int main(int argc, char **argv){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	int i;

	// 检查命令行参数的合法性 
	if (argc != 2){
		printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
		return 1;
	}

	// 打开输出设备 
	if ((fp = pcap_open(argv[1],            // 设备名
		100,                // 要捕获的部分 (只捕获前100个字节)
		PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
		1000,               // 读超时时间
		NULL,               // 远程机器验证
		errbuf              // 错误缓冲
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 1;
	}

	// 假设在以太网上，设置MAC的目的地址为 1:1:1:1:1:1 
	packet[0] = 1;
	packet[1] = 1;
	packet[2] = 1;
	packet[3] = 1;
	packet[4] = 1;
	packet[5] = 1;

	// 设置MAC源地址为 2:2:2:2:2:2 
	packet[6] = 2;
	packet[7] = 2;
	packet[8] = 2;
	packet[9] = 2;
	packet[10] = 2;
	packet[11] = 2;

	// 填充剩下的内容 
	for (i = 12; i<100; i++){
		packet[i] = i % 256;
	}

	// 发送数据包 
	if (pcap_sendpacket(fp, packet, 100 ) != 0){
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
		return -1;
	}

	return 0;
}