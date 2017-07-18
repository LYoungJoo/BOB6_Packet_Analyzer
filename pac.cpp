#include <iostream>
#include <cstdint>
#include <pcap.h>

using namespace std;

class PacketCapture{
	public:
		uint16_t my_ntohs(uint16_t val){
			uint16_t res;
			res = (((val) & 0xff) << 8) | ((val >> 8) & 0xff);
			return res;
		}
};

struct eth {
	u_int8_t destip[6];
	u_int8_t srcip[6];
	u_int16_t type;

	void printDestIP(eth *eth_header){
		cout << "Dest MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).destip[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}

	void printSrcIP(eth *eth_header){
		cout << "Src MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).srcip[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}
};


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bool chk;
	eth *eth_header;

	dev = pcap_lookupdev(errbuf);
	pcap_lookupnet(dev, &net, &mask, errbuf);
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	while(0 <= (chk = pcap_next_ex(handle, &header, &packet)))
	{
		if (chk == 0)
			continue;
		else {
			cout << "====== PACKET ======" << endl;
			cout << "1) ETH HEADER" << endl;
			eth_header = (eth *)packet;
			eth_header->printSrcIP(eth_header);
			eth_header->printDestIP(eth_header);
			if ( (*eth_header).type == 8 )
				cout << "2) IP HEADER" << endl;
					cout << "IP HEADER!!";

			cout << endl;
		}
	}
}
/*
   int main(){
   char packet[] = {0x00, 0x50};
//	uint16_t port = ntohs(*(uint16_t*)packet);
uint16_t port = my_ntohs(*(uint16_t*)packet);
cout << "prot = " << port  << endl;
return 0;
}
 */
