#include <iostream>
#include <cstdint>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h> // #include <net/ip.h> for linux

using namespace std;

struct eth {
	u_int8_t srcmac[6];
	u_int8_t destmac[6];
	u_int16_t type;

	void printSrcMAC(eth *eth_header){
		cout << "Src MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).srcmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}

	void printDestMAC(eth *eth_header){
		cout << "Dest MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).destmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}
};

struct ip_s {
	u_int8_t header_len : 4;
	u_int8_t version : 4;
	u_int8_t servicetype;
	u_int16_t totallen;
	u_int16_t identification;
	u_int16_t fragmentoff;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t headerchksum;
	u_int8_t srcip[4];
	u_int8_t destip[4];

	void printSrcIP(ip_s *ip_header){
		cout << "Src IP - ";
		for(int i = 0; i < 4; ++i) {
			printf("%d", (int *)((*ip_header).srcip[i]));
			if ( i != 3)
				printf(".");
		}
		cout << endl;
	}

	void printDestIP(ip_s *ip_header){
		cout << "Dest IP - ";
		for(int i = 0; i < 4; ++i) {
			printf("%d", (int *)((*ip_header).destip[i]));
			if ( i != 3)
				printf(".");
		}
		cout << endl;
	}
};	

struct tcp {
	u_int16_t srcport;
	u_int16_t destport;
	u_int32_t seqnum;
	u_int32_t acknum;
	u_int8_t reserved :4;
	u_int8_t header_len :4;
	u_int8_t tcpflag;
	u_int16_t window;
	u_int16_t checksum;
	u_int16_t uregntpoint;
	u_int32_t tcp_option;

	uint16_t my_ntohs(u_int16_t val){
		uint16_t res;
		res = (((val) & 0xff) << 8) | ((val >> 8) & 0xff);
		return res;
	}

	void printSrcPort(tcp *tcp_header){
		cout << "Src port - ";
		printf("%d",my_ntohs(((*tcp_header).srcport)));
		cout << endl;
	}

	void printDestPort(tcp *tcp_header){
		cout << "Dest port - ";
		printf("%d",my_ntohs(((*tcp_header).destport)));
		cout << endl;
	}
};

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "port 80";	/* The filter expression */
	char filter_exp[0];
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bool chk;
	eth *eth_header;
	ip_s *ip_header;
	tcp *tcp_header;
	char *data;

	if( argc < 2 ){ 
		dev = pcap_lookupdev(errbuf);
		pcap_lookupnet(dev, &net, &mask, errbuf);
	}
	else {
		dev = argv[1]; 
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	while(0 <= (chk = pcap_next_ex(handle, &header, &packet)))
	{
		if (chk == 0)
			continue;
		else {
			cout << "======================== PACKET ========================" << endl;
			cout << "1) ETH HEADER" << endl;
			eth_header = (eth *)packet;
			eth_header->printSrcMAC(eth_header);
			eth_header->printDestMAC(eth_header);

			if ((*eth_header).type == ntohs(ETHERTYPE_IP)) {
				cout << "2) IP HEADER" << endl;
				ip_header = (ip_s*)(packet+14);
				ip_header->printSrcIP(ip_header);
				ip_header->printDestIP(ip_header);

				if ((*ip_header).protocol == IPPROTO_TCP) {
					cout << "3) TCP HEADER" << endl; 
					tcp_header = (tcp*)(packet+14 + (((*ip_header).header_len) * 4));
					tcp_header->printSrcPort(tcp_header);
					tcp_header->printDestPort(tcp_header);
	
					cout << "4) DATA" << endl;
					data = (char *)(packet + 14 + (((*ip_header).header_len) * 4) \
						 + (((*tcp_header).header_len) * 4));
					cout << "Data Length - "; 
					printf("%d\n", ntohs((*ip_header).totallen)) \
						- (((*ip_header).header_len) * 4) \
						- (((*tcp_header).header_len) * 4) ;
					cout << data << endl << endl;
				}
			}
		}
	}
}
