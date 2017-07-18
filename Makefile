all: packet_analyzer

packet_analyzer:
	g++ -lpcap -o packet_analyzer pac.cpp -lpcap

clean:
	rm packet_analyzer
