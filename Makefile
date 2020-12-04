include /usr/local/etc/PcapPlusPlus.mk

.PHONY: PcapInfo IntInfo

# All Target
PcapInfo:
	g++ $(PCAPPP_INCLUDES) -c -o pcap_info.o pcap_info.cc
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o PcapInfo pcap_info.o $(PCAPPP_LIBS)
	rm pcap_info.o

IntInfo:
	g++ $(PCAPPP_INCLUDES) -c -o int_info.o int_info.cc
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o IntInfo int_info.o $(PCAPPP_LIBS)
	rm int_info.o

# Clean Target
clean:
	rm main.o
	rm PcapInfo
	rm IntInfo