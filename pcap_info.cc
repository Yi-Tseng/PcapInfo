#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <CRC.h>
#include "utils.h"


int main(int argc, char* argv[]) {
  bool printFlows = false;
  std::string pcapFile;

  if (argc < 2) {
    std::cout << "Input file name was not given" << std::endl;
    return 1;
  }

  if (std::strcmp(argv[1], "-v") == 0) {
    printFlows = true;
    pcapFile = argv[2];
  } else {
    pcapFile = argv[1];
  }

  // open a pcap file for reading
  pcpp::IFileReaderDevice* reader =
      pcpp::IFileReaderDevice::getReader(pcapFile.c_str());

  if (!reader->open()) {
    delete reader;
    std::cout << "Error opening input pcap file\n";
    return 1;
  }

  // print file summary
  std::cout << "File summary:" << std::endl;
  std::cout << "~~~~~~~~~~~~~" << std::endl;
  std::cout << "   File name: " << reader->getFileName() << std::endl;
  std::cout << "   File size: " << reader->getFileSize() << " bytes"
            << std::endl;

  pcpp::PcapFileReaderDevice* pcapReader =
      dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);

  if (pcapReader == nullptr) {
    std::cout << "Unknown file format";
  }

  pcpp::LinkLayerType linkLayer = pcapReader->getLinkLayerType();
  std::cout << "   Link layer type: ";
  if (linkLayer == pcpp::LINKTYPE_ETHERNET)
    std::cout << "Ethernet";
  else if (linkLayer == pcpp::LINKTYPE_LINUX_SLL)
    std::cout << "Linux cooked capture";
  else if (linkLayer == pcpp::LINKTYPE_NULL)
    std::cout << "Null/Loopback";
  else if (linkLayer == pcpp::LINKTYPE_RAW ||
           linkLayer == pcpp::LINKTYPE_DLT_RAW1 ||
           linkLayer == pcpp::LINKTYPE_DLT_RAW2) {
    std::cout << "Raw IP (" << linkLayer << ")";
  }
  uint32_t totalPkts = 0;
  uint32_t numIpv4 = 0;
  uint32_t numIpv6 = 0;
  uint32_t numOthers = 0;
  std::unordered_map<V4Tuple, uint32_t, V4TupleHasher> flows;
  std::unordered_set<uint32_t> flowHashes;
  pcpp::RawPacket rawPacket;
  while (pcapReader->getNextPacket(rawPacket)) {
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (ipv4Layer) {
      numIpv4++;
      uint32_t src = ipv4Layer->getSrcIpAddress().toInt();
      uint32_t dst = ipv4Layer->getDstIpAddress().toInt();
      uint8_t proto = ipv4Layer->getIPv4Header()->protocol;
      uint16_t l4Sport = 0;
      uint16_t l4Dport = 0;
      if (tcpLayer) {
        l4Sport = tcpLayer->getTcpHeader()->portSrc;
        l4Dport = tcpLayer->getTcpHeader()->portDst;
      } else if (udpLayer) {
        l4Sport = udpLayer->getUdpHeader()->portSrc;
        l4Dport = udpLayer->getUdpHeader()->portDst;
      }
      V4Tuple ftple = {src, dst, proto, l4Sport, l4Dport};
      uint32_t crc32 = CRC::Calculate(&ftple, sizeof(V4Tuple), CRC::CRC_32());
      flowHashes.insert(crc32);

      if (flows.find(ftple) == flows.end()) {
        flows[ftple] = 1;
      } else {
        flows[ftple]++;
      }

    } else if (ipv6Layer) {
      numIpv6++;
    } else {
      numOthers++;
    }
    totalPkts++;
  }

  std::cout << std::endl;
  std::cout << "Total IPv4: " << numIpv4 << " ("
            << (double)numIpv4 / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Total IPv6: " << numIpv6 << " ("
            << (double)numIpv6 / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Other types of packet: " << numOthers << " ("
            << (double)numOthers / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Total IPv4 5-tuples: " << flows.size() << std::endl;
  std::cout << "Total IPv4 5-tuple hashes: " << flowHashes.size() << std::endl;
  std::cout << "Total: " << totalPkts << std::endl;

  if (printFlows) {
    std::vector<std::pair<V4Tuple, uint32_t>> flowsInOrder;
    for (auto it = flows.begin(); it != flows.end(); ++it) {
      flowsInOrder.push_back(std::make_pair(it->first, it->second));
    }

    sort(flowsInOrder.begin(), flowsInOrder.end(), SortFlows);

    for (auto it = flowsInOrder.begin(); it != flowsInOrder.end(); ++it) {
      std::cout << it->first.ToString() << " : "
                << it->second << std::endl;
    }
  }

  reader->close();
  delete reader;
  return 0;
}