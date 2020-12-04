#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#include <iostream>
#include <unordered_set>

#include "CRC.h"

struct V4Tuple {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t proto;
  uint16_t l4Sport;
  uint16_t l4Dport;
  bool operator==(V4Tuple const& other) const {
    return srcIp == other.srcIp && dstIp == other.dstIp &&
           proto == other.proto && l4Sport == other.l4Sport &&
           l4Dport == other.l4Dport;
  }
};

struct V4TupleHasher {
  std::size_t operator()(V4Tuple const& v4tuple) const noexcept {
    return CRC::Calculate(&v4tuple, sizeof(V4Tuple), CRC::CRC_32());
  }
};

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Input file name was not given";
    return 1;
  }

  // open a pcap file for reading
  pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(argv[1]);

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
  unsigned long totalPkts = 0;
  unsigned long numIpv4 = 0;
  unsigned long numIpv6 = 0;
  unsigned long numOthers = 0;
  std::unordered_set<V4Tuple, V4TupleHasher> flowCount;
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
      flowCount.insert(ftple);
    } else if (ipv6Layer) {
      numIpv6++;
    } else {
      numOthers++;
    }
    totalPkts++;

    if (totalPkts % 100000 == 0) {
      std::cout << "\r" << totalPkts;
    }
  }

  std::cout << std::endl;
  std::cout << "Total IPv4: " << numIpv4 << " ("
            << (double)numIpv4 / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Total IPv6: " << numIpv6 << " ("
            << (double)numIpv6 / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Other types of packet: " << numOthers << " ("
            << (double)numOthers / totalPkts * 100 << "%)" << std::endl;
  std::cout << "Total IPv4 5-tuples: " << flowCount.size() << std::endl;
  std::cout << "Total IPv4 5-tuple hashes: " << flowHashes.size() << std::endl;
  std::cout << "Total: " << totalPkts << std::endl;

  reader->close();
  delete reader;
  return 0;
}