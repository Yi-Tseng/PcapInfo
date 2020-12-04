#include <CRC.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PayloadLayer.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "utils.h"
#include "xnt.h"

int main(int argc, char* argv[]) {
  bool printFlows = false;
  std::string pcapFile;

  if (argc < 2) {
    std::cout << "Input file name was not given" << std::endl;
    return 1;
  }

  pcapFile = argv[1];

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
  std::cout << std::endl;

  uint32_t totalReports = 0;
  uint32_t skipped = 0;

  std::unordered_map<V4Tuple, uint32_t, V4TupleHasher> flows;
  std::unordered_set<uint32_t> flowHashes;
  pcpp::RawPacket rawPacket;
  while (pcapReader->getNextPacket(rawPacket)) {
    totalReports++;
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
      std::cout << "No UDP header" << std::endl;
      skipped++;
      continue;
    }
    uint16_t l4Dport = ntohs(udpLayer->getUdpHeader()->portDst);

    if (l4Dport != 32766) {
      std::cout << "UDP port not 32766, " << l4Dport << std::endl;
      skipped++;
      continue;
    }
    pcpp::PayloadLayer* payloadLayer =
        parsedPacket.getLayerOfType<pcpp::PayloadLayer>();

    // Parse INT Header
    uint8_t* payload = payloadLayer->getPayload();
    size_t payloadLen = payloadLayer->getPayloadLen();

    std::shared_ptr<IntFixedHeader> intFixReport =
        ParseIntFixedHeader(&payload, &payloadLen);

    if (!intFixReport) {
      std::cout << "No fix report" << std::endl;
      skipped++;
      continue;
    }

    std::shared_ptr<IntLocalReport> intLocalReport =
        ParseIntLocalReport(&payload, &payloadLen);

    if (!intLocalReport) {
      std::cout << "No local report" << std::endl;
      skipped++;
      continue;
    }

    // The inner packet
    struct timeval t = {0};
    uint8_t* innerData = (uint8_t*)malloc(sizeof(uint8_t) * payloadLen);
    std::memcpy(innerData, payload, payloadLen);

    pcpp::RawPacket innerPacket(innerData, payloadLen, t, false,
                                pcpp::LINKTYPE_ETHERNET);
    pcpp::Packet innerParsedPacket(&innerPacket);
    pcpp::IPv4Layer* innerIpv4Layer =
        innerParsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* innerTcpLayer =
        innerParsedPacket.getLayerOfType<pcpp::TcpLayer>();
    pcpp::UdpLayer* innerUdpLayer =
        innerParsedPacket.getLayerOfType<pcpp::UdpLayer>();

    if (innerIpv4Layer) {
      uint32_t innerSrc = innerIpv4Layer->getSrcIpAddress().toInt();
      uint32_t innerDst = innerIpv4Layer->getDstIpAddress().toInt();
      uint8_t innerProto = ntohs(innerIpv4Layer->getIPv4Header()->protocol);
      uint16_t innerL4Sport = 0;
      uint16_t innerL4Dport = 0;
      if (innerTcpLayer) {
        innerL4Sport = ntohs(innerTcpLayer->getTcpHeader()->portSrc);
        innerL4Dport = ntohs(innerTcpLayer->getTcpHeader()->portDst);
      } else if (innerUdpLayer) {
        innerL4Sport = ntohs(innerUdpLayer->getUdpHeader()->portSrc);
        innerL4Dport = ntohs(innerUdpLayer->getUdpHeader()->portSrc);
      }
      V4Tuple ftple = {innerSrc, innerDst, innerProto, innerL4Sport,
                       innerL4Dport};
      uint32_t crc32 = CRC::Calculate(&ftple, sizeof(V4Tuple), CRC::CRC_32());
      flowHashes.insert(crc32);
      if (flows.find(ftple) == flows.end()) {
        flows[ftple] = 1;
      } else {
        flows[ftple]++;
      }
    } else {
      std::cout << "No Inner Ip header, first byte: " << (uint16_t)innerData[0] << std::endl;
      skipped++;
    }

    delete innerData;
  }
  std::cout << std::endl;
  std::cout << "Total reports: " << totalReports << std::endl;
  std::cout << "Total skipped: " << skipped << std::endl;

  std::cout << "Total Inner IPv4 5-tuples: " << flows.size() << std::endl;
  std::cout << "Total Inner IPv4 5-tuple hashes: " << flowHashes.size()
            << std::endl;

  std::vector<std::pair<V4Tuple, uint32_t>> flowsInOrder;
  for (auto it = flows.begin(); it != flows.end(); ++it) {
    flowsInOrder.push_back(std::make_pair(it->first, it->second));
  }

  sort(flowsInOrder.begin(), flowsInOrder.end(), SortFlows);

  for (auto it = flowsInOrder.begin(); it != flowsInOrder.end(); ++it) {
    std::cout << it->first.ToString() << " : " << it->second << std::endl;
  }

  reader->close();
  delete reader;
  return 0;
}