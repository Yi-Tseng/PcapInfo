
#ifndef UTILS_H
#define UTILS_H

#include <CRC.h>
#include <RawPacket.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

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

  std::string ToString() const {
    std::stringstream ss;
    ss << std::hex << srcIp << ", " << std::hex << dstIp << ", " << std::hex
       << (uint16_t)(proto) << ", " << std::dec << l4Sport << ", " << l4Dport;
    return ss.str();
  }
};

struct V4TupleHasher {
  std::size_t operator()(V4Tuple const& v4tuple) const noexcept {
    return CRC::Calculate(&v4tuple, sizeof(V4Tuple), CRC::CRC_32());
  }
};

bool SortFlows(const std::pair<V4Tuple, uint32_t>& a,
               const std::pair<V4Tuple, uint32_t>& b) {
  return a.second > b.second;
}

void DumpPacketHex(const pcpp::RawPacket& packet) {
  const uint8_t* rawData = packet.getRawData();
  int len = packet.getRawDataLen();

  for (int c = 0; c < len; c++) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex
              << (uint16_t)rawData[c] << " ";
  }

  std::cout << std::endl;
}

#endif  // UTILS_H
