#include <iostream>
#include <fstream>
#include <cstdint>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <unordered_map>
#include <set>
#include <limits>
#include <algorithm>

uint32_t readUInt32(std::ifstream& file) {
    uint8_t bytes[4];
    file.read(reinterpret_cast<char*>(bytes), 4);

    if (!file)
        return 0;

    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

uint16_t readUInt16(const std::vector<uint8_t>& data, size_t pos) {
    return (static_cast<uint16_t>(data[pos]) << 8) |
           static_cast<uint16_t>(data[pos + 1]);
}

std::string getMac(const std::vector<uint8_t>& packet, size_t start) {
    std::ostringstream mac;

    for (int i = 0; i < 6; i++) {
        if (i)
            mac << ":";

        mac << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(packet[start + i]);
    }

    return mac.str();
}

std::string getIp(const std::vector<uint8_t>& packet, size_t start) {
    return std::to_string(packet[start]) + "." +
           std::to_string(packet[start + 1]) + "." +
           std::to_string(packet[start + 2]) + "." +
           std::to_string(packet[start + 3]);
}

std::string getService(uint16_t port) {
    switch (port) {
        case 20:
        case 21:
            return "FTP";

        case 22:
            return "SSH";

        case 23:
            return "Telnet";

        case 25:
            return "SMTP";

        case 53:
            return "DNS";

        case 67:
        case 68:
            return "DHCP";

        case 80:
            return "HTTP";

        case 110:
            return "POP3";

        case 123:
            return "NTP";

        case 143:
            return "IMAP";

        case 443:
            return "HTTPS";

        case 993:
            return "IMAPS";

        case 995:
            return "POP3S";

        default:
            return "Unknown";
    }
}

std::string makeFlowKey(
    const std::string& srcIp,
    const std::string& dstIp,
    uint16_t srcPort,
    uint16_t dstPort,
    const std::string& protocol
) {
    return srcIp + ":" +
           std::to_string(srcPort) +
           " -> " +
           dstIp + ":" +
           std::to_string(dstPort) +
           " [" +
           protocol +
           "]";
}

int main(int argc, char* argv[]) {

    std::cout << "========================================\n";
    std::cout << "       NETWORK PACKET ANALYZER\n";
    std::cout << "========================================\n\n";

    std::string filename;

    if (argc > 1)
        filename = argv[1];
    else
        filename = "samples/arp.pcapng";

    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        std::cout << "Error: Could not open file: "
                  << filename << "\n";
        std::cout << "Usage: netanalyzer <capture.pcapng>\n";
        return 1;
    }

    uint32_t sectionType = readUInt32(file);
    uint32_t sectionLength = readUInt32(file);

    if (!file || sectionLength < 12) {
        std::cout << "Error: Invalid section header.\n";
        return 1;
    }

    file.seekg(sectionLength - 12, std::ios::cur);

    if (!file) {
        std::cout << "Error: Could not read section header.\n";
        return 1;
    }

    uint32_t sectionClosingLength = readUInt32(file);

    if (!file) {
        std::cout << "Error: Could not read section closing length.\n";
        return 1;
    }

    uint32_t interfaceType = readUInt32(file);
    uint32_t interfaceLength = readUInt32(file);

    if (!file || interfaceLength < 16) {
        std::cout << "Error: Invalid interface description block.\n";
        return 1;
    }

    file.seekg(interfaceLength - 12, std::ios::cur);

    if (!file) {
        std::cout << "Error: Could not read interface block.\n";
        return 1;
    }

    uint32_t interfaceClosingLength = readUInt32(file);

    if (!file) {
        std::cout << "Error: Could not read interface closing length.\n";
        return 1;
    }

    uint32_t packetCount = 0;

    uint32_t arpCount = 0;
    uint32_t ipv4Count = 0;
    uint32_t ipv6Count = 0;
    uint32_t tcpCount = 0;
    uint32_t udpCount = 0;
    uint32_t icmpCount = 0;
    uint32_t unknownCount = 0;

    uint64_t totalCapturedBytes = 0;
    uint64_t totalOriginalBytes = 0;

    uint32_t smallestPacket =
        std::numeric_limits<uint32_t>::max();

    uint32_t largestPacket = 0;

    uint32_t synCount = 0;
    uint32_t ackCount = 0;
    uint32_t finCount = 0;
    uint32_t rstCount = 0;
    uint32_t pshCount = 0;
    uint32_t urgCount = 0;

    std::unordered_map<std::string, uint32_t> ipCounts;
    std::unordered_map<std::string, uint32_t> macCounts;
    std::unordered_map<uint16_t, uint32_t> portCounts;
    std::unordered_map<std::string, uint32_t> trafficDirections;

    std::unordered_map<std::string, std::set<uint16_t>> portsBySource;
    std::unordered_map<std::string, uint32_t> synBySource;

    std::unordered_map<std::string, uint32_t> flowPackets;
    std::unordered_map<std::string, uint64_t> flowBytes;

    while (true) {

        uint32_t blockType = readUInt32(file);

        if (!file)
            break;

        uint32_t blockLength = readUInt32(file);

        if (!file) {
            std::cout << "Error: Could not read block length.\n";
            break;
        }

        if (blockLength < 12) {
            std::cout << "Error: Invalid block length.\n";
            break;
        }

        if (blockType != 0x00000006) {

            file.seekg(blockLength - 12, std::ios::cur);

            if (!file)
                break;

            readUInt32(file);
            continue;
        }

        uint32_t interfaceId = readUInt32(file);
        uint32_t timestampHigh = readUInt32(file);
        uint32_t timestampLow = readUInt32(file);
        uint32_t capturedLength = readUInt32(file);
        uint32_t originalLength = readUInt32(file);

        if (!file) {
            std::cout << "Error: Could not read packet metadata.\n";
            break;
        }

        if (capturedLength > blockLength) {
            std::cout << "Error: Invalid packet length.\n";
            break;
        }

        std::vector<uint8_t> packet(capturedLength);

        file.read(
            reinterpret_cast<char*>(packet.data()),
            capturedLength
        );

        if (!file) {
            std::cout << "Error: Incomplete packet data.\n";
            break;
        }

        uint32_t padding =
            (4 - (capturedLength % 4)) % 4;

        file.seekg(padding, std::ios::cur);

        if (!file) {
            std::cout << "Error: Could not skip packet padding.\n";
            break;
        }

        uint32_t closingLength = readUInt32(file);

        if (!file) {
            std::cout << "Error: Could not read packet closing length.\n";
            break;
        }

        packetCount++;

        totalCapturedBytes += capturedLength;
        totalOriginalBytes += originalLength;

        if (capturedLength < smallestPacket)
            smallestPacket = capturedLength;

        if (capturedLength > largestPacket)
            largestPacket = capturedLength;

        if (packet.size() < 14) {
            unknownCount++;
            continue;
        }

        std::string destinationMac =
            getMac(packet, 0);

        std::string sourceMac =
            getMac(packet, 6);

        macCounts[sourceMac]++;
        macCounts[destinationMac]++;

        uint16_t etherType =
            readUInt16(packet, 12);

        if (etherType == 0x0806) {
            arpCount++;
            continue;
        }

        if (etherType == 0x86DD) {
            ipv6Count++;
            continue;
        }

        if (etherType != 0x0800) {
            unknownCount++;
            continue;
        }

        ipv4Count++;

        if (packet.size() < 34)
            continue;

        size_t ipStart = 14;

        uint8_t versionAndIhl =
            packet[ipStart];

        uint8_t version =
            versionAndIhl >> 4;

        uint8_t ihl =
            versionAndIhl & 0x0F;

        size_t ipHeaderLength =
            static_cast<size_t>(ihl) * 4;

        if (
            version != 4 ||
            ipHeaderLength < 20 ||
            packet.size() < ipStart + ipHeaderLength
        ) {
            continue;
        }

        std::string sourceIp =
            getIp(packet, ipStart + 12);

        std::string destinationIp =
            getIp(packet, ipStart + 16);

        ipCounts[sourceIp]++;
        ipCounts[destinationIp]++;

        uint8_t protocol =
            packet[ipStart + 9];

        trafficDirections[
            sourceIp + " -> " + destinationIp
        ]++;

        size_t transportStart =
            ipStart + ipHeaderLength;

        if (protocol == 1) {
            icmpCount++;
            continue;
        }

        if (protocol == 6) {

            tcpCount++;

            if (packet.size() < transportStart + 20)
                continue;

            uint16_t sourcePort =
                readUInt16(packet, transportStart);

            uint16_t destinationPort =
                readUInt16(
                    packet,
                    transportStart + 2
                );

            portCounts[sourcePort]++;
            portCounts[destinationPort]++;

            uint16_t flags =
                readUInt16(
                    packet,
                    transportStart + 12
                ) & 0x01FF;

            if (flags & 0x002) {
                synCount++;
                synBySource[sourceIp]++;
            }

            if (flags & 0x010)
                ackCount++;

            if (flags & 0x001)
                finCount++;

            if (flags & 0x004)
                rstCount++;

            if (flags & 0x008)
                pshCount++;

            if (flags & 0x020)
                urgCount++;

            portsBySource[sourceIp].insert(
                destinationPort
            );

            std::string flow =
                makeFlowKey(
                    sourceIp,
                    destinationIp,
                    sourcePort,
                    destinationPort,
                    "TCP"
                );

            flowPackets[flow]++;
            flowBytes[flow] += capturedLength;

            continue;
        }

        if (protocol == 17) {

            udpCount++;

            if (packet.size() < transportStart + 8)
                continue;

            uint16_t sourcePort =
                readUInt16(packet, transportStart);

            uint16_t destinationPort =
                readUInt16(
                    packet,
                    transportStart + 2
                );

            portCounts[sourcePort]++;
            portCounts[destinationPort]++;

            std::string flow =
                makeFlowKey(
                    sourceIp,
                    destinationIp,
                    sourcePort,
                    destinationPort,
                    "UDP"
                );

            flowPackets[flow]++;
            flowBytes[flow] += capturedLength;

            continue;
        }

        unknownCount++;
    }

    std::vector<std::string> alerts;

    for (const auto& entry : portsBySource) {

        if (entry.second.size() >= 10) {

            alerts.push_back(
                "Possible port scan from " +
                entry.first +
                " (" +
                std::to_string(entry.second.size()) +
                " ports)"
            );
        }
    }

    for (const auto& entry : synBySource) {

        if (entry.second >= 20) {

            alerts.push_back(
                "High SYN activity from " +
                entry.first +
                " (" +
                std::to_string(entry.second) +
                " SYN packets)"
            );
        }
    }

    std::vector<std::pair<std::string, uint32_t>> sortedIps;

    for (const auto& item : ipCounts)
        sortedIps.push_back({item.first, item.second});


    std::vector<std::pair<std::string, uint32_t>> sortedMacs;

    for (const auto& item : macCounts)
        sortedMacs.push_back({item.first, item.second});


    std::vector<std::pair<uint16_t, uint32_t>> sortedPorts;

    for (const auto& item : portCounts)
        sortedPorts.push_back({item.first, item.second});


    std::vector<std::pair<std::string, uint32_t>> sortedDirections;

    for (const auto& item : trafficDirections)
        sortedDirections.push_back({item.first, item.second});


    std::vector<std::pair<std::string, uint32_t>> sortedFlows;

    for (const auto& item : flowPackets)
        sortedFlows.push_back({item.first, item.second});


    auto compareCounts =
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        };


    std::sort(
        sortedIps.begin(),
        sortedIps.end(),
        compareCounts
    );

    std::sort(
        sortedMacs.begin(),
        sortedMacs.end(),
        compareCounts
    );

    std::sort(
        sortedPorts.begin(),
        sortedPorts.end(),
        compareCounts
    );

    std::sort(
        sortedDirections.begin(),
        sortedDirections.end(),
        compareCounts
    );

    std::sort(
        sortedFlows.begin(),
        sortedFlows.end(),
        compareCounts
    );

    std::cout << "\n========================================\n";
    std::cout << "        NETWORK ANALYSIS REPORT\n";
    std::cout << "========================================\n";

    std::cout << "\nCAPTURE\n";
    std::cout << "Packets       : "
              << packetCount << "\n";

    std::cout << "Captured      : "
              << totalCapturedBytes
              << " bytes\n";

    std::cout << "Original      : "
              << totalOriginalBytes
              << " bytes\n";

    if (packetCount > 0) {

        double average =
            static_cast<double>(totalCapturedBytes) /
            packetCount;

        std::cout << "Average       : "
                  << std::fixed
                  << std::setprecision(2)
                  << average
                  << " bytes\n";

        std::cout << "Smallest      : "
                  << smallestPacket
                  << " bytes\n";

        std::cout << "Largest       : "
                  << largestPacket
                  << " bytes\n";
    }

    std::cout << "\nPROTOCOLS\n";
    std::cout << "ARP           : " << arpCount << "\n";
    std::cout << "IPv4          : " << ipv4Count << "\n";
    std::cout << "IPv6          : " << ipv6Count << "\n";
    std::cout << "TCP           : " << tcpCount << "\n";
    std::cout << "UDP           : " << udpCount << "\n";
    std::cout << "ICMP          : " << icmpCount << "\n";
    std::cout << "Unknown       : " << unknownCount << "\n";

    std::cout << "\nTOP IP ADDRESSES\n";
    std::cout << "----------------------------------------\n";

    for (
        size_t i = 0;
        i < std::min<size_t>(10, sortedIps.size());
        i++
    ) {
        std::cout << std::left
                  << std::setw(18)
                  << sortedIps[i].first
                  << sortedIps[i].second
                  << " packets\n";
    }

    std::cout << "\nTOP MAC ADDRESSES\n";
    std::cout << "----------------------------------------\n";

    for (
        size_t i = 0;
        i < std::min<size_t>(10, sortedMacs.size());
        i++
    ) {
        std::cout << std::left
                  << std::setw(20)
                  << sortedMacs[i].first
                  << sortedMacs[i].second
                  << " packets\n";
    }

    std::cout << "\nTOP PORTS\n";
    std::cout << "----------------------------------------\n";

    for (
        size_t i = 0;
        i < std::min<size_t>(10, sortedPorts.size());
        i++
    ) {
        uint16_t port =
            sortedPorts[i].first;

        std::cout << std::left
                  << std::setw(8)
                  << port
                  << std::setw(10)
                  << getService(port)
                  << sortedPorts[i].second
                  << " uses\n";
    }

    std::cout << "\nTRAFFIC DIRECTIONS\n";
    std::cout << "----------------------------------------\n";

    for (
        size_t i = 0;
        i < std::min<size_t>(10, sortedDirections.size());
        i++
    ) {
        std::cout << sortedDirections[i].first
                  << " : "
                  << sortedDirections[i].second
                  << " packets\n";
    }

    std::cout << "\nTCP FLAGS\n";
    std::cout << "----------------------------------------\n";

    std::cout << "SYN           : "
              << synCount << "\n";

    std::cout << "ACK           : "
              << ackCount << "\n";

    std::cout << "FIN           : "
              << finCount << "\n";

    std::cout << "RST           : "
              << rstCount << "\n";

    std::cout << "PSH           : "
              << pshCount << "\n";

    std::cout << "URG           : "
              << urgCount << "\n";

    std::cout << "\nNETWORK FLOWS\n";
    std::cout << "----------------------------------------\n";

    for (
        size_t i = 0;
        i < std::min<size_t>(10, sortedFlows.size());
        i++
    ) {
        const std::string& flow =
            sortedFlows[i].first;

        std::cout << flow << "\n";

        std::cout << "  Packets: "
                  << sortedFlows[i].second
                  << "\n";

        std::cout << "  Bytes: "
                  << flowBytes[flow]
                  << "\n";
    }

    std::cout << "\nSECURITY ALERTS\n";
    std::cout << "----------------------------------------\n";

    if (alerts.empty()) {

        std::cout << "No basic anomalies detected.\n";

    } else {

        for (const auto& alert : alerts)
            std::cout << "[ALERT] "
                      << alert
                      << "\n";
    }

    std::cout << "\n========================================\n";
    std::cout << "          ANALYSIS COMPLETE\n";
    std::cout << "========================================\n";

    return 0;
}