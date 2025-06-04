#pragma once

#include <cstdint>
#include <arpa/inet.h>

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

#pragma pack(push, 1)
struct TcpHdr {
    uint16_t tcp_src_port;       // Source TCP port
    uint16_t tcp_dest_port;      // Destination TCP port

    uint32_t tcp_seq;            // TCP sequence number
    uint32_t tcp_ack;            // TCP acknowledgment number

    uint8_t  reserved : 4;       // Reserved (unused / should be zero / 4bits from 6bits of reserved space)
    uint8_t  tcp_offset : 4;     // Header length (in 32-bit words)

    uint8_t  tcp_flags;          // TCP flags (SYN, ACK, FIN, etc..., and 2bits from reserved space )
    uint16_t tcp_window;         // TCP Window size
    uint16_t tcp_checksum;       // TCP checksum
    uint16_t tcp_urgent;         // TCP urgent pointer
};
typedef TcpHdr* PTcpHdr;
#pragma pack(pop)

// Return header length in bytes
inline uint8_t get_header_length(const TcpHdr* hdr) {
    return hdr->tcp_offset * 4;
}


