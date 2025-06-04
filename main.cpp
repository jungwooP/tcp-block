#include <cstdio>
#include <cstring>      // 문자열/메모리 처리 함수
#include <cstdlib>      // 일반 유틸리티 함수 (malloc, rand 등)
#include <pcap.h>       // libpcap 캡처 함수
#include <sys/socket.h> // 소켓 생성
#include <sys/types.h>
#include <sys/ioctl.h>  // ioctl 통해 인터페이스 정보 조회
#include <net/if.h>     // 인터페이스 관련 구조체
#include <unistd.h>     // close 등 유닉스 시스템 호출
#include <arpa/inet.h>  // inet_ntop, 소켓 주소 구조체

#include "tcphdr.h"     // TCP header 구조체
#include "iphdr.h"      // IP header 구조체
#include "ethhdr.h"     // Ethernet header 구조체

#define REDIRECT_PAYLOAD \
    "HTTP/1.0 302 Redirect\r\n" \
    "Location: http://warning.or.kr\r\n" \
    "\r\n"

// Local Interface MAC, IP 주소 저장
Mac mac;
Ip ip;

// TCP Checksum 계산을 위한 도우미 Header 구조체 (실제로는 전송 안 됨)
typedef struct {
    uint32_t src_ip;  // 출발지 IP
    uint32_t dst_ip;  // 목적지 IP
    uint8_t  zero;    // 항상 0
    uint8_t  proto;   // 프로토콜 번호 (TCP=6)
    uint16_t length;  // TCP 헤더 + 데이터의 총 길이
} helper_header;

//Usage
void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// interface의 이름 받아서 MAC/IP를 조회하는 함수
// out_mac, out_ip에 결과를 저장
int get_interface_header(const char* iface, Mac* out_mac, Ip* out_ip) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    // MAC 주소 조회
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    uint8_t mac_buf[6];
    memcpy(mac_buf, ifr.ifr_hwaddr.sa_data, 6);
    *out_mac = Mac(mac_buf);

    // IP 주소 조회
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    char ip_buf[30];
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip_buf, sizeof(ip_buf));
    *out_ip = Ip(ip_buf);
    close(sockfd);
    return 0;
}

// IP 및 TCP protocol의 Checksum 계산 (16bit Word 합산 -> 역전 -> 보수)
// 16비트 워드를 더하고, 넘친 비트를 접어 합친 후 역전 보수
uint16_t checksum_calc(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *((uint8_t*)data);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage(); // 인자가 부족 시, 종료
        return 0;
    }

    const char* iface = argv[1];
    // Interface의 MAC/IP 가져오기 (raw 소켓 송신 시 필요해서 받아오기)
    if (get_interface_header(iface, &mac, &ip) < 0) {
        fprintf(stderr, "Failed to get MAC/IP for %s\n", iface);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap 세션 열기: iface 인터페이스, 수신 모드, 1ms 타임아웃
    pcap_t* pcap = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "couldn't open device %s (%s)\n", iface, errbuf);
        return -1;
    }
    printf("[*] Listening on interface %s\n", iface);

    const char* pattern = argv[2]; // 차단할 HTTP의 Pattern (EX: "Host: test.gilgil.net")
    struct pcap_pkthdr* header;
    const u_char* packet;
    PEthHdr eth_hdr;
    PIpHdr ip_hdr;
    PTcpHdr tcp_hdr;

    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue; // 타임아웃 후 다시 대기하도록 함. 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            fprintf(stderr, "pcap_next_ex return %d (%s)\n", res, pcap_geterr(pcap));
            break;
        }
        eth_hdr = (PEthHdr)packet;
        // Ethernet 타입이 IPv4가 아니면 스킵
        if (eth_hdr->type() != EthHdr::Ip4) continue;

        ip_hdr = (PIpHdr)((uint8_t*)eth_hdr + sizeof(EthHdr));
        uint32_t ip_hdr_len = (ip_hdr->ip_len) * 4;  // IP Header 길이 (byte)
        uint32_t ip_tot_len = ntohs(ip_hdr->total_len); // IP 전체 길이 (네트워크 바이트 오더 -> 호스트)
        // TCP 아닌 패킷 무시
        if (ip_hdr->proto != IPPROTO_TCP) continue; 

        tcp_hdr = (PTcpHdr)((uint8_t*)ip_hdr + ip_hdr_len);
        uint32_t tcp_hdr_len = get_header_length(tcp_hdr); // TCP Header 길이 (byte)
        uint32_t data_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
        if (data_len == 0) continue; // 데이터가 없으면 패턴 검사 불필요해서 .. 
        
        // TCP 페이로드 복사 후 문자열 패턴 검사
        char* data_buf = (char*)malloc(data_len + 1);
        if (!data_buf) continue;
        memset(data_buf, 0, data_len + 1);
        memcpy(data_buf, (uint8_t*)tcp_hdr + tcp_hdr_len, data_len);
        bool match = (strstr(data_buf, pattern) != nullptr);
        free(data_buf);
        if (!match) continue;

        // 패턴 탐지 시 로그 출력하기!
        printf("[*] Pattern \"%s\" detected, injecting block packets.\n", pattern);
        
        // 1) 역방향 FIN+Redirect 송신 (Server -> Client)
        // raw 소켓 생성 (TCP 레이어까지 직접 생성함.) 
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (raw_sock < 0) continue;
        int opt = 1;
        // IP_HDRINCL: IP 헤더를 수작업으로 포함하겠다는 설정임.
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
            close(raw_sock);
            continue;
        }

        struct sockaddr_in addr_cli;
        memset(&addr_cli, 0, sizeof(addr_cli));
        addr_cli.sin_family = AF_INET;
        addr_cli.sin_addr.s_addr = ip_hdr->sip_; // 원본 클라이언트 IP

        const char* redirect_payload = REDIRECT_PAYLOAD;
        uint16_t redirect_len = strlen(REDIRECT_PAYLOAD);
        
        // IP/TCP + 페이로드 길이 계산 (IP 헤더(20) + TCP 헤더(20) + payload 길이 합산)
        uint16_t new_ip_len = sizeof(IpHdr);
        uint16_t new_tcp_len = sizeof(TcpHdr);
        uint16_t total_len = new_ip_len + new_tcp_len + redirect_len;
        
        // 패킷 버퍼 할당
        char* out_pkt = (char*)malloc(total_len);
        if (!out_pkt) {
            close(raw_sock);
            continue;
        }
        memset(out_pkt, 0, total_len);
        
         // IP Header 구성 (20 Byte)
        PIpHdr new_ip_hdr = (PIpHdr)out_pkt; 
        new_ip_hdr->ip_v = 4;                                // IPv4
        new_ip_hdr->ip_len = new_ip_len / 4;                 // IHL(20byte -> 5)
        new_ip_hdr->total_len = htons(total_len);            // 전체 길이 (IP+TCP+데이터)
        new_ip_hdr->id = htons(rand() & 0xFFFF);             // 랜덤 ID가 들어감. 
        new_ip_hdr->ttl = 128;                               // Backward용 TTL 설정
        new_ip_hdr->proto = IPPROTO_TCP;                     // 프로토콜 TCP
        new_ip_hdr->sip_ = ip_hdr->dip_;                     // 서버 IP -> 출발지
        new_ip_hdr->dip_ = ip_hdr->sip_;                     // 클라이언트 IP → 목적지
        new_ip_hdr->check = 0;
        new_ip_hdr->check = checksum_calc((uint16_t*)new_ip_hdr, new_ip_len);

        // TCP Header 구성 (20 Byte)
        PTcpHdr new_tcp_hdr = (PTcpHdr)(out_pkt + new_ip_len);
        new_tcp_hdr->tcp_src_port = tcp_hdr->tcp_dest_port;   // 서버 포트 -> src
        new_tcp_hdr->tcp_dest_port = tcp_hdr->tcp_src_port;   // 클라이언트 포트 -> dst
        new_tcp_hdr->tcp_offset = new_tcp_len / 4;            // HLEN=5
        new_tcp_hdr->tcp_flags = TCP_FIN | TCP_ACK;           // FIN+ACK
        new_tcp_hdr->tcp_seq = tcp_hdr->tcp_ack;              // seq = 원본 TCP ACK
        uint32_t orig_seq = ntohl(tcp_hdr->tcp_seq);
        new_tcp_hdr->tcp_ack = htonl(orig_seq + data_len);    // ack=org_seq+payload_len
        new_tcp_hdr->tcp_window = htons(60000);               // Window 크기는 넉넉하게 함.
        new_tcp_hdr->tcp_urgent = 0;
        
        // TCP 데이터 복사 --> (302 Redirect)
        memcpy(out_pkt + new_ip_len + new_tcp_len, redirect_payload, redirect_len);
        
        // TCP Checksum 계산하기 (도우미 헤더 + TCP 헤더 + 데이터)
        helper_header helper;
        helper.src_ip = new_ip_hdr->sip_;
        helper.dst_ip = new_ip_hdr->dip_;
        helper.zero = 0;
        helper.proto = IPPROTO_TCP;
        helper.length = htons(new_tcp_len + redirect_len);

        int ph_sz = sizeof(helper_header);
        int seg_total = new_tcp_len + redirect_len;
        char* chk_buf = (char*)malloc(ph_sz + seg_total);
        if (!chk_buf) {
            free(out_pkt);
            close(raw_sock);
            continue;
        }
        memcpy(chk_buf, &helper, ph_sz);
        memcpy(chk_buf + ph_sz, new_tcp_hdr, seg_total);
        new_tcp_hdr->tcp_checksum = checksum_calc((uint16_t*)chk_buf, ph_sz + seg_total);
        free(chk_buf);

        // 역방향 패킷 전송하기 - sendto
        sendto(raw_sock, out_pkt, total_len, 0, (struct sockaddr*)&addr_cli, sizeof(addr_cli));
        free(out_pkt);
        close(raw_sock);
        
        // 2) 정방향 RST+ACK 송신 (Client -> Server)
        uint32_t saved_ip_len = ip_hdr_len;
        uint32_t rst_size = sizeof(EthHdr) + saved_ip_len + sizeof(TcpHdr);
        char* rst_pkt = (char*)malloc(rst_size);
        if (!rst_pkt) continue;
        memset(rst_pkt, 0, rst_size);
        memcpy(rst_pkt, packet, rst_size); // 원본 Ethernet+IP+TCP 헤더 복제

        // Ethernet 헤더 수정: smac=내 MAC, dmac=원본 dmac(서버 MAC 유지)
        PEthHdr rst_eth = (PEthHdr)rst_pkt;
        PIpHdr rst_ip_hdr = (PIpHdr)(rst_pkt + sizeof(EthHdr));
        PTcpHdr rst_tcp_hdr = (PTcpHdr)(rst_pkt + sizeof(EthHdr) + saved_ip_len);

        rst_eth->smac_ = mac;

        // IP 헤더 재계산
        rst_ip_hdr->total_len = htons(saved_ip_len + sizeof(TcpHdr)); // IP+TCP 길이
        rst_ip_hdr->check = 0;
        rst_ip_hdr->check = checksum_calc((uint16_t*)rst_ip_hdr, saved_ip_len);

        // TCP 헤더 재계산
        rst_tcp_hdr->tcp_offset = sizeof(TcpHdr) / 4; // HLEN=5
        rst_tcp_hdr->tcp_seq = htonl(ntohl(tcp_hdr->tcp_seq) + data_len); // seq=org_seq+payload_len
        rst_tcp_hdr->tcp_flags = TCP_RST | TCP_ACK;  // RST+ACK
        rst_tcp_hdr->tcp_checksum = 0;

        helper_header helper2;
        helper2.src_ip = rst_ip_hdr->sip_;
        helper2.dst_ip = rst_ip_hdr->dip_;
        helper2.zero = 0;
        helper2.proto = IPPROTO_TCP;
        helper2.length = htons(sizeof(TcpHdr));

        int ph2_sz = sizeof(helper_header);
        int seg2_total = sizeof(TcpHdr);
        char* chk_buf2 = (char*)malloc(ph2_sz + seg2_total);
        if (!chk_buf2) {
            free(rst_pkt);
            continue;
        }
        memcpy(chk_buf2, &helper2, ph2_sz);
        memcpy(chk_buf2 + ph2_sz, rst_tcp_hdr, seg2_total);
        rst_tcp_hdr->tcp_checksum = checksum_calc((uint16_t*)chk_buf2, ph2_sz + seg2_total);
        free(chk_buf2);
        
        // 정방향 RST 패킷 전송
        pcap_sendpacket(pcap, (const u_char*)rst_pkt, rst_size);
        free(rst_pkt);
    }

    pcap_close(pcap);
    return 0;
}

