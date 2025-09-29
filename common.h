#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_FRAME_SIZE 1500
#define MAX_DATA_SIZE 1400
#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define MAX_CONNECTED_PORTS 8
#define MAX_MAC_TABLE_SIZE 16
#define MAX_ARP_TABLE_SIZE 32
#define MAX_ROUTING_TABLE_SIZE 64
#define MAX_RIP_ENTRIES 25
#define BROADCAST_MAC "FF:FF:FF:FF:FF:FF"
#define BROADCAST_IP "255.255.255.255"
#define ACK_FRAME "ACK_FRAME"
#define TIMEOUT_SEC 3
#define DEVICE_ID_MAX 32
#define FILE_LOCK_RETRY 5
#define FILE_LOCK_WAIT_MS 50
#define MAX_PACKET_SIZE 1024
#define MAX_WINDOW_SIZE 8
#define TCP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define ETH_HEADER_SIZE 14
#define RIP_HEADER_SIZE 4
#define RIP_ENTRY_SIZE 20

// Protocol types
#define PROTO_ARP 0x0806
#define PROTO_IP 0x0800
#define PROTO_TCP 6
#define PROTO_UDP 17

// Well-known ports
#define HTTP_PORT 80
#define DNS_PORT 53
#define RIP_PORT 520
#define FTP_PORT 21
#define SSH_PORT 22
#define TELNET_PORT 23

// Ephemeral port range
#define EPHEMERAL_PORT_START 32768
#define EPHEMERAL_PORT_END 60999

// TCP flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// RIP constants
#define RIP_VERSION 2
#define RIP_REQUEST 1
#define RIP_RESPONSE 2
#define RIP_INFINITY 16
#define RIP_UPDATE_TIMER 30
#define RIP_TIMEOUT 180
#define RIP_GARBAGE_TIMER 120

// Transport layer protocols
typedef enum {
    TRANSPORT_TCP,
    TRANSPORT_UDP
} transport_protocol_t;

// TCP states
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

// Sliding window states
typedef enum {
    FRAME_READY,
    FRAME_SENT,
    FRAME_ACKED
} frame_state_t;

// Ethernet frame structure
typedef struct {
    char dest_mac[MAC_ADDR_LEN];
    char source_mac[MAC_ADDR_LEN];
    uint16_t ethertype;
    char payload[MAX_DATA_SIZE];
    int payload_size;
    uint32_t checksum;
} __attribute__((packed)) EthernetFrame;

// IP packet structure
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    char source_ip[IP_ADDR_LEN];
    char dest_ip[IP_ADDR_LEN];
    char payload[MAX_PACKET_SIZE];
    int payload_size;
} __attribute__((packed)) IPPacket;

// ARP packet structure
typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
    char sender_mac[MAC_ADDR_LEN];
    char sender_ip[IP_ADDR_LEN];
    char target_mac[MAC_ADDR_LEN];
    char target_ip[IP_ADDR_LEN];
} __attribute__((packed)) ARPPacket;

// TCP header structure
typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t header_len;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    char payload[MAX_PACKET_SIZE];
    int payload_size;
} __attribute__((packed)) TCPPacket;

// UDP header structure
typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
    char payload[MAX_PACKET_SIZE];
    int payload_size;
} __attribute__((packed)) UDPPacket;

// RIP header
typedef struct {
    uint8_t command;
    uint8_t version;
    uint16_t zero;
} __attribute__((packed)) RIPHeader;

// RIP entry
typedef struct {
    uint16_t afi;
    uint16_t route_tag;
    char ip_addr[IP_ADDR_LEN];
    char subnet_mask[IP_ADDR_LEN];
    char next_hop[IP_ADDR_LEN];
    uint32_t metric;
} __attribute__((packed)) RIPEntry;

// RIP packet
typedef struct {
    RIPHeader header;
    RIPEntry entries[MAX_RIP_ENTRIES];
    int entry_count;
} RIPPacket;

// Sliding window frame
typedef struct {
    TCPPacket packet;
    frame_state_t state;
    time_t send_time;
    int retries;
} SlidingWindowFrame;

// ARP table entry
typedef struct {
    char ip_address[IP_ADDR_LEN];
    char mac_address[MAC_ADDR_LEN];
    time_t last_seen;
    bool is_static;
} ARPEntry;

// Routing table entry
typedef struct {
    char network[IP_ADDR_LEN];
    char netmask[IP_ADDR_LEN];
    char next_hop[IP_ADDR_LEN];
    char interface[DEVICE_ID_MAX];
    int metric;
    bool is_static;
    time_t last_update;
} RoutingEntry;

// Port connection structure
typedef struct {
    int port_num;
    char device_id[DEVICE_ID_MAX];
    char file_in[100];
    char file_out[100];
    char ip_address[IP_ADDR_LEN];
    char netmask[IP_ADDR_LEN];
    bool connected;
} Port;

// MAC table entry for switches
typedef struct {
    char mac_address[MAC_ADDR_LEN];
    int port_num;
    time_t last_seen;
} MACTableEntry;

// TCP connection state
typedef struct {
    char remote_ip[IP_ADDR_LEN];
    uint16_t remote_port;
    uint16_t local_port;
    tcp_state_t state;
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t expected_seq;
    
    // Sliding window for Go-Back-N
    SlidingWindowFrame window[MAX_WINDOW_SIZE];
    int window_start;
    int window_next_seq;
    int window_size;
    
    time_t last_activity;
    pthread_mutex_t conn_mutex;
} TCPConnection;

// Application service structure
typedef struct {
    uint16_t port;
    transport_protocol_t protocol;
    bool active;
    void (*handler)(char* request, char* response, int* response_size, char* source_ip);
} AppService;

// Port manager
typedef struct {
    uint16_t next_ephemeral;
    pthread_mutex_t port_mutex;
} PortManager;

// Global port manager
PortManager port_manager = {
    .next_ephemeral = EPHEMERAL_PORT_START,
    .port_mutex = PTHREAD_MUTEX_INITIALIZER
};

// Get next ephemeral port
uint16_t get_ephemeral_port() {
    pthread_mutex_lock(&port_manager.port_mutex);
    uint16_t port = port_manager.next_ephemeral++;
    if (port_manager.next_ephemeral > EPHEMERAL_PORT_END) {
        port_manager.next_ephemeral = EPHEMERAL_PORT_START;
    }
    pthread_mutex_unlock(&port_manager.port_mutex);
    return port;
}

// Generate checksum
uint32_t calculate_checksum(const void *data, int size) {
    uint32_t sum = 0;
    const uint8_t *bytes = (const uint8_t*)data;
    for (int i = 0; i < size; i++) {
        sum += bytes[i];
    }
    return sum;
}

// Validate checksum
bool validate_checksum(const EthernetFrame *frame) {
    uint32_t calc_sum = calculate_checksum(frame->payload, frame->payload_size);
    return (calc_sum == frame->checksum);
}

// Generate random MAC address
void generate_random_mac(char *mac) {
    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X", 
            rand() % 256, rand() % 256, rand() % 256, 
            rand() % 256, rand() % 256, rand() % 256);
}

// IP address utilities
bool is_same_network(const char *ip1, const char *ip2, const char *netmask) {
    struct in_addr addr1, addr2, mask;
    inet_aton(ip1, &addr1);
    inet_aton(ip2, &addr2);
    inet_aton(netmask, &mask);
    
    return (addr1.s_addr & mask.s_addr) == (addr2.s_addr & mask.s_addr);
}

bool is_broadcast_ip(const char *ip, const char *network, const char *netmask) {
    struct in_addr addr, net, mask;
    inet_aton(ip, &addr);
    inet_aton(network, &net);
    inet_aton(netmask, &mask);
    
    uint32_t broadcast = net.s_addr | (~mask.s_addr);
    return addr.s_addr == broadcast;
}

// Calculate network address
void get_network_address(const char *ip, const char *netmask, char *network) {
    struct in_addr addr, mask, net;
    inet_aton(ip, &addr);
    inet_aton(netmask, &mask);
    net.s_addr = addr.s_addr & mask.s_addr;
    strcpy(network, inet_ntoa(net));
}

// Create Ethernet frame
void create_ethernet_frame(EthernetFrame *frame, const char *dest_mac, 
                          const char *source_mac, uint16_t ethertype,
                          const void *payload, int payload_size) {
    memset(frame, 0, sizeof(EthernetFrame));
    
    if (payload_size > MAX_DATA_SIZE) {
        payload_size = MAX_DATA_SIZE;
    }
    
    strncpy(frame->dest_mac, dest_mac, MAC_ADDR_LEN - 1);
    frame->dest_mac[MAC_ADDR_LEN - 1] = '\0';
    strncpy(frame->source_mac, source_mac, MAC_ADDR_LEN - 1);
    frame->source_mac[MAC_ADDR_LEN - 1] = '\0';
    frame->ethertype = ethertype;
    
    if (payload && payload_size > 0) {
        memcpy(frame->payload, payload, payload_size);
    }
    frame->payload_size = payload_size;
    frame->checksum = calculate_checksum(payload, payload_size);
}

// Create IP packet
void create_ip_packet(IPPacket *packet, const char *source_ip, 
                     const char *dest_ip, uint8_t protocol,
                     const void *payload, int payload_size) {
    memset(packet, 0, sizeof(IPPacket));
    
    if (payload_size > MAX_PACKET_SIZE) {
        payload_size = MAX_PACKET_SIZE;
    }
    
    packet->version_ihl = 0x45;
    packet->tos = 0;
    packet->total_length = htons(IP_HEADER_SIZE + payload_size);
    packet->id = htons(rand() % 65536);
    packet->flags_fragment = 0;
    packet->ttl = 64;
    packet->protocol = protocol;
    packet->checksum = 0;
    strncpy(packet->source_ip, source_ip, IP_ADDR_LEN - 1);
    packet->source_ip[IP_ADDR_LEN - 1] = '\0';
    strncpy(packet->dest_ip, dest_ip, IP_ADDR_LEN - 1);
    packet->dest_ip[IP_ADDR_LEN - 1] = '\0';
    
    if (payload && payload_size > 0) {
        memcpy(packet->payload, payload, payload_size);
    }
    packet->payload_size = payload_size;
}

// Create ARP packet
void create_arp_packet(ARPPacket *arp, uint16_t opcode, 
                      const char *sender_mac, const char *sender_ip,
                      const char *target_mac, const char *target_ip) {
    memset(arp, 0, sizeof(ARPPacket));
    
    arp->hw_type = htons(1);
    arp->proto_type = htons(PROTO_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(opcode);
    strncpy(arp->sender_mac, sender_mac, MAC_ADDR_LEN - 1);
    arp->sender_mac[MAC_ADDR_LEN - 1] = '\0';
    strncpy(arp->sender_ip, sender_ip, IP_ADDR_LEN - 1);
    arp->sender_ip[IP_ADDR_LEN - 1] = '\0';
    strncpy(arp->target_mac, target_mac, MAC_ADDR_LEN - 1);
    arp->target_mac[MAC_ADDR_LEN - 1] = '\0';
    strncpy(arp->target_ip, target_ip, IP_ADDR_LEN - 1);
    arp->target_ip[IP_ADDR_LEN - 1] = '\0';
}

// Create TCP packet
void create_tcp_packet(TCPPacket *tcp, uint16_t src_port, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags,
                      const void *payload, int payload_size) {
    memset(tcp, 0, sizeof(TCPPacket));
    
    tcp->source_port = htons(src_port);
    tcp->dest_port = htons(dst_port);
    tcp->seq_num = htonl(seq);
    tcp->ack_num = htonl(ack);
    tcp->header_len = (TCP_HEADER_SIZE / 4) << 4;
    tcp->flags = flags;
    tcp->window_size = htons(MAX_WINDOW_SIZE);
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;
    
    if (payload && payload_size > 0) {
        memcpy(tcp->payload, payload, payload_size);
    }
    tcp->payload_size = payload_size;
}

// Create UDP packet
void create_udp_packet(UDPPacket *udp, uint16_t src_port, uint16_t dst_port,
                      const void *payload, int payload_size) {
    memset(udp, 0, sizeof(UDPPacket));
    
    udp->source_port = htons(src_port);
    udp->dest_port = htons(dst_port);
    udp->length = htons(UDP_HEADER_SIZE + payload_size);
    udp->checksum = 0;
    
    if (payload && payload_size > 0) {
        memcpy(udp->payload, payload, payload_size);
    }
    udp->payload_size = payload_size;
}

// Create RIP packet
void create_rip_packet(RIPPacket *rip, uint8_t command) {
    memset(rip, 0, sizeof(RIPPacket));
    rip->header.command = command;
    rip->header.version = RIP_VERSION;
    rip->header.zero = 0;
    rip->entry_count = 0;
}

// Add RIP entry
void add_rip_entry(RIPPacket *rip, const char *network, const char *netmask,
                  const char *next_hop, uint32_t metric) {
    if (rip->entry_count >= MAX_RIP_ENTRIES) return;
    
    RIPEntry *entry = &rip->entries[rip->entry_count];
    entry->afi = htons(2); // Address Family Internet
    entry->route_tag = 0;
    strncpy(entry->ip_addr, network, IP_ADDR_LEN - 1);
    strncpy(entry->subnet_mask, netmask, IP_ADDR_LEN - 1);
    strncpy(entry->next_hop, next_hop, IP_ADDR_LEN - 1);
    entry->metric = htonl(metric);
    
    rip->entry_count++;
}

// Print frame details
void print_ethernet_frame(const EthernetFrame *frame, const char *prefix) {
    printf("%s Ethernet Frame: SRC=%s, DST=%s, Type=0x%04x, Size=%d\n", 
           prefix, frame->source_mac, frame->dest_mac, 
           frame->ethertype, frame->payload_size);
}

void print_ip_packet(const IPPacket *packet, const char *prefix) {
    printf("%s IP Packet: SRC=%s, DST=%s, Proto=%d, Size=%d, TTL=%d\n",
           prefix, packet->source_ip, packet->dest_ip, 
           packet->protocol, packet->payload_size, packet->ttl);
}

void print_tcp_packet(const TCPPacket *tcp, const char *prefix) {
    printf("%s TCP: SRC_PORT=%d, DST_PORT=%d, SEQ=%u, ACK=%u, FLAGS=0x%02x\n",
           prefix, ntohs(tcp->source_port), ntohs(tcp->dest_port),
           ntohl(tcp->seq_num), ntohl(tcp->ack_num), tcp->flags);
}

// Directory and file operations
bool ensure_tmp_directory() {
    struct stat st = {0};
    if (stat("./tmp", &st) == -1) {
        if (mkdir("./tmp", 0777) != 0) {
            printf("Failed to create tmp directory: %s\n", strerror(errno));
            return false;
        }
        printf("Created ./tmp directory\n");
    }
    return true;
}

bool init_comm_file(const char *file_path) {
    if (!ensure_tmp_directory()) return false;
    
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        printf("Failed to create communication file %s: %s\n", 
               file_path, strerror(errno));
        return false;
    }
    fclose(file);
    
    if (chmod(file_path, 0666) != 0) {
        printf("Failed to set permissions on %s: %s\n", 
               file_path, strerror(errno));
        return false;
    }
    
    printf("Initialized file: %s\n", file_path);
    return true;
}

// Frame transmission functions
bool send_ethernet_frame(const char *file_path, const EthernetFrame *frame) {
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        printf("SEND_ERROR: Failed to open %s: %s\n", file_path, strerror(errno));
        return false;
    }
    
    size_t written = fwrite(frame, sizeof(EthernetFrame), 1, file);
    fflush(file);
    fclose(file);
    
    if (written != 1) {
        printf("SEND_ERROR: Failed to write frame to %s\n", file_path);
        return false;
    }
    
    printf("SEND_OK: Wrote frame to %s (size=%zu)\n", file_path, sizeof(EthernetFrame));
    return true;
}

bool receive_ethernet_frame(const char *file_path, EthernetFrame *frame) {
    struct stat st;
    if (stat(file_path, &st) == -1) {
        return false;
    }
    
    if (st.st_size < sizeof(EthernetFrame)) {
        return false;
    }
    
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        return false;
    }
    
    memset(frame, 0, sizeof(EthernetFrame));
    
    size_t read = fread(frame, sizeof(EthernetFrame), 1, file);
    fclose(file);
    
    if (read == 1) {
        FILE *clear_file = fopen(file_path, "wb");
        if (clear_file) {
            fclose(clear_file);
        }
        printf("RECV_OK: Read frame from %s\n", file_path);
        return true;
    }
    
    return false;
}

// Helper function for file paths
void get_file_paths(char *file_in, char *file_out, const char *my_id, 
                    const char *other_id, int port_num) {
    snprintf(file_in, 99, "./tmp/%s_to_%s_port%d.bin", other_id, my_id, port_num);
    snprintf(file_out, 99, "./tmp/%s_to_%s_port%d.bin", my_id, other_id, port_num);
    
    printf("FILE_PATHS: my_id=%s, other_id=%s, port=%d\n", my_id, other_id, port_num);
    printf("  file_in (I read):  %s\n", file_in);
    printf("  file_out (I write): %s\n", file_out);
}

// Application layer handlers
void http_handler(char* request, char* response, int* response_size, char* source_ip) {
    printf("HTTP_HANDLER: Request from %s: %s\n", source_ip, request);
    
    // Simple HTTP response
    const char* http_template = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>Network Simulator HTTP Server</h1>"
        "<p>Request from: %s</p>"
        "<p>Your request: %s</p>"
        "</body></html>";
    
    char body[512];
    snprintf(body, sizeof(body), 
             "<html><body><h1>Network Simulator HTTP Server</h1>"
             "<p>Request from: %s</p></body></html>", source_ip);
    
    snprintf(response, MAX_PACKET_SIZE, http_template, 
             (int)strlen(body), source_ip, "GET /");
    
    *response_size = strlen(response);
}

void dns_handler(char* request, char* response, int* response_size, char* source_ip) {
    printf("DNS_HANDLER: Query from %s: %s\n", source_ip, request);
    
    // Simple DNS response (mock)
    if (strstr(request, "example.com")) {
        snprintf(response, MAX_PACKET_SIZE, "DNS_RESPONSE:192.168.1.100");
    } else {
        snprintf(response, MAX_PACKET_SIZE, "DNS_RESPONSE:NOT_FOUND");
    }
    
    *response_size = strlen(response);
}

#endif