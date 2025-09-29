#include "common.h"

char my_mac[MAC_ADDR_LEN];
char my_ip[IP_ADDR_LEN];
char my_netmask[IP_ADDR_LEN];
char device_id[DEVICE_ID_MAX];
char conn_device[DEVICE_ID_MAX];
int port_num;
char file_in[100];
char file_out[100];
bool running = true;

// ARP and networking
ARPEntry arp_table[MAX_ARP_TABLE_SIZE];
int arp_table_size = 0;
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;

// Transport layer
TCPConnection tcp_connections[8];
int tcp_conn_count = 0;
AppService services[8];
int service_count = 0;
pthread_mutex_t transport_mutex = PTHREAD_MUTEX_INITIALIZER;

// TCP sequence numbers
uint32_t next_seq_num = 1000;

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nShutting down end device...\n");
        running = false;
    }
}

// Initialize services
void init_services() {
    // HTTP service
    services[service_count].port = HTTP_PORT;
    services[service_count].protocol = TRANSPORT_TCP;
    services[service_count].active = true;
    services[service_count].handler = http_handler;
    service_count++;
    
    // DNS service
    services[service_count].port = DNS_PORT;
    services[service_count].protocol = TRANSPORT_UDP;
    services[service_count].active = true;
    services[service_count].handler = dns_handler;
    service_count++;
    
    printf("Services initialized: HTTP (port %d), DNS (port %d)\n", HTTP_PORT, DNS_PORT);
}

// Find service by port
AppService* find_service(uint16_t port, transport_protocol_t protocol) {
    for (int i = 0; i < service_count; i++) {
        if (services[i].port == port && services[i].protocol == protocol && services[i].active) {
            return &services[i];
        }
    }
    return NULL;
}

// TCP connection management
TCPConnection* find_tcp_connection(const char *remote_ip, uint16_t remote_port, uint16_t local_port) {
    pthread_mutex_lock(&transport_mutex);
    
    for (int i = 0; i < tcp_conn_count; i++) {
        if (strcmp(tcp_connections[i].remote_ip, remote_ip) == 0 &&
            tcp_connections[i].remote_port == remote_port &&
            tcp_connections[i].local_port == local_port) {
            pthread_mutex_unlock(&transport_mutex);
            return &tcp_connections[i];
        }
    }
    
    pthread_mutex_unlock(&transport_mutex);
    return NULL;
}

TCPConnection* create_tcp_connection(const char *remote_ip, uint16_t remote_port, uint16_t local_port) {
    pthread_mutex_lock(&transport_mutex);
    
    if (tcp_conn_count >= 8) {
        pthread_mutex_unlock(&transport_mutex);
        return NULL;
    }
    
    TCPConnection *conn = &tcp_connections[tcp_conn_count++];
    strcpy(conn->remote_ip, remote_ip);
    conn->remote_port = remote_port;
    conn->local_port = local_port;
    conn->state = TCP_CLOSED;
    conn->seq_num = next_seq_num;
    conn->ack_num = 0;
    conn->expected_seq = 0;
    conn->window_start = 0;
    conn->window_next_seq = 0;
    conn->window_size = MAX_WINDOW_SIZE;
    conn->last_activity = time(NULL);
    pthread_mutex_init(&conn->conn_mutex, NULL);
    
    // Initialize sliding window
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        conn->window[i].state = FRAME_READY;
        conn->window[i].retries = 0;
    }
    
    next_seq_num += 1000;
    
    pthread_mutex_unlock(&transport_mutex);
    return conn;
}

char* get_gateway_ip(const char *dest_ip);
char* find_mac_for_ip(const char *ip_address);
void send_arp_request(const char *target_ip);
void send_udp_packet(const char *dest_ip, uint16_t src_port, uint16_t dst_port,
                    const void *data, int data_size);

// Go-Back-N: Send window
void send_tcp_window(TCPConnection *conn, const char *dest_mac) {
    pthread_mutex_lock(&conn->conn_mutex);
    
    int sent = 0;
    for (int i = 0; i < conn->window_size; i++) {
        int idx = (conn->window_start + i) % MAX_WINDOW_SIZE;
        
        if (conn->window[idx].state == FRAME_READY) {
            // Send the frame
            IPPacket ip;
            create_ip_packet(&ip, my_ip, conn->remote_ip, PROTO_TCP, 
                           &conn->window[idx].packet, sizeof(TCPPacket));
            
            EthernetFrame frame;
            create_ethernet_frame(&frame, dest_mac, my_mac, PROTO_IP, &ip, sizeof(IPPacket));
            
            if (send_ethernet_frame(file_out, &frame)) {
                conn->window[idx].state = FRAME_SENT;
                conn->window[idx].send_time = time(NULL);
                sent++;
                printf("TCP_WINDOW: Sent frame %d (SEQ=%u)\n", idx, 
                       ntohl(conn->window[idx].packet.seq_num));
            }
        }
    }
    
    if (sent > 0) {
        printf("TCP_WINDOW: Sent %d frames\n", sent);
    }
    
    pthread_mutex_unlock(&conn->conn_mutex);
}

// Go-Back-N: Handle ACK
void handle_tcp_ack(TCPConnection *conn, uint32_t ack_num) {
    pthread_mutex_lock(&conn->conn_mutex);
    
    printf("TCP_ACK: Received ACK=%u\n", ack_num);
    
    // Mark frames as acknowledged
    int acked = 0;
    while (conn->window_start < conn->window_next_seq) {
        int idx = conn->window_start % MAX_WINDOW_SIZE;
        uint32_t seq = ntohl(conn->window[idx].packet.seq_num);
        
        if (seq < ack_num) {
            conn->window[idx].state = FRAME_ACKED;
            conn->window_start++;
            acked++;
        } else {
            break;
        }
    }
    
    if (acked > 0) {
        printf("TCP_ACK: Acknowledged %d frames, window start now %d\n", 
               acked, conn->window_start);
    }
    
    pthread_mutex_unlock(&conn->conn_mutex);
}

// Go-Back-N: Timeout and retransmit
void check_tcp_timeouts(TCPConnection *conn, const char *dest_mac) {
    pthread_mutex_lock(&conn->conn_mutex);
    
    time_t current_time = time(NULL);
    bool need_retransmit = false;
    
    for (int i = 0; i < conn->window_size; i++) {
        int idx = (conn->window_start + i) % MAX_WINDOW_SIZE;
        
        if (conn->window[idx].state == FRAME_SENT) {
            if (current_time - conn->window[idx].send_time > TIMEOUT_SEC) {
                need_retransmit = true;
                printf("TCP_TIMEOUT: Frame %d timed out\n", idx);
                break;
            }
        }
    }
    
    if (need_retransmit) {
        // Go-Back-N: Retransmit all unacked frames
        printf("TCP_RETRANSMIT: Go-Back-N retransmission\n");
        for (int i = 0; i < conn->window_size; i++) {
            int idx = (conn->window_start + i) % MAX_WINDOW_SIZE;
            if (conn->window[idx].state == FRAME_SENT) {
                conn->window[idx].state = FRAME_READY;
                conn->window[idx].retries++;
            }
        }
    }
    
    pthread_mutex_unlock(&conn->conn_mutex);
    
    if (need_retransmit) {
        send_tcp_window(conn, dest_mac);
    }
}

// Send TCP packet
void send_tcp_packet(const char *dest_ip, uint16_t src_port, uint16_t dst_port,
                    uint32_t seq, uint32_t ack, uint8_t flags,
                    const void *data, int data_size) {
    printf("\nTCP_SEND: Sending TCP packet to %s:%d\n", dest_ip, dst_port);
    
    // Determine next hop
    char *gateway = get_gateway_ip(dest_ip);
    char *next_hop_ip = gateway ? gateway : (char*)dest_ip;
    
    // Look up MAC address
    char *dest_mac = find_mac_for_ip(next_hop_ip);
    if (!dest_mac) {
        printf("TCP_ARP: No MAC for %s, sending ARP request first\n", next_hop_ip);
        send_arp_request(next_hop_ip);
        return;
    }
    
    // Create TCP packet
    TCPPacket tcp;
    create_tcp_packet(&tcp, src_port, dst_port, seq, ack, flags, data, data_size);
    print_tcp_packet(&tcp, "TCP_SEND");
    
    // For data packets, add to sliding window
    if (data_size > 0 && (flags & TCP_ACK) == 0) {
        TCPConnection *conn = find_tcp_connection(dest_ip, dst_port, src_port);
        if (!conn) {
            conn = create_tcp_connection(dest_ip, dst_port, src_port);
        }
        
        if (conn) {
            pthread_mutex_lock(&conn->conn_mutex);
            int idx = conn->window_next_seq % MAX_WINDOW_SIZE;
            memcpy(&conn->window[idx].packet, &tcp, sizeof(TCPPacket));
            conn->window[idx].state = FRAME_READY;
            conn->window_next_seq++;
            pthread_mutex_unlock(&conn->conn_mutex);
            
            send_tcp_window(conn, dest_mac);
            return;
        }
    }
    
    // Direct send for control packets (SYN, ACK, FIN)
    IPPacket ip;
    create_ip_packet(&ip, my_ip, dest_ip, PROTO_TCP, &tcp, sizeof(TCPPacket));
    
    EthernetFrame frame;
    create_ethernet_frame(&frame, dest_mac, my_mac, PROTO_IP, &ip, sizeof(IPPacket));
    
    if (send_ethernet_frame(file_out, &frame)) {
        printf("TCP_OK: Sent TCP packet\n");
    } else {
        printf("TCP_FAIL: Failed to send TCP packet\n");
    }
}

// Handle TCP packet
void handle_tcp_packet(TCPPacket *tcp, const char *source_ip) {
    uint16_t src_port = ntohs(tcp->source_port);
    uint16_t dst_port = ntohs(tcp->dest_port);
    uint32_t seq = ntohl(tcp->seq_num);
    uint32_t ack = ntohl(tcp->ack_num);
    
    printf("TCP_RECV: From %s:%d to port %d, SEQ=%u, ACK=%u, FLAGS=0x%02x\n",
           source_ip, src_port, dst_port, seq, ack, tcp->flags);
    
    // Find or create connection
    TCPConnection *conn = find_tcp_connection(source_ip, src_port, dst_port);
    
    // Handle based on flags
    if (tcp->flags & TCP_SYN) {
        if (tcp->flags & TCP_ACK) {
            // SYN-ACK received
            printf("TCP_SYNACK: Received SYN-ACK\n");
            if (conn && conn->state == TCP_SYN_SENT) {
                conn->state = TCP_ESTABLISHED;
                conn->ack_num = seq + 1;
                // Send ACK
                send_tcp_packet(source_ip, dst_port, src_port, 
                              conn->seq_num, conn->ack_num, TCP_ACK, NULL, 0);
            }
        } else {
            // SYN received - new connection request
            printf("TCP_SYN: New connection request\n");
            AppService *service = find_service(dst_port, TRANSPORT_TCP);
            if (service) {
                if (!conn) {
                    conn = create_tcp_connection(source_ip, src_port, dst_port);
                }
                if (conn) {
                    conn->state = TCP_SYN_RECEIVED;
                    conn->expected_seq = seq + 1;
                    conn->ack_num = seq + 1;
                    // Send SYN-ACK
                    send_tcp_packet(source_ip, dst_port, src_port,
                                  conn->seq_num, conn->ack_num, TCP_SYN | TCP_ACK, NULL, 0);
                    conn->seq_num++;
                }
            }
        }
    } else if (tcp->flags & TCP_ACK) {
        if (conn) {
            if (conn->state == TCP_SYN_RECEIVED) {
                conn->state = TCP_ESTABLISHED;
                printf("TCP_ESTABLISHED: Connection established\n");
            }
            
            // Handle ACK for sliding window
            handle_tcp_ack(conn, ack);
            
            // Process data if any
            if (tcp->payload_size > 0) {
                printf("TCP_DATA: Received %d bytes of data\n", tcp->payload_size);
                
                // Check sequence number (simple in-order delivery)
                if (seq == conn->expected_seq) {
                    conn->expected_seq = seq + tcp->payload_size;
                    
                    // Process data
                    AppService *service = find_service(dst_port, TRANSPORT_TCP);
                    if (service) {
                        char response[MAX_PACKET_SIZE];
                        int response_size = 0;
                        service->handler(tcp->payload, response, &response_size, (char*)source_ip);
                        
                        if (response_size > 0) {
                            // Send response
                            send_tcp_packet(source_ip, dst_port, src_port,
                                          conn->seq_num, conn->expected_seq, 
                                          TCP_ACK | TCP_PSH, response, response_size);
                            conn->seq_num += response_size;
                        }
                    }
                    
                    // Send ACK
                    send_tcp_packet(source_ip, dst_port, src_port,
                                  conn->seq_num, conn->expected_seq, TCP_ACK, NULL, 0);
                } else {
                    printf("TCP_OUT_OF_ORDER: Expected SEQ=%u, got SEQ=%u\n", 
                           conn->expected_seq, seq);
                    // Send duplicate ACK
                    send_tcp_packet(source_ip, dst_port, src_port,
                                  conn->seq_num, conn->expected_seq, TCP_ACK, NULL, 0);
                }
            }
        }
    } else if (tcp->flags & TCP_FIN) {
        printf("TCP_FIN: Connection close request\n");
        if (conn) {
            conn->state = TCP_FIN_WAIT_1;
            // Send ACK for FIN
            send_tcp_packet(source_ip, dst_port, src_port,
                          conn->seq_num, seq + 1, TCP_ACK, NULL, 0);
            // Send our FIN
            send_tcp_packet(source_ip, dst_port, src_port,
                          conn->seq_num, seq + 1, TCP_FIN | TCP_ACK, NULL, 0);
        }
    }
}

// Handle UDP packet
void handle_udp_packet(UDPPacket *udp, const char *source_ip) {
    uint16_t src_port = ntohs(udp->source_port);
    uint16_t dst_port = ntohs(udp->dest_port);
    
    printf("UDP_RECV: From %s:%d to port %d, %d bytes\n",
           source_ip, src_port, dst_port, udp->payload_size);
    
    // Check for DNS service
    AppService *service = find_service(dst_port, TRANSPORT_UDP);
    if (service) {
        char response[MAX_PACKET_SIZE];
        int response_size = 0;
        service->handler(udp->payload, response, &response_size, (char*)source_ip);
        
        if (response_size > 0) {
            // Send UDP response
            printf("UDP_REPLY: Sending response\n");
            send_udp_packet(source_ip, dst_port, src_port, response, response_size);
        }
    }
}

// Send UDP packet
void send_udp_packet(const char *dest_ip, uint16_t src_port, uint16_t dst_port,
                    const void *data, int data_size) {
    printf("\nUDP_SEND: Sending UDP packet to %s:%d\n", dest_ip, dst_port);
    
    // Determine next hop
    char *gateway = get_gateway_ip(dest_ip);
    char *next_hop_ip = gateway ? gateway : (char*)dest_ip;
    
    // Look up MAC address
    char *dest_mac = find_mac_for_ip(next_hop_ip);
    if (!dest_mac) {
        printf("UDP_ARP: No MAC for %s, sending ARP request first\n", next_hop_ip);
        send_arp_request(next_hop_ip);
        return;
    }
    
    // Create UDP packet
    UDPPacket udp;
    create_udp_packet(&udp, src_port, dst_port, data, data_size);
    
    // Create IP packet
    IPPacket ip;
    create_ip_packet(&ip, my_ip, dest_ip, PROTO_UDP, &udp, sizeof(UDPPacket));
    
    // Create Ethernet frame
    EthernetFrame frame;
    create_ethernet_frame(&frame, dest_mac, my_mac, PROTO_IP, &ip, sizeof(IPPacket));
    
    if (send_ethernet_frame(file_out, &frame)) {
        printf("UDP_OK: Sent UDP packet\n");
    } else {
        printf("UDP_FAIL: Failed to send UDP packet\n");
    }
}

// ARP functions
char* find_mac_for_ip(const char *ip_address) {
    pthread_mutex_lock(&arp_mutex);
    
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip_address, ip_address) == 0) {
            static char mac[MAC_ADDR_LEN];
            strncpy(mac, arp_table[i].mac_address, MAC_ADDR_LEN - 1);
            mac[MAC_ADDR_LEN - 1] = '\0';
            pthread_mutex_unlock(&arp_mutex);
            return mac;
        }
    }
    
    pthread_mutex_unlock(&arp_mutex);
    return NULL;
}

void update_arp_table(const char *ip_address, const char *mac_address) {
    pthread_mutex_lock(&arp_mutex);
    
    // Check if entry exists
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip_address, ip_address) == 0) {
            strncpy(arp_table[i].mac_address, mac_address, MAC_ADDR_LEN - 1);
            arp_table[i].mac_address[MAC_ADDR_LEN - 1] = '\0';
            arp_table[i].last_seen = time(NULL);
            printf("ARP_UPDATE: %s -> %s\n", ip_address, mac_address);
            pthread_mutex_unlock(&arp_mutex);
            return;
        }
    }
    
    // Add new entry
    if (arp_table_size < MAX_ARP_TABLE_SIZE) {
        strncpy(arp_table[arp_table_size].ip_address, ip_address, IP_ADDR_LEN - 1);
        arp_table[arp_table_size].ip_address[IP_ADDR_LEN - 1] = '\0';
        strncpy(arp_table[arp_table_size].mac_address, mac_address, MAC_ADDR_LEN - 1);
        arp_table[arp_table_size].mac_address[MAC_ADDR_LEN - 1] = '\0';
        arp_table[arp_table_size].last_seen = time(NULL);
        arp_table[arp_table_size].is_static = false;
        arp_table_size++;
        printf("ARP_ADD: %s -> %s\n", ip_address, mac_address);
    } else {
        printf("ARP_FULL: Cannot add %s\n", ip_address);
    }
    
    pthread_mutex_unlock(&arp_mutex);
}

void send_arp_request(const char *target_ip) {
    printf("ARP_REQ: Sending ARP request for %s\n", target_ip);
    
    ARPPacket arp;
    create_arp_packet(&arp, 1, my_mac, my_ip, "00:00:00:00:00:00", target_ip);
    
    EthernetFrame frame;
    create_ethernet_frame(&frame, BROADCAST_MAC, my_mac, PROTO_ARP, &arp, sizeof(ARPPacket));
    
    if (send_ethernet_frame(file_out, &frame)) {
        printf("ARP_REQ_OK: Sent ARP request for %s\n", target_ip);
    } else {
        printf("ARP_REQ_FAIL: Failed to send ARP request for %s\n", target_ip);
    }
}

void handle_arp_packet(ARPPacket *arp) {
    uint16_t opcode = ntohs(arp->opcode);
    
    printf("ARP_RECV: %s from %s (%s) asking for %s\n",
           opcode == 1 ? "REQUEST" : "REPLY",
           arp->sender_ip, arp->sender_mac, arp->target_ip);
    
    // Always update ARP table with sender info
    update_arp_table(arp->sender_ip, arp->sender_mac);
    
    if (opcode == 1) { // ARP Request
        if (strcmp(arp->target_ip, my_ip) == 0) {
            printf("ARP_REPLY: Target IP %s is mine, sending reply\n", arp->target_ip);
            
            // Send ARP reply
            ARPPacket reply;
            create_arp_packet(&reply, 2, my_mac, my_ip, arp->sender_mac, arp->sender_ip);
            
            EthernetFrame frame;
            create_ethernet_frame(&frame, arp->sender_mac, my_mac, PROTO_ARP, 
                                 &reply, sizeof(ARPPacket));
            
            if (send_ethernet_frame(file_out, &frame)) {
                printf("ARP_REPLY_OK: Sent ARP reply to %s\n", arp->sender_ip);
            } else {
                printf("ARP_REPLY_FAIL: Failed to send ARP reply to %s\n", arp->sender_ip);
            }
        } else {
            printf("ARP_IGNORE: Target IP %s not mine (%s)\n", arp->target_ip, my_ip);
        }
    } else if (opcode == 2) { // ARP Reply
        printf("ARP_REPLY_RECV: From %s (%s)\n", arp->sender_ip, arp->sender_mac);
    }
}

// Get gateway IP for routing
char* get_gateway_ip(const char *dest_ip) {
    // Simple logic: if destination is not on same network, use .1 as gateway
    if (!is_same_network(dest_ip, my_ip, my_netmask)) {
        static char gateway[IP_ADDR_LEN];
        char network[IP_ADDR_LEN];
        get_network_address(my_ip, my_netmask, network);
        
        struct in_addr net;
        inet_aton(network, &net);
        net.s_addr |= htonl(1); // Set last octet to 1
        
        strcpy(gateway, inet_ntoa(net));
        
        printf("GATEWAY: Dest %s not on local network, using gateway %s\n", dest_ip, gateway);
        return gateway;
    }
    
    printf("DIRECT: Dest %s is on local network\n", dest_ip);
    return NULL; // Direct delivery
}

void send_ping(const char *dest_ip) {
    printf("\nPING_START: Sending ping to %s\n", dest_ip);
    
    // Ping uses ICMP, but we'll simulate with UDP for simplicity
    char ping_data[] = "PING";
    uint16_t src_port = get_ephemeral_port();
    
    send_udp_packet(dest_ip, src_port, 0, ping_data, strlen(ping_data));
}

void send_http_request(const char *dest_ip) {
    printf("\nHTTP_START: Sending HTTP request to %s\n", dest_ip);
    
    uint16_t src_port = get_ephemeral_port();
    
    // Create or find TCP connection
    TCPConnection *conn = find_tcp_connection(dest_ip, HTTP_PORT, src_port);
    if (!conn) {
        conn = create_tcp_connection(dest_ip, HTTP_PORT, src_port);
    }
    
    if (!conn) {
        printf("HTTP_ERROR: Failed to create connection\n");
        return;
    }
    
    // Send SYN to establish connection
    conn->state = TCP_SYN_SENT;
    send_tcp_packet(dest_ip, src_port, HTTP_PORT, conn->seq_num, 0, TCP_SYN, NULL, 0);
    conn->seq_num++;
    
    // In a real implementation, we would wait for connection establishment
    // For now, queue the HTTP request
    char http_request[] = "GET / HTTP/1.1\r\nHost: server\r\n\r\n";
    
    // This would normally be sent after connection is established
    printf("HTTP_QUEUED: Request queued for transmission\n");
}

void send_dns_query(const char *dest_ip, const char *hostname) {
    printf("\nDNS_START: Querying %s for %s\n", dest_ip, hostname);
    
    uint16_t src_port = get_ephemeral_port();
    char query[256];
    snprintf(query, sizeof(query), "DNS_QUERY:%s", hostname);
    
    send_udp_packet(dest_ip, src_port, DNS_PORT, query, strlen(query));
}

void handle_ip_packet(IPPacket *ip) {
    printf("IP_RECV: %s -> %s, Protocol=%d, TTL=%d\n", 
           ip->source_ip, ip->dest_ip, ip->protocol, ip->ttl);
    
    // Check if packet is for us
    if (strcmp(ip->dest_ip, my_ip) != 0 && strcmp(ip->dest_ip, BROADCAST_IP) != 0) {
        printf("IP_IGNORE: Packet not for us (my IP: %s)\n", my_ip);
        return;
    }
    
    if (ip->protocol == PROTO_TCP) {
        TCPPacket *tcp = (TCPPacket*)ip->payload;
        handle_tcp_packet(tcp, ip->source_ip);
    } else if (ip->protocol == PROTO_UDP) {
        UDPPacket *udp = (UDPPacket*)ip->payload;
        handle_udp_packet(udp, ip->source_ip);
    }
}

// Main frame processing
void process_frames() {
    EthernetFrame frame;
    if (receive_ethernet_frame(file_in, &frame)) {
        printf("\n*** DEVICE: Received frame ***\n");
        printf("    From: %s\n", frame.source_mac);
        printf("    To: %s\n", frame.dest_mac);
        printf("    Type: 0x%04x\n", frame.ethertype);
        print_ethernet_frame(&frame, "Device");
        
        if (frame.ethertype == PROTO_ARP) {
            printf("FRAME_TYPE: ARP packet\n");
            ARPPacket *arp = (ARPPacket*)frame.payload;
            handle_arp_packet(arp);
        } else if (frame.ethertype == PROTO_IP) {
            printf("FRAME_TYPE: IP packet\n");
            IPPacket *ip = (IPPacket*)frame.payload;
            handle_ip_packet(ip);
        } else {
            printf("FRAME_TYPE: Unknown ethertype 0x%04x\n", frame.ethertype);
        }
    }
    
    // Check TCP timeouts for all connections
    pthread_mutex_lock(&transport_mutex);
    for (int i = 0; i < tcp_conn_count; i++) {
        if (tcp_connections[i].state == TCP_ESTABLISHED) {
            // Get destination MAC for retransmissions
            char *dest_mac = find_mac_for_ip(tcp_connections[i].remote_ip);
            if (dest_mac) {
                check_tcp_timeouts(&tcp_connections[i], dest_mac);
            }
        }
    }
    pthread_mutex_unlock(&transport_mutex);
}

// Print tables
void print_arp_table() {
    pthread_mutex_lock(&arp_mutex);
    
    printf("\n--- ARP Table ---\n");
    printf("IP Address      | MAC Address       | Age (sec)\n");
    printf("-------------------------------------------\n");
    
    time_t current_time = time(NULL);
    for (int i = 0; i < arp_table_size; i++) {
        printf("%-15s | %-17s | %ld\n", 
               arp_table[i].ip_address, 
               arp_table[i].mac_address,
               current_time - arp_table[i].last_seen);
    }
    
    if (arp_table_size == 0) {
        printf("(No entries)\n");
    }
    
    printf("-------------------------------------------\n");
    pthread_mutex_unlock(&arp_mutex);
}

void print_network_config() {
    printf("\n--- Network Configuration ---\n");
    printf("Device ID: %s\n", device_id);
    printf("MAC Address: %s\n", my_mac);
    printf("IP Address: %s\n", my_ip);
    printf("Netmask: %s\n", my_netmask);
    printf("Connected to: %s (port %d)\n", conn_device, port_num);
    printf("Files: %s <-> %s\n", file_in, file_out);
    
    // Calculate network and gateway
    char network[IP_ADDR_LEN];
    get_network_address(my_ip, my_netmask, network);
    printf("Network: %s/%s\n", network, my_netmask);
    
    struct in_addr net;
    inet_aton(network, &net);
    net.s_addr |= htonl(1);
    printf("Default Gateway: %s\n", inet_ntoa(net));
    printf("-----------------------------\n");
}

void print_connections() {
    pthread_mutex_lock(&transport_mutex);
    
    printf("\n--- TCP Connections ---\n");
    printf("Remote IP:Port  | Local Port | State        | SEQ    | ACK    | Window\n");
    printf("------------------------------------------------------------------------\n");
    
    for (int i = 0; i < tcp_conn_count; i++) {
        TCPConnection *conn = &tcp_connections[i];
        const char *state_str = "UNKNOWN";
        
        switch (conn->state) {
            case TCP_CLOSED: state_str = "CLOSED"; break;
            case TCP_LISTEN: state_str = "LISTEN"; break;
            case TCP_SYN_SENT: state_str = "SYN_SENT"; break;
            case TCP_SYN_RECEIVED: state_str = "SYN_RECEIVED"; break;
            case TCP_ESTABLISHED: state_str = "ESTABLISHED"; break;
            case TCP_FIN_WAIT_1: state_str = "FIN_WAIT_1"; break;
            case TCP_FIN_WAIT_2: state_str = "FIN_WAIT_2"; break;
            case TCP_CLOSE_WAIT: state_str = "CLOSE_WAIT"; break;
            case TCP_CLOSING: state_str = "CLOSING"; break;
            case TCP_LAST_ACK: state_str = "LAST_ACK"; break;
            case TCP_TIME_WAIT: state_str = "TIME_WAIT"; break;
        }
        
        printf("%s:%-5d | %-10d | %-12s | %-6u | %-6u | %d-%d\n",
               conn->remote_ip, conn->remote_port, conn->local_port,
               state_str, conn->seq_num, conn->ack_num,
               conn->window_start, conn->window_next_seq);
    }
    
    if (tcp_conn_count == 0) {
        printf("(No connections)\n");
    }
    
    printf("------------------------------------------------------------------------\n");
    pthread_mutex_unlock(&transport_mutex);
}

void print_services() {
    printf("\n--- Active Services ---\n");
    printf("Port | Protocol | Description\n");
    printf("------------------------------\n");
    
    for (int i = 0; i < service_count; i++) {
        if (services[i].active) {
            const char *proto = services[i].protocol == TRANSPORT_TCP ? "TCP" : "UDP";
            const char *desc = "";
            
            if (services[i].port == HTTP_PORT) desc = "HTTP Server";
            else if (services[i].port == DNS_PORT) desc = "DNS Server";
            
            printf("%-4d | %-8s | %s\n", services[i].port, proto, desc);
        }
    }
    
    printf("------------------------------\n");
}

// Command thread
void *command_thread(void *arg) {
    char cmd[512];
    
    while (running) {
        printf("\nDevice[%s]> ", device_id);
        fflush(stdout);
        
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }
        
        cmd[strcspn(cmd, "\n")] = 0;
        
        if (strcmp(cmd, "show arp") == 0) {
            print_arp_table();
        } else if (strcmp(cmd, "show config") == 0) {
            print_network_config();
        } else if (strcmp(cmd, "show connections") == 0) {
            print_connections();
        } else if (strcmp(cmd, "show services") == 0) {
            print_services();
        } else if (strncmp(cmd, "ping", 4) == 0) {
            char dest_ip[IP_ADDR_LEN];
            if (sscanf(cmd + 5, "%15s", dest_ip) == 1) {
                send_ping(dest_ip);
            } else {
                printf("Usage: ping <dest_ip>\n");
                printf("Example: ping 192.168.2.100\n");
            }
        } else if (strncmp(cmd, "http", 4) == 0) {
            char dest_ip[IP_ADDR_LEN];
            if (sscanf(cmd + 5, "%15s", dest_ip) == 1) {
                send_http_request(dest_ip);
            } else {
                printf("Usage: http <dest_ip>\n");
                printf("Example: http 192.168.2.100\n");
            }
        } else if (strncmp(cmd, "dns", 3) == 0) {
            char dest_ip[IP_ADDR_LEN], hostname[256];
            if (sscanf(cmd + 4, "%15s %255s", dest_ip, hostname) == 2) {
                send_dns_query(dest_ip, hostname);
            } else {
                printf("Usage: dns <dns_server_ip> <hostname>\n");
                printf("Example: dns 192.168.1.100 example.com\n");
            }
        } else if (strncmp(cmd, "tcp", 3) == 0) {
            char dest_ip[IP_ADDR_LEN];
            int dest_port;
            char data[256];
            if (sscanf(cmd + 4, "%15s %d %[^\n]", dest_ip, &dest_port, data) >= 2) {
                uint16_t src_port = get_ephemeral_port();
                
                // For testing: send raw TCP data
                if (strlen(data) > 0) {
                    send_tcp_packet(dest_ip, src_port, dest_port, 
                                  next_seq_num++, 0, TCP_PSH | TCP_ACK, 
                                  data, strlen(data));
                } else {
                    // Just establish connection
                    TCPConnection *conn = create_tcp_connection(dest_ip, dest_port, src_port);
                    if (conn) {
                        conn->state = TCP_SYN_SENT;
                        send_tcp_packet(dest_ip, src_port, dest_port, 
                                      conn->seq_num, 0, TCP_SYN, NULL, 0);
                        conn->seq_num++;
                    }
                }
            } else {
                printf("Usage: tcp <dest_ip> <dest_port> [data]\n");
                printf("Example: tcp 192.168.2.100 80 \"GET / HTTP/1.0\\r\\n\\r\\n\"\n");
            }
        } else if (strncmp(cmd, "udp", 3) == 0) {
            char dest_ip[IP_ADDR_LEN];
            int dest_port;
            char data[256];
            if (sscanf(cmd + 4, "%15s %d %[^\n]", dest_ip, &dest_port, data) == 3) {
                uint16_t src_port = get_ephemeral_port();
                send_udp_packet(dest_ip, src_port, dest_port, data, strlen(data));
            } else {
                printf("Usage: udp <dest_ip> <dest_port> <data>\n");
                printf("Example: udp 192.168.2.100 53 \"DNS_QUERY:example.com\"\n");
            }
        } else if (strncmp(cmd, "arp", 3) == 0) {
            char target_ip[IP_ADDR_LEN];
            if (sscanf(cmd + 4, "%15s", target_ip) == 1) {
                send_arp_request(target_ip);
            } else {
                printf("Usage: arp <target_ip>\n");
                printf("Example: arp 192.168.1.1\n");
            }
        } else if (strcmp(cmd, "debug") == 0) {
            printf("\n=== Debug Info ===\n");
            print_network_config();
            print_arp_table();
            print_connections();
            print_services();
            printf("Next sequence number: %u\n", next_seq_num);
        } else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  show arp           - Display ARP table\n");
            printf("  show config        - Display network configuration\n");
            printf("  show connections   - Display TCP connections\n");
            printf("  show services      - Display active services\n");
            printf("  ping <dest_ip>     - Send ping to destination\n");
            printf("  http <dest_ip>     - Send HTTP request\n");
            printf("  dns <server> <host>- Send DNS query\n");
            printf("  tcp <ip> <port>    - Connect to TCP port\n");
            printf("  udp <ip> <port> <data> - Send UDP packet\n");
            printf("  arp <target_ip>    - Send ARP request\n");
            printf("  debug              - Show all debug information\n");
            printf("  help               - Show this help\n");
            printf("  exit               - Exit the device\n");
            printf("\nExamples:\n");
            printf("  arp 192.168.1.1    - ARP for gateway\n");
            printf("  ping 192.168.2.100 - Ping device on other subnet\n");
            printf("  http 192.168.2.100 - HTTP request to device\n");
            printf("  dns 192.168.1.100 google.com - DNS query\n");
        } else if (strcmp(cmd, "exit") == 0) {
            running = false;
            break;
        } else if (strlen(cmd) > 0) {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
    }
    
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <device_id> <conn_device> <port_num> <ip_address> <netmask>\n", argv[0]);
        printf("Example: %s device1 router1 1 192.168.1.100 255.255.255.0\n", argv[0]);
        printf("Example: %s device2 router1 2 192.168.2.100 255.255.255.0\n", argv[0]);
        return 1;
    }
    
    strncpy(device_id, argv[1], DEVICE_ID_MAX - 1);
    device_id[DEVICE_ID_MAX - 1] = '\0';
    strncpy(conn_device, argv[2], DEVICE_ID_MAX - 1);
    conn_device[DEVICE_ID_MAX - 1] = '\0';
    port_num = atoi(argv[3]);
    strncpy(my_ip, argv[4], IP_ADDR_LEN - 1);
    my_ip[IP_ADDR_LEN - 1] = '\0';
    strncpy(my_netmask, argv[5], IP_ADDR_LEN - 1);
    my_netmask[IP_ADDR_LEN - 1] = '\0';
    
    signal(SIGINT, handle_signal);
    srand(time(NULL) ^ (getpid() << 16));
    
    generate_random_mac(my_mac);
    
    printf("\n=== Initializing Device %s ===\n", device_id);
    printf("MAC: %s\n", my_mac);
    printf("IP: %s/%s\n", my_ip, my_netmask);
    printf("Connected to: %s (port %d)\n", conn_device, port_num);
    
    // Create communication files
    get_file_paths(file_in, file_out, device_id, conn_device, port_num);
    
    if (!init_comm_file(file_in) || !init_comm_file(file_out)) {
        printf("Failed to initialize communication files\n");
        return 1;
    }
    
    // Initialize services
    init_services();
    
    pthread_t cmd_tid;
    pthread_create(&cmd_tid, NULL, command_thread, NULL);
    
    printf("\n=== Device %s started ===\n", device_id);
    printf("Type 'help' for available commands.\n");
    printf("Use 'show config' to see network configuration.\n");
    printf("Use 'show services' to see active services.\n");
    printf("Use 'debug' to see all debug info.\n\n");
    
    // Main loop
    printf("Device main loop started...\n");
    while (running) {
        process_frames();
        usleep(100000); // 100ms
    }
    
    // Cleanup
    pthread_join(cmd_tid, NULL);
    pthread_mutex_destroy(&arp_mutex);
    pthread_mutex_destroy(&transport_mutex);
    
    // Clean up TCP connections
    for (int i = 0; i < tcp_conn_count; i++) {
        pthread_mutex_destroy(&tcp_connections[i].conn_mutex);
    }
    
    printf("End device shut down\n");
    return 0;
}