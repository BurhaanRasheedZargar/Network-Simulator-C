#include "common.h"

Port ports[MAX_CONNECTED_PORTS];
int num_ports = 0;
ARPEntry arp_table[MAX_ARP_TABLE_SIZE];
int arp_table_size = 0;
RoutingEntry routing_table[MAX_ROUTING_TABLE_SIZE];
int routing_table_size = 0;
bool running = true;
bool rip_enabled = false;
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t routing_mutex = PTHREAD_MUTEX_INITIALIZER;
char router_id[DEVICE_ID_MAX];
char router_macs[MAX_CONNECTED_PORTS][MAC_ADDR_LEN];
time_t last_rip_update = 0;

// RIP thread variables
pthread_t rip_thread;
bool rip_thread_running = false;

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nShutting down router...\n");
        running = false;
        rip_thread_running = false;
    }
}

// Add a port to the router
bool add_port(const char *device_id, int port_num, const char *ip_addr, const char *netmask) {
    if (num_ports >= MAX_CONNECTED_PORTS) {
        printf("Maximum number of ports reached\n");
        return false;
    }
    
    printf("\n=== Adding port %d for device '%s' ===\n", port_num, device_id);
    
    char file_in[100], file_out[100];
    get_file_paths(file_in, file_out, router_id, device_id, port_num);
    
    if (!init_comm_file(file_in) || !init_comm_file(file_out)) {
        printf("Failed to initialize communication files for port %d\n", port_num);
        return false;
    }
    
    ports[num_ports].port_num = port_num;
    strncpy(ports[num_ports].device_id, device_id, DEVICE_ID_MAX - 1);
    ports[num_ports].device_id[DEVICE_ID_MAX - 1] = '\0';
    strncpy(ports[num_ports].file_in, file_in, sizeof(ports[num_ports].file_in) - 1);
    ports[num_ports].file_in[sizeof(ports[num_ports].file_in) - 1] = '\0';
    strncpy(ports[num_ports].file_out, file_out, sizeof(ports[num_ports].file_out) - 1);
    ports[num_ports].file_out[sizeof(ports[num_ports].file_out) - 1] = '\0';
    strncpy(ports[num_ports].ip_address, ip_addr, IP_ADDR_LEN - 1);
    ports[num_ports].ip_address[IP_ADDR_LEN - 1] = '\0';
    strncpy(ports[num_ports].netmask, netmask, IP_ADDR_LEN - 1);
    ports[num_ports].netmask[IP_ADDR_LEN - 1] = '\0';
    ports[num_ports].connected = true;
    
    // Generate a unique MAC address for this router port
    generate_random_mac(router_macs[num_ports]);
    
    // Add directly connected network to routing table
    pthread_mutex_lock(&routing_mutex);
    if (routing_table_size < MAX_ROUTING_TABLE_SIZE) {
        char network[IP_ADDR_LEN];
        get_network_address(ip_addr, netmask, network);
        
        strcpy(routing_table[routing_table_size].network, network);
        strcpy(routing_table[routing_table_size].netmask, netmask);
        strcpy(routing_table[routing_table_size].next_hop, "0.0.0.0");
        strcpy(routing_table[routing_table_size].interface, device_id);
        routing_table[routing_table_size].metric = 0;
        routing_table[routing_table_size].is_static = true;
        routing_table[routing_table_size].last_update = time(NULL);
        routing_table_size++;
        printf("Added route: %s/%s via %s (direct)\n", network, netmask, device_id);
    }
    pthread_mutex_unlock(&routing_mutex);
    
    printf("Router port %d configured:\n", port_num);
    printf("  IP: %s/%s\n", ip_addr, netmask);
    printf("  MAC: %s\n", router_macs[num_ports]);
    printf("  Interface: %s\n", device_id);
    printf("  Files: %s <-> %s\n", file_in, file_out);
    
    num_ports++;
    return true;
}

// Update ARP table
void update_arp_table(const char *ip_address, const char *mac_address) {
    pthread_mutex_lock(&arp_mutex);
    
    // Check if entry exists
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip_address, ip_address) == 0) {
            strcpy(arp_table[i].mac_address, mac_address);
            arp_table[i].last_seen = time(NULL);
            printf("ARP_UPDATE: %s -> %s\n", ip_address, mac_address);
            pthread_mutex_unlock(&arp_mutex);
            return;
        }
    }
    
    // Add new entry
    if (arp_table_size < MAX_ARP_TABLE_SIZE) {
        strcpy(arp_table[arp_table_size].ip_address, ip_address);
        strcpy(arp_table[arp_table_size].mac_address, mac_address);
        arp_table[arp_table_size].last_seen = time(NULL);
        arp_table[arp_table_size].is_static = false;
        arp_table_size++;
        printf("ARP_ADD: %s -> %s\n", ip_address, mac_address);
    } else {
        printf("ARP_FULL: Cannot add %s\n", ip_address);
    }
    
    pthread_mutex_unlock(&arp_mutex);
}

// Find MAC address for IP
char* find_mac_for_ip(const char *ip_address) {
    pthread_mutex_lock(&arp_mutex);
    
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip_address, ip_address) == 0) {
            static char mac[MAC_ADDR_LEN];
            strcpy(mac, arp_table[i].mac_address);
            pthread_mutex_unlock(&arp_mutex);
            return mac;
        }
    }
    
    pthread_mutex_unlock(&arp_mutex);
    return NULL;
}

// Send ARP request
void send_arp_request(const char *target_ip, int port_index) {
    if (port_index < 0 || port_index >= num_ports) {
        printf("ARP_ERROR: Invalid port index %d\n", port_index);
        return;
    }
    
    printf("ARP_REQ: Sending ARP request for %s on port %d\n", target_ip, port_index);
    
    ARPPacket arp;
    create_arp_packet(&arp, 1, router_macs[port_index], ports[port_index].ip_address,
                     "00:00:00:00:00:00", target_ip);
    
    EthernetFrame frame;
    create_ethernet_frame(&frame, BROADCAST_MAC, router_macs[port_index], 
                         PROTO_ARP, &arp, sizeof(ARPPacket));
    
    if (send_ethernet_frame(ports[port_index].file_out, &frame)) {
        printf("ARP_REQ_OK: Sent ARP request for %s\n", target_ip);
    } else {
        printf("ARP_REQ_FAIL: Failed to send ARP request for %s\n", target_ip);
    }
}

// Handle ARP packet
void handle_arp_packet(ARPPacket *arp, int port_index) {
    uint16_t opcode = ntohs(arp->opcode);
    
    printf("ARP_RECV: %s from %s (%s) asking for %s\n", 
           opcode == 1 ? "REQUEST" : "REPLY",
           arp->sender_ip, arp->sender_mac, arp->target_ip);
    
    // Always update ARP table with sender info
    update_arp_table(arp->sender_ip, arp->sender_mac);
    
    if (opcode == 1) { // ARP Request
        // Check if target IP is one of our interfaces
        if (strcmp(ports[port_index].ip_address, arp->target_ip) == 0) {
            printf("ARP_REPLY: Target IP %s is ours, sending reply\n", arp->target_ip);
            
            // Send ARP reply
            ARPPacket reply;
            create_arp_packet(&reply, 2, router_macs[port_index], arp->target_ip,
                             arp->sender_mac, arp->sender_ip);
            
            EthernetFrame frame;
            create_ethernet_frame(&frame, arp->sender_mac, router_macs[port_index],
                                 PROTO_ARP, &reply, sizeof(ARPPacket));
            
            if (send_ethernet_frame(ports[port_index].file_out, &frame)) {
                printf("ARP_REPLY_OK: Sent ARP reply to %s\n", arp->sender_ip);
            } else {
                printf("ARP_REPLY_FAIL: Failed to send ARP reply\n");
            }
        } else {
            printf("ARP_IGNORE: Target IP %s not for this interface (%s)\n", 
                   arp->target_ip, ports[port_index].ip_address);
        }
    } else if (opcode == 2) { // ARP Reply
        printf("ARP_REPLY_RECV: From %s (%s)\n", arp->sender_ip, arp->sender_mac);
    }
}

// Send RIP update
void send_rip_update(int port_index) {
    printf("RIP_UPDATE: Sending RIP update on port %d\n", port_index);
    
    RIPPacket rip;
    create_rip_packet(&rip, RIP_RESPONSE);
    
    pthread_mutex_lock(&routing_mutex);
    
    // Add all routes to RIP packet (except those learned from this interface)
    for (int i = 0; i < routing_table_size; i++) {
        // Don't advertise routes back to the interface they came from (split horizon)
        if (strcmp(routing_table[i].interface, ports[port_index].device_id) != 0) {
            int metric = routing_table[i].metric + 1;
            if (metric > RIP_INFINITY) metric = RIP_INFINITY;
            
            add_rip_entry(&rip, routing_table[i].network, routing_table[i].netmask,
                         "0.0.0.0", metric);
        }
    }
    
    pthread_mutex_unlock(&routing_mutex);
    
    if (rip.entry_count == 0) {
        printf("RIP_UPDATE: No routes to advertise on port %d\n", port_index);
        return;
    }
    
    // Create UDP packet for RIP
    UDPPacket udp;
    int rip_size = RIP_HEADER_SIZE + (rip.entry_count * RIP_ENTRY_SIZE);
    create_udp_packet(&udp, RIP_PORT, RIP_PORT, &rip, rip_size);
    
    // Create IP packet
    IPPacket ip;
    create_ip_packet(&ip, ports[port_index].ip_address, BROADCAST_IP, 
                    PROTO_UDP, &udp, UDP_HEADER_SIZE + rip_size);
    
    // Create Ethernet frame
    EthernetFrame frame;
    create_ethernet_frame(&frame, BROADCAST_MAC, router_macs[port_index],
                         PROTO_IP, &ip, IP_HEADER_SIZE + UDP_HEADER_SIZE + rip_size);
    
    if (send_ethernet_frame(ports[port_index].file_out, &frame)) {
        printf("RIP_UPDATE_OK: Sent RIP update with %d routes on port %d\n", 
               rip.entry_count, port_index);
    } else {
        printf("RIP_UPDATE_FAIL: Failed to send RIP update\n");
    }
}

// Handle RIP packet
void handle_rip_packet(RIPPacket *rip, const char *source_ip, int port_index) {
    printf("RIP_RECV: Received RIP %s from %s with %d entries\n",
           rip->header.command == RIP_REQUEST ? "REQUEST" : "RESPONSE",
           source_ip, rip->entry_count);
    
    if (rip->header.version != RIP_VERSION) {
        printf("RIP_ERROR: Unsupported RIP version %d\n", rip->header.version);
        return;
    }
    
    if (rip->header.command == RIP_REQUEST) {
        // Send RIP response
        send_rip_update(port_index);
        return;
    }
    
    // Process RIP response
    pthread_mutex_lock(&routing_mutex);
    
    for (int i = 0; i < rip->entry_count; i++) {
        RIPEntry *entry = &rip->entries[i];
        uint32_t metric = ntohl(entry->metric);
        
        if (metric >= RIP_INFINITY) continue;
        
        // Check if route already exists
        bool found = false;
        for (int j = 0; j < routing_table_size; j++) {
            if (strcmp(routing_table[j].network, entry->ip_addr) == 0 &&
                strcmp(routing_table[j].netmask, entry->subnet_mask) == 0) {
                found = true;
                
                // Update if better metric or same next hop
                if (!routing_table[j].is_static && 
                    (metric + 1 < routing_table[j].metric ||
                     strcmp(routing_table[j].next_hop, source_ip) == 0)) {
                    routing_table[j].metric = metric + 1;
                    strcpy(routing_table[j].next_hop, source_ip);
                    strcpy(routing_table[j].interface, ports[port_index].device_id);
                    routing_table[j].last_update = time(NULL);
                    printf("RIP_UPDATE_ROUTE: %s/%s via %s metric %d\n",
                           entry->ip_addr, entry->subnet_mask, source_ip, metric + 1);
                }
                break;
            }
        }
        
        // Add new route if not found
        if (!found && routing_table_size < MAX_ROUTING_TABLE_SIZE && metric + 1 < RIP_INFINITY) {
            strcpy(routing_table[routing_table_size].network, entry->ip_addr);
            strcpy(routing_table[routing_table_size].netmask, entry->subnet_mask);
            strcpy(routing_table[routing_table_size].next_hop, source_ip);
            strcpy(routing_table[routing_table_size].interface, ports[port_index].device_id);
            routing_table[routing_table_size].metric = metric + 1;
            routing_table[routing_table_size].is_static = false;
            routing_table[routing_table_size].last_update = time(NULL);
            routing_table_size++;
            printf("RIP_ADD_ROUTE: %s/%s via %s metric %d\n",
                   entry->ip_addr, entry->subnet_mask, source_ip, metric + 1);
        }
    }
    
    pthread_mutex_unlock(&routing_mutex);
}

// RIP timer thread
void *rip_timer_thread(void *arg) {
    printf("RIP_THREAD: Started\n");
    
    while (rip_thread_running) {
        time_t current_time = time(NULL);
        
        // Send periodic updates
        if (current_time - last_rip_update >= RIP_UPDATE_TIMER) {
            printf("RIP_TIMER: Sending periodic updates\n");
            for (int i = 0; i < num_ports; i++) {
                if (ports[i].connected) {
                    send_rip_update(i);
                }
            }
            last_rip_update = current_time;
        }
        
        // Check for expired routes
        pthread_mutex_lock(&routing_mutex);
        for (int i = 0; i < routing_table_size; i++) {
            if (!routing_table[i].is_static && 
                current_time - routing_table[i].last_update > RIP_TIMEOUT) {
                printf("RIP_EXPIRE: Route to %s/%s expired\n",
                       routing_table[i].network, routing_table[i].netmask);
                routing_table[i].metric = RIP_INFINITY;
            }
        }
        pthread_mutex_unlock(&routing_mutex);
        
        sleep(5); // Check every 5 seconds
    }
    
    printf("RIP_THREAD: Stopped\n");
    return NULL;
}

// Find route for destination IP
int find_route(const char *dest_ip, char *next_hop, char *interface) {
    pthread_mutex_lock(&routing_mutex);
    
    int best_match = -1;
    int longest_prefix = -1;
    
    printf("ROUTE_LOOKUP: Looking for route to %s\n", dest_ip);
    
    for (int i = 0; i < routing_table_size; i++) {
        if (routing_table[i].metric >= RIP_INFINITY) continue;
        
        printf("  Checking route %d: %s/%s via %s metric %d\n", 
               i, routing_table[i].network, routing_table[i].netmask, 
               routing_table[i].next_hop, routing_table[i].metric);
        
        if (is_same_network(dest_ip, routing_table[i].network, routing_table[i].netmask)) {
            // Calculate prefix length
            struct in_addr mask;
            inet_aton(routing_table[i].netmask, &mask);
            int prefix_len = __builtin_popcount(mask.s_addr);
            
            printf("    MATCH! Prefix length: %d\n", prefix_len);
            
            if (prefix_len > longest_prefix) {
                longest_prefix = prefix_len;
                best_match = i;
            }
        }
    }
    
    if (best_match != -1) {
        strcpy(next_hop, routing_table[best_match].next_hop);
        strcpy(interface, routing_table[best_match].interface);
        int metric = routing_table[best_match].metric;
        printf("ROUTE_FOUND: %s via %s (interface %s, metric %d)\n", 
               dest_ip, next_hop, interface, metric);
        pthread_mutex_unlock(&routing_mutex);
        return metric;
    }
    
    printf("ROUTE_NOT_FOUND: No route to %s\n", dest_ip);
    pthread_mutex_unlock(&routing_mutex);
    return -1;
}

// Find port index by interface name
int find_port_by_interface(const char *interface) {
    for (int i = 0; i < num_ports; i++) {
        if (strcmp(ports[i].device_id, interface) == 0) {
            return i;
        }
    }
    return -1;
}

// Route IP packet
void route_ip_packet(IPPacket *packet, int incoming_port) {
    printf("\nROUTE_START: Routing packet from %s to %s (TTL=%d)\n", 
           packet->source_ip, packet->dest_ip, packet->ttl);
    
    // Decrement TTL
    packet->ttl--;
    if (packet->ttl <= 0) {
        printf("ROUTE_DROP: TTL expired\n");
        return;
    }
    
    char next_hop[IP_ADDR_LEN];
    char interface[DEVICE_ID_MAX];
    
    int metric = find_route(packet->dest_ip, next_hop, interface);
    if (metric == -1) {
        printf("ROUTE_DROP: No route to %s\n", packet->dest_ip);
        return;
    }
    
    int port_index = find_port_by_interface(interface);
    if (port_index == -1) {
        printf("ROUTE_ERROR: Interface %s not found\n", interface);
        return;
    }
    
    // Don't route back to the same interface
    if (port_index == incoming_port) {
        printf("ROUTE_DROP: Not routing back to same interface\n");
        return;
    }
    
    // Determine actual next hop
    char actual_next_hop[IP_ADDR_LEN];
    if (strcmp(next_hop, "0.0.0.0") == 0) {
        // Directly connected
        strcpy(actual_next_hop, packet->dest_ip);
        printf("ROUTE_DIRECT: Directly connected, next hop = %s\n", actual_next_hop);
    } else {
        strcpy(actual_next_hop, next_hop);
        printf("ROUTE_VIA: Via gateway %s\n", actual_next_hop);
    }
    
    // Look up MAC address
    char *dest_mac = find_mac_for_ip(actual_next_hop);
    if (!dest_mac) {
        printf("ROUTE_ARP: No MAC for %s, sending ARP request\n", actual_next_hop);
        send_arp_request(actual_next_hop, port_index);
        return;
    }
    
    printf("ROUTE_MAC: Found MAC %s for %s\n", dest_mac, actual_next_hop);
    
    // Forward packet
    EthernetFrame frame;
    create_ethernet_frame(&frame, dest_mac, router_macs[port_index], 
                         PROTO_IP, packet, sizeof(IPPacket));
    
    if (send_ethernet_frame(ports[port_index].file_out, &frame)) {
        printf("ROUTE_OK: Forwarded packet to %s via %s (port %d)\n", 
               packet->dest_ip, actual_next_hop, port_index);
    } else {
        printf("ROUTE_FAIL: Failed to forward packet\n");
    }
}

// Process frames from all ports
void process_frames() {
    for (int i = 0; i < num_ports; i++) {
        if (!ports[i].connected) continue;
        
        EthernetFrame frame;
        if (receive_ethernet_frame(ports[i].file_in, &frame)) {
            printf("\n*** ROUTER: Received frame on port %d ***\n", ports[i].port_num);
            printf("    From: %s\n", frame.source_mac);
            printf("    To: %s\n", frame.dest_mac);
            printf("    Type: 0x%04x\n", frame.ethertype);
            print_ethernet_frame(&frame, "Router");
            
            if (frame.ethertype == PROTO_ARP) {
                printf("FRAME_TYPE: ARP packet\n");
                ARPPacket *arp = (ARPPacket*)frame.payload;
                handle_arp_packet(arp, i);
            } else if (frame.ethertype == PROTO_IP) {
                printf("FRAME_TYPE: IP packet\n");
                IPPacket *ip = (IPPacket*)frame.payload;
                print_ip_packet(ip, "Router");
                
                // Check if packet is for us (any of our interfaces)
                bool for_us = false;
                for (int j = 0; j < num_ports; j++) {
                    if (strcmp(ports[j].ip_address, ip->dest_ip) == 0) {
                        for_us = true;
                        printf("IP_DEST: Packet is for us (interface %d: %s)\n", j, ports[j].ip_address);
                        break;
                    }
                }
                
                if (for_us) {
                    printf("IP_DELIVER: Packet delivered to router\n");
                    // Handle packets destined for router
                    if (ip->protocol == PROTO_UDP) {
                        UDPPacket *udp = (UDPPacket*)ip->payload;
                        if (ntohs(udp->dest_port) == RIP_PORT) {
                            printf("RIP: Received RIP packet\n");
                            RIPPacket *rip = (RIPPacket*)udp->payload;
                            handle_rip_packet(rip, ip->source_ip, i);
                        }
                    }
                } else if (strcmp(ip->dest_ip, BROADCAST_IP) == 0) {
                    // Handle broadcast packets
                    if (ip->protocol == PROTO_UDP) {
                        UDPPacket *udp = (UDPPacket*)ip->payload;
                        if (ntohs(udp->dest_port) == RIP_PORT) {
                            printf("RIP: Received RIP broadcast\n");
                            RIPPacket *rip = (RIPPacket*)udp->payload;
                            handle_rip_packet(rip, ip->source_ip, i);
                        }
                    }
                } else {
                    printf("IP_FORWARD: Packet needs forwarding\n");
                    // Route the packet
                    route_ip_packet(ip, i);
                }
            } else {
                printf("FRAME_TYPE: Unknown ethertype 0x%04x\n", frame.ethertype);
            }
        }
    }
}

// Print ARP table
void print_arp_table() {
    pthread_mutex_lock(&arp_mutex);
    
    printf("\n--- ARP Table ---\n");
    printf("IP Address      | MAC Address       | Age (sec) | Type\n");
    printf("----------------------------------------------------\n");
    
    time_t current_time = time(NULL);
    for (int i = 0; i < arp_table_size; i++) {
        printf("%-15s | %-17s | %9ld | %s\n", 
               arp_table[i].ip_address, 
               arp_table[i].mac_address,
               current_time - arp_table[i].last_seen,
               arp_table[i].is_static ? "Static" : "Dynamic");
    }
    
    if (arp_table_size == 0) {
        printf("(No entries in ARP table)\n");
    }
    
    printf("----------------------------------------------------\n");
    pthread_mutex_unlock(&arp_mutex);
}

// Print routing table
void print_routing_table() {
    pthread_mutex_lock(&routing_mutex);
    
    printf("\n--- Routing Table ---\n");
    printf("Network         | Netmask         | Next Hop       | Interface | Metric | Type    | Age\n");
    printf("---------------------------------------------------------------------------------------\n");
    
    time_t current_time = time(NULL);
    for (int i = 0; i < routing_table_size; i++) {
        printf("%-15s | %-15s | %-14s | %-9s | %6d | %-7s | %ld\n",
               routing_table[i].network,
               routing_table[i].netmask, 
               routing_table[i].next_hop,
               routing_table[i].interface,
               routing_table[i].metric,
               routing_table[i].is_static ? "Static" : "RIP",
               current_time - routing_table[i].last_update);
    }
    
    if (routing_table_size == 0) {
        printf("(No routes in routing table)\n");
    }
    
    printf("---------------------------------------------------------------------------------------\n");
    pthread_mutex_unlock(&routing_mutex);
}

// Print port status
void print_port_status() {
    printf("\n--- Router Port Status ---\n");
    printf("Port | Interface       | IP Address      | Netmask         | MAC Address       | Connected\n");
    printf("-----------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < num_ports; i++) {
        printf("%4d | %-15s | %-15s | %-15s | %-17s | %s\n", 
               ports[i].port_num, 
               ports[i].device_id,
               ports[i].ip_address,
               ports[i].netmask,
               router_macs[i],
               ports[i].connected ? "Yes" : "No");
    }
    
    if (num_ports == 0) {
        printf("(No ports configured)\n");
    }
    
    printf("-----------------------------------------------------------------------------------------------\n");
}

// Add static route
bool add_static_route(const char *network, const char *netmask, const char *next_hop, const char *interface) {
    pthread_mutex_lock(&routing_mutex);
    
    if (routing_table_size >= MAX_ROUTING_TABLE_SIZE) {
        pthread_mutex_unlock(&routing_mutex);
        printf("Routing table full\n");
        return false;
    }
    
    strcpy(routing_table[routing_table_size].network, network);
    strcpy(routing_table[routing_table_size].netmask, netmask);
    strcpy(routing_table[routing_table_size].next_hop, next_hop);
    strcpy(routing_table[routing_table_size].interface, interface);
    routing_table[routing_table_size].metric = 1;
    routing_table[routing_table_size].is_static = true;
    routing_table[routing_table_size].last_update = time(NULL);
    routing_table_size++;
    
    pthread_mutex_unlock(&routing_mutex);
    
    printf("Static route added: %s/%s via %s\n", network, netmask, next_hop);
    return true;
}

// Command thread
void *command_thread(void *arg) {
    char cmd[256];
    
    while (running) {
        printf("\nRouter[%s]> ", router_id);
        fflush(stdout);
        
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }
        
        cmd[strcspn(cmd, "\n")] = 0;
        
        if (strcmp(cmd, "show arp") == 0) {
            print_arp_table();
        } else if (strcmp(cmd, "show routes") == 0) {
            print_routing_table();
        } else if (strcmp(cmd, "show ports") == 0) {
            print_port_status();
        } else if (strncmp(cmd, "route add", 9) == 0) {
            char network[IP_ADDR_LEN], netmask[IP_ADDR_LEN], next_hop[IP_ADDR_LEN], interface[DEVICE_ID_MAX];
            if (sscanf(cmd + 10, "%s %s %s %s", network, netmask, next_hop, interface) == 4) {
                add_static_route(network, netmask, next_hop, interface);
            } else {
                printf("Usage: route add <network> <netmask> <next_hop> <interface>\n");
                printf("Example: route add 192.168.2.0 255.255.255.0 0.0.0.0 device2\n");
            }
        } else if (strcmp(cmd, "rip enable") == 0) {
            if (!rip_enabled) {
                rip_enabled = true;
                rip_thread_running = true;
                pthread_create(&rip_thread, NULL, rip_timer_thread, NULL);
                printf("RIP enabled\n");
                
                // Send initial RIP updates
                for (int i = 0; i < num_ports; i++) {
                    if (ports[i].connected) {
                        send_rip_update(i);
                    }
                }
            } else {
                printf("RIP is already enabled\n");
            }
        } else if (strcmp(cmd, "rip disable") == 0) {
            if (rip_enabled) {
                rip_enabled = false;
                rip_thread_running = false;
                pthread_join(rip_thread, NULL);
                printf("RIP disabled\n");
            } else {
                printf("RIP is already disabled\n");
            }
        } else if (strcmp(cmd, "rip send") == 0) {
            if (rip_enabled) {
                printf("Sending RIP updates on all interfaces\n");
                for (int i = 0; i < num_ports; i++) {
                    if (ports[i].connected) {
                        send_rip_update(i);
                    }
                }
            } else {
                printf("RIP is not enabled\n");
            }
        } else if (strcmp(cmd, "debug") == 0) {
            printf("\n=== Debug Info ===\n");
            printf("Router ID: %s\n", router_id);
            printf("Number of ports: %d\n", num_ports);
            printf("RIP enabled: %s\n", rip_enabled ? "Yes" : "No");
            for (int i = 0; i < num_ports; i++) {
                printf("Port %d: %s -> %s:%s\n", i, ports[i].device_id, 
                       ports[i].ip_address, ports[i].netmask);
                printf("  Files: %s <-> %s\n", ports[i].file_in, ports[i].file_out);
            }
        } else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  show arp       - Display ARP table\n");
            printf("  show routes    - Display routing table\n");
            printf("  show ports     - Display port status\n");
            printf("  route add      - Add static route\n");
            printf("  rip enable     - Enable RIP protocol\n");
            printf("  rip disable    - Disable RIP protocol\n");
            printf("  rip send       - Send RIP updates manually\n");
            printf("  debug          - Show debug information\n");
            printf("  help           - Show this help\n");
            printf("  exit           - Exit the router\n");
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
    if (argc < 4 || (argc - 2) % 3 != 0) {
        printf("Usage: %s <router_id> <interface1> <ip1> <netmask1> [interface2] [ip2] [netmask2] ...\n", argv[0]);
        printf("Example: %s router1 device1 192.168.1.1 255.255.255.0 device2 192.168.2.1 255.255.255.0\n", argv[0]);
        return 1;
    }
    
    strncpy(router_id, argv[1], DEVICE_ID_MAX - 1);
    router_id[DEVICE_ID_MAX - 1] = '\0';
    
    signal(SIGINT, handle_signal);
    srand(time(NULL));
    
    ensure_tmp_directory();
    
    printf("\n=== Initializing Router '%s' ===\n", router_id);
    
    // Add ports
    int port_count = 1;
    for (int i = 2; i < argc; i += 3) {
        if (i + 2 < argc) {
            if (!add_port(argv[i], port_count, argv[i+1], argv[i+2])) {
                printf("Failed to add port for interface %s\n", argv[i]);
                return 1;
            }
            port_count++;
        }
    }
    
    printf("\n=== Router '%s' started with %d ports ===\n", router_id, num_ports);
    printf("Type 'help' for available commands.\n");
    printf("Use 'debug' to see port configuration.\n");
    printf("Use 'show routes' to see routing table.\n");
    printf("Use 'rip enable' to start RIP protocol.\n\n");
    
    pthread_t cmd_tid;
    pthread_create(&cmd_tid, NULL, command_thread, NULL);
    
    // Main loop
    printf("Router main loop started...\n");
    while (running) {
        process_frames();
        usleep(100000); // 100ms
    }
    
    // Cleanup
    if (rip_thread_running) {
        rip_thread_running = false;
        pthread_join(rip_thread, NULL);
    }
    pthread_join(cmd_tid, NULL);
    pthread_mutex_destroy(&arp_mutex);
    pthread_mutex_destroy(&routing_mutex);
    
    printf("Router shut down successfully\n");
    return 0;
}