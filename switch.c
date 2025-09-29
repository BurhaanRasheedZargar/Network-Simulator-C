#include "common.h"

Port ports[MAX_CONNECTED_PORTS];
int num_ports = 0;
MACTableEntry mac_table[MAX_MAC_TABLE_SIZE];
int mac_table_size = 0;
bool running = true;
pthread_mutex_t mac_table_mutex = PTHREAD_MUTEX_INITIALIZER;
char switch_id[DEVICE_ID_MAX];

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nShutting down switch...\n");
        running = false;
    }
}

// Add a port to the switch
bool add_port(const char *device_id, int port_num) {
    if (num_ports >= MAX_CONNECTED_PORTS) {
        printf("Maximum number of ports reached\n");
        return false;
    }
    
    char file_in[100], file_out[100];
    get_file_paths(file_in, file_out, switch_id, device_id, port_num);
    
    printf("[DEBUG] Creating files for port %d: in=%s, out=%s\n", port_num, file_in, file_out);
    
    if (!init_comm_file(file_in)) {
        printf("Failed to initialize input file %s for port %d: %s\n", 
               file_in, port_num, strerror(errno));
        return false;
    }
    
    if (!init_comm_file(file_out)) {
        printf("Failed to initialize output file %s for port %d: %s\n", 
               file_out, port_num, strerror(errno));
        return false;
    }
    
    ports[num_ports].port_num = port_num;
    strncpy(ports[num_ports].device_id, device_id, DEVICE_ID_MAX - 1);
    strncpy(ports[num_ports].file_in, file_in, sizeof(ports[num_ports].file_in) - 1);
    strncpy(ports[num_ports].file_out, file_out, sizeof(ports[num_ports].file_out) - 1);
    ports[num_ports].connected = true;
    
    printf("Port %d added successfully:\n", port_num);
    printf("  - Input file (device → switch): %s\n", file_in);
    printf("  - Output file (switch → device): %s\n", file_out);
    
    num_ports++;
    return true;
}

// Find port number for a MAC address
int find_port_for_mac(const char *mac_address) {
    pthread_mutex_lock(&mac_table_mutex);
    
    for (int i = 0; i < mac_table_size; i++) {
        if (strcmp(mac_table[i].mac_address, mac_address) == 0) {
            int port = mac_table[i].port_num;
            pthread_mutex_unlock(&mac_table_mutex);
            return port;
        }
    }
    
    pthread_mutex_unlock(&mac_table_mutex);
    return -1;
}

// Update MAC table with a new entry
void update_mac_table(const char *mac_address, int port_num) {
    pthread_mutex_lock(&mac_table_mutex);
    
    // Check if MAC already exists
    for (int i = 0; i < mac_table_size; i++) {
        if (strcmp(mac_table[i].mac_address, mac_address) == 0) {
            // Update existing entry
            mac_table[i].port_num = port_num;
            mac_table[i].last_seen = time(NULL);
            pthread_mutex_unlock(&mac_table_mutex);
            return;
        }
    }
    
    // Add new entry if table not full
    if (mac_table_size < MAX_MAC_TABLE_SIZE) {
        strcpy(mac_table[mac_table_size].mac_address, mac_address);
        mac_table[mac_table_size].port_num = port_num;
        mac_table[mac_table_size].last_seen = time(NULL);
        mac_table_size++;
        printf("Added MAC %s on port %d to the MAC table\n", mac_address, port_num);
    } else {
        // Find oldest entry and replace it
        time_t oldest_time = time(NULL);
        int oldest_idx = 0;
        
        for (int i = 0; i < mac_table_size; i++) {
            if (mac_table[i].last_seen < oldest_time) {
                oldest_time = mac_table[i].last_seen;
                oldest_idx = i;
            }
        }
        
        printf("MAC table full. Replacing oldest entry %s with %s on port %d\n",
               mac_table[oldest_idx].mac_address, mac_address, port_num);
        
        strcpy(mac_table[oldest_idx].mac_address, mac_address);
        mac_table[oldest_idx].port_num = port_num;
        mac_table[oldest_idx].last_seen = time(NULL);
    }
    
    pthread_mutex_unlock(&mac_table_mutex);
}

// Find port index by port number
int find_port_index(int port_num) {
    for (int i = 0; i < num_ports; i++) {
        if (ports[i].port_num == port_num) {
            return i;
        }
    }
    return -1;
}

// Process frames from all ports and forward them based on MAC address
void process_frames() {
    for (int i = 0; i < num_ports; i++) {
        if (!ports[i].connected) continue;
        
        EthernetFrame frame;
        if (receive_ethernet_frame(ports[i].file_in, &frame)) {
            printf("\n[SWITCH] Received frame on port %d from device %s\n", 
                   ports[i].port_num, ports[i].device_id);
            print_ethernet_frame(&frame, "Switch");
            
            // Update MAC table with source MAC
            update_mac_table(frame.source_mac, ports[i].port_num);
            
            // Check if it's a broadcast frame
            if (strcmp(frame.dest_mac, BROADCAST_MAC) == 0) {
                printf("[SWITCH] Broadcasting frame to all ports except the source port %d\n", 
                       ports[i].port_num);
                
                // Send to all ports except the source
                int broadcast_count = 0;
                
                for (int j = 0; j < num_ports; j++) {
                    if (j != i && ports[j].connected) {
                        printf("[SWITCH] Forwarding broadcast frame to device %s on port %d...\n", 
                               ports[j].device_id, ports[j].port_num);
                        
                        if (send_ethernet_frame(ports[j].file_out, &frame)) {
                            printf("[SWITCH] Successfully sent broadcast frame to port %d\n", 
                                   ports[j].port_num);
                            broadcast_count++;
                        } else {
                            printf("[ERROR] Failed to send to device %s on port %d: %s\n", 
                                   ports[j].device_id, ports[j].port_num, strerror(errno));
                        }
                    }
                }
                
                printf("[SWITCH] Frame broadcast to %d of %d eligible ports\n", 
                       broadcast_count, num_ports - 1);
            } else {
                // Unicast frame - look up destination MAC
                int dest_port = find_port_for_mac(frame.dest_mac);
                
                if (dest_port == -1) {
                    // MAC not in table, broadcast
                    printf("[SWITCH] Destination MAC %s not in table. Broadcasting\n", frame.dest_mac);
                    
                    int broadcast_count = 0;
                    
                    for (int j = 0; j < num_ports; j++) {
                        if (j != i && ports[j].connected) {
                            printf("[SWITCH] Forwarding frame to device %s on port %d...\n", 
                                   ports[j].device_id, ports[j].port_num);
                            
                            if (send_ethernet_frame(ports[j].file_out, &frame)) {
                                printf("[SWITCH] Successfully forwarded frame to port %d\n", 
                                       ports[j].port_num);
                                broadcast_count++;
                            } else {
                                printf("[ERROR] Failed to send to device %s on port %d: %s\n", 
                                       ports[j].device_id, ports[j].port_num, strerror(errno));
                            }
                        }
                    }
                    
                    printf("[SWITCH] Unknown destination frame forwarded to %d ports\n", 
                           broadcast_count);
                } else {
                    // Send to specific port
                    int port_idx = find_port_index(dest_port);
                    if (port_idx != -1 && port_idx != i) {
                        printf("[SWITCH] Forwarding frame to port %d for MAC %s\n", 
                               dest_port, frame.dest_mac);
                        
                        if (send_ethernet_frame(ports[port_idx].file_out, &frame)) {
                            printf("[SWITCH] Successfully sent frame to device %s on port %d\n", 
                                   ports[port_idx].device_id, dest_port);
                        } else {
                            printf("[ERROR] Failed to send to device %s on port %d: %s\n", 
                                   ports[port_idx].device_id, dest_port, strerror(errno));
                        }
                    } else if (port_idx == i) {
                        printf("[SWITCH] Source and destination on same port %d. Not forwarding.\n", dest_port);
                    } else {
                        printf("[ERROR] Port %d not found in port list\n", dest_port);
                    }
                }
            }
        }
    }
}

// Print the MAC table
void print_mac_table() {
    pthread_mutex_lock(&mac_table_mutex);
    
    printf("\n--- MAC Address Table ---\n");
    printf("MAC Address        | Port | Age (sec)\n");
    printf("------------------------------------\n");
    
    time_t current_time = time(NULL);
    for (int i = 0; i < mac_table_size; i++) {
        printf("%-19s | %4d | %ld\n", 
               mac_table[i].mac_address, 
               mac_table[i].port_num, 
               current_time - mac_table[i].last_seen);
    }
    
    if (mac_table_size == 0) {
        printf("(No entries in MAC table)\n");
    }
    
    printf("------------------------------------\n");
    printf("Total entries: %d/%d\n", mac_table_size, MAX_MAC_TABLE_SIZE);
    
    pthread_mutex_unlock(&mac_table_mutex);
}

// Print port status
void print_port_status() {
    printf("\n--- Switch Port Status ---\n");
    printf("Port | Device ID       | Connected | Input File                | Output File\n");
    printf("-------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < num_ports; i++) {
        printf("%4d | %-15s | %-9s | %-25s | %s\n", 
               ports[i].port_num, 
               ports[i].device_id,
               ports[i].connected ? "Yes" : "No", 
               ports[i].file_in,
               ports[i].file_out);
    }
    
    if (num_ports == 0) {
        printf("(No ports configured)\n");
    }
    
    printf("-------------------------------------------------------------------------------\n");
}

// Command thread
void *command_thread(void *arg) {
    char cmd[64];
    
    while (running) {
        printf("\nSwitch> ");
        fflush(stdout);
        
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }
        
        cmd[strcspn(cmd, "\n")] = 0;
        
        if (strcmp(cmd, "show mac") == 0) {
            print_mac_table();
        } else if (strcmp(cmd, "show ports") == 0) {
            print_port_status();
        } else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  show mac   - Display MAC address table\n");
            printf("  show ports - Display ports status\n");
            printf("  help       - Show this help\n");
            printf("  exit       - Exit the switch\n");
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
    if (argc < 3) {
        printf("Usage: %s <switch_id> <device1_id> [device2_id] ... [deviceN_id]\n", argv[0]);
        printf("Example: %s switch1 device1 device2\n", argv[0]);
        return 1;
    }
    
    strncpy(switch_id, argv[1], DEVICE_ID_MAX - 1);
    
    signal(SIGINT, handle_signal);
    
    ensure_tmp_directory();
    
    printf("Initializing switch '%s' with %d devices...\n", switch_id, argc - 2);
    
    // Add ports for each device
    for (int i = 2; i < argc; i++) {
        printf("Adding port %d for device '%s'...\n", i - 1, argv[i]);
        if (!add_port(argv[i], i - 1)) {
            printf("Failed to add port for device %s\n", argv[i]);
            return 1;
        }
    }
    
    printf("\nSwitch '%s' started successfully with %d ports.\n", switch_id, num_ports);
    printf("Type 'help' for available commands, or press Ctrl+C to exit.\n");
    
    pthread_t cmd_tid;
    pthread_create(&cmd_tid, NULL, command_thread, NULL);
    
    // Main loop
    while (running) {
        process_frames();
        usleep(100000); // 100ms pause to reduce CPU usage
    }
    
    // Cleanup
    pthread_join(cmd_tid, NULL);
    pthread_mutex_destroy(&mac_table_mutex);
    
    printf("Switch shut down successfully\n");
    return 0;
}