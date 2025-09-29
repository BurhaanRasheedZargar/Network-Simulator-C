#include "common.h"

Port ports[MAX_CONNECTED_PORTS];
int num_ports = 0;
bool running = true;
char hub_id[DEVICE_ID_MAX];

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nShutting down hub...\n");
        running = false;
    }
}

// Add a port to the hub
bool add_port(const char *device_id, int port_num) {
    if (num_ports >= MAX_CONNECTED_PORTS) {
        printf("Maximum number of ports reached\n");
        return false;
    }
    
    char file_in[100], file_out[100];
    sprintf(file_in, "./tmp/%s_to_%s_port%d.bin", device_id, hub_id, port_num);
    sprintf(file_out, "./tmp/%s_to_%s_port%d.bin", hub_id, device_id, port_num);
    
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
    printf("  - Input file (device → hub): %s\n", file_in);
    printf("  - Output file (hub → device): %s\n", file_out);
    
    num_ports++;
    return true;
}

// Process frames from all ports and broadcast them
void process_frames() {
    for (int i = 0; i < num_ports; i++) {
        if (!ports[i].connected) {
            continue;
        }
        
        EthernetFrame frame;
        if (receive_ethernet_frame(ports[i].file_in, &frame)) {
            printf("\n[HUB] Received frame on port %d from MAC %s to MAC %s\n", 
                   ports[i].port_num, frame.source_mac, frame.dest_mac);
            print_ethernet_frame(&frame, "Hub");
            
            // Broadcast frame to all ports except the one that sent it
            int broadcast_count = 0;
            
            for (int j = 0; j < num_ports; j++) {
                if (j != i && ports[j].connected) {
                    printf("[HUB] Broadcasting frame to port %d (device: %s)...\n", 
                           ports[j].port_num, ports[j].device_id);
                    
                    if (send_ethernet_frame(ports[j].file_out, &frame)) {
                        printf("[HUB] Successfully forwarded frame to port %d\n", 
                               ports[j].port_num);
                        broadcast_count++;
                    } else {
                        printf("[ERROR] Failed to broadcast to port %d: %s\n", 
                               ports[j].port_num, strerror(errno));
                    }
                }
            }
            
            printf("[HUB] Frame forwarded to %d of %d ports\n", 
                   broadcast_count, num_ports - 1);
        }
    }
}

void print_port_status() {
    printf("\n--- Hub Port Status ---\n");
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
    
    printf("-------------------------------------------------------------------------------\n");
}

// Command thread
void *command_thread(void *arg) {
    char cmd[32];
    
    while (running) {
        printf("\nHub> ");
        fflush(stdout);
        
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }
        
        cmd[strcspn(cmd, "\n")] = 0;
        
        if (strcmp(cmd, "show ports") == 0) {
            print_port_status();
        } else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  show ports - Display port status\n");
            printf("  help       - Show this help\n");
            printf("  exit       - Exit the hub\n");
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
    if (argc < 2) {
        printf("Usage: %s <hub_id> <device1_id> [device2_id] ... [deviceN_id]\n", argv[0]);
        printf("Example: %s hub1 device1 device2 device3\n", argv[0]);
        return 1;
    }
    
    strncpy(hub_id, argv[1], DEVICE_ID_MAX - 1);

    signal(SIGINT, handle_signal);
    
    ensure_tmp_directory();
    
    printf("Initializing hub with %d devices...\n", argc - 2);
    
    // Add ports for each device
    for (int i = 2; i < argc; i++) {
        printf("Adding port %d for device '%s'...\n", i - 1, argv[i]);
        if (!add_port(argv[i], i - 1)) {
            printf("Failed to add port for device %s\n", argv[i]);
            return 1;
        }
    }
    
    printf("\nHub started successfully with %d ports.\n", num_ports);
    printf("Type 'help' for available commands, or press Ctrl+C to exit.\n");
    
    pthread_t cmd_tid;
    pthread_create(&cmd_tid, NULL, command_thread, NULL);
    
    while (running) {
        process_frames();
        usleep(100000); // 100ms pause to reduce CPU usage
    }
    
    pthread_join(cmd_tid, NULL);
    
    printf("Hub shut down successfully\n");
    return 0;
}