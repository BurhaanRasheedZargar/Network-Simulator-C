# C Network Simulator 

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)

This project is a comprehensive network simulator written in C that models a full network stack, from the physical layer up to the application layer. It transforms a basic Layer 2 frame-forwarding system into a dynamic environment supporting multiple network devices, modern protocols, and diverse topologies.

The simulator is an excellent platform for networking education, allowing users to experiment with real network protocols in a controlled, interactive command-line environment.

---
## Key Features 

* **Layered Architecture**: Implements a protocol stack modeling OSI Layers 2 through 7, from Ethernet framing to application services.
* **Network Devices**:
    * **Router**: A multi-interface Layer 3 device for routing packets between different subnets.
    * **Switch**: An intelligent Layer 2 device with a dynamic MAC address table for efficient frame forwarding.
    * **Hub**: A simple Layer 1 device that broadcasts incoming frames to all ports, creating a single collision domain.
    * **End Device**: A fully-featured host with a complete network stack, capable of running client and server applications.
* **Core Protocols**:
    * **IPv4**: Implemented for Layer 3 addressing and routing.
    * **ARP**: Handles dynamic resolution of IP addresses to MAC addresses.
    * **TCP**: Provides reliable, connection-oriented transport with a 3-way handshake and a Go-Back-N sliding window for flow control.
    * **UDP**: Provides unreliable, connectionless datagram service for lightweight transport.
* **Dynamic & Static Routing**:
    * The router supports manual configuration of **static routes**.
    * It also implements the **RIP (Routing Information Protocol)** for dynamic discovery of network routes.
* **Application Services**:
    * **HTTP Server**: A simple web server running on TCP port 80.
    * **DNS Server**: A mock DNS server on UDP port 53 for name resolution.
* **Interactive CLI**: Each network device features a command-line interface for real-time configuration, monitoring, and debugging.

---
## Architecture 

The simulator uses a layered approach that mirrors the OSI model. Communication between devices at the physical layer is simulated using binary files (`.bin`) for inter-process communication (IPC), where each file represents a unidirectional link.

1.  **Application Layer**: HTTP & DNS services.
2.  **Transport Layer**: TCP & UDP protocols.
3.  **Network Layer**: IPv4, ARP, and Routing (Static/RIP).
4.  **Data Link Layer**: Ethernet frame encapsulation.
5.  **Physical Layer**: File-based IPC.

---
## How to Compile 
```bash
# A `tmp` directory is required for the communication files.
# Ensure it is created in the same directory as the executables.
mkdir -p tmp
```

```bash
# Compile the Router
gcc -o router router.c
```
```bash
# Compile the Switch
gcc -o switch switch.c
```
```bash
# Compile the Hub
gcc -o hub hub.c 
```
```bash
# Compile the End Device
gcc -o end_device end_device.c
```

# Refer the report for running an example.
