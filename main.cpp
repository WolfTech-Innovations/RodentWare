#include <iostream>
#include <unordered_set>
#include <string>
#include <cstring>
#include <windows.h>
#include <iphlpapi.h>
#include <fstream>
#include <ctime>
#include <thread>
#include <mutex>
#include <vector> // Include vector header

#pragma comment(lib, "iphlpapi.lib")

const std::unordered_set<uint16_t> SUSPICIOUS_PORTS = {4444, 5555}; // Example suspicious ports
const std::unordered_set<std::string> SUSPICIOUS_IPS = {"192.168.1.100", "10.0.0.1"}; // Example suspicious IPs
const std::string LOG_FILE = "rodentware_log.txt"; // Log file for suspicious activity
std::mutex log_mutex; // Mutex for thread-safe logging

void log_activity(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log_file(LOG_FILE, std::ios_base::app);
    if (log_file.is_open()) {
        std::time_t now = std::time(nullptr);
        log_file << std::ctime(&now) << ": " << message << std::endl;
        log_file.close();
    }
}

void block_ip(const std::string& ip) {
    // Block the IP address using Windows Firewall
    std::string command = "netsh advfirewall firewall add rule name=\"RodentWare Block " + ip + "\" dir=OUT action=BLOCK remoteip=" + ip;
    system(command.c_str()); // Execute the command
    std::cout << "[RodentWare] Blocking IP: " << ip << std::endl;
    log_activity("Blocked IP: " + ip);
}

void check_connections() {
    ULONG buffer_size = 0;
    GetExtendedTcpTable(nullptr, &buffer_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buffer(buffer_size); // Use std::vector to hold the buffer

    if (GetExtendedTcpTable(buffer.data(), &buffer_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto tcp_table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (size_t i = 0; i < tcp_table->dwNumEntries; ++i) {
            auto& entry = tcp_table->table[i];
            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = entry.dwLocalPort;
            addr.sin_addr.s_addr = entry.dwLocalAddr;

            uint16_t local_port = ntohs(addr.sin_port);
            std::string local_ip = inet_ntoa(addr.sin_addr);

            // Check for suspicious ports
            if (SUSPICIOUS_PORTS.find(local_port) != SUSPICIOUS_PORTS.end()) {
                std::string message = "[RodentWare] Suspicious connection detected: " + local_ip + ":" + std::to_string(local_port);
                std::cout << message << std::endl;
                log_activity(message);
                block_ip(local_ip); // Block the suspicious IP
            }

            // Check for suspicious IPs
            if (SUSPICIOUS_IPS.find(local_ip) != SUSPICIOUS_IPS.end()) {
                std::string message = "[RodentWare] Connection to suspicious IP detected: " + local_ip;
                std::cout << message << std::endl;
                log_activity(message);
                block_ip(local_ip); // Block the suspicious IP
            }
        }
    } else {
        std::cerr << "[RodentWare] Failed to retrieve TCP table." << std::endl;
    }
}

int main() {
    std::cout << "[RodentWare] Starting RodentWare IDS..." << std::endl;

    while (true) {
        check_connections();
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Check every 5 seconds
    }

    return 0;
}