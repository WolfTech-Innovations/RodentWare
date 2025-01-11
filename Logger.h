#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <ctime>

class Logger {
private:
    static std::ofstream log_file;
    static std::mutex log_mutex;

    // Function to get the current timestamp
    static std::string get_current_timestamp() {
        std::time_t now = std::time(0);
        char buf[80];
        struct tm* timeinfo = localtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buf);
    }

public:
    // Initialize logger and open log file
    static void init(const std::string& filename = "rodentware_log.txt") {
        log_file.open(filename, std::ios::out | std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "ERROR: Failed to open log file." << std::endl;
            exit(1);
        }
    }

    // Function to log messages to both the console and file
    static void log(const std::string& level, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex);

        std::string timestamp = get_current_timestamp();
        std::string log_message = "[" + timestamp + "] [" + level + "] " + message;

        // Print to console
        std::cout << log_message << std::endl;

        // Write to file
        if (log_file.is_open()) {
            log_file << log_message << std::endl;
        }
    }

    // Close log file when done
    static void close() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
};

// Initialize the static members
std::ofstream Logger::log_file;
std::mutex Logger::log_mutex;

#endif // LOGGER_H
