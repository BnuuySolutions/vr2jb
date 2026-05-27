#include "bridge.hpp"
#include "logger.hpp"

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <cstring>
#include <chrono>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>

static int _kbhit() {
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

static int _getch() {
    unsigned char ch = 0;
    if (read(STDIN_FILENO, &ch, 1) < 0) {
        return 0;
    }
    return ch;
}
#endif

// ==========================================
// Protocol Definitions
// ==========================================
#pragma pack(push, 1)
struct PacketHeader {
    uint8_t  magic;       
    uint8_t  type;        
    uint16_t length;      
};
#pragma pack(pop)

enum PacketType : uint8_t {
    PKT_TTY_IN = 1,
    PKT_TTY_OUT = 2,
    PKT_TTY_START = 3,
    PKT_TTY_STOP = 4,
    PKT_FILE_START = 10,
    PKT_FILE_DATA = 11,
    PKT_FILE_END = 12,
    PKT_FILE_ERR = 13,
    PKT_EXEC_CMD = 20,
    PKT_EXEC_OUT = 21,
    PKT_EXEC_ERR = 22,
    PKT_EXEC_EXIT = 23
};

#define PKT_MAGIC 0xA5
#define MAX_PAYLOAD_SIZE (4096 - sizeof(PacketHeader))

PSVR2Bridge::PSVR2Bridge(libusb_device_handle* dev_handle) : dev(dev_handle) {}

bool PSVR2Bridge::send_packet(uint8_t type, const uint8_t* payload, uint16_t len) {
    PacketHeader hdr = { PKT_MAGIC, type, len };
    std::vector<uint8_t> tx_buf {};
    
    tx_buf.reserve(sizeof(hdr) + len);
    tx_buf.insert(tx_buf.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
    if (len > 0 && payload != nullptr) {
        tx_buf.insert(tx_buf.end(), payload, payload + len);
    }

    int actual;
    return (libusb_bulk_transfer(dev, 0x04, tx_buf.data(), tx_buf.size(), &actual, 1000) == 0);
}

void PSVR2Bridge::upload(const std::string& local_path, const std::string& remote_path) {
    if (!dev) {
        LOG_ERROR << "[-] USB device handle invalid." << std::endl;
        return;
    }

    std::ifstream file(local_path, std::ios::binary);
    if (!file) {
        LOG_ERROR << "[-] Failed to open local file '" << local_path << "'" << std::endl;
        return;
    }

    LOG_INFO << "[*] Uploading to " << remote_path << "..." << std::endl;
    
    if (!send_packet(PKT_FILE_START, (const uint8_t*)remote_path.c_str(), remote_path.length())) {
        LOG_ERROR << "[-] Failed to send file start command." << std::endl;
        return;
    }

    uint8_t buffer[MAX_PAYLOAD_SIZE];
    size_t total_bytes = 0;
    while (file.read((char*)buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (!send_packet(PKT_FILE_DATA, buffer, file.gcount())) {
            LOG_ERROR << "[-] Failed to transmit file chunk." << std::endl;
            return;
        }
        total_bytes += file.gcount();
    }

    send_packet(PKT_FILE_END, nullptr, 0);
    LOG_INFO << "[+] Upload complete (" << std::dec << total_bytes << " bytes)." << std::endl;
}

void PSVR2Bridge::exec(const std::string& cmd) {
    if (!dev) {
        LOG_ERROR << "[-] USB device handle invalid." << std::endl;
        return;
    }

    if (!send_packet(PKT_EXEC_CMD, (const uint8_t*)cmd.c_str(), cmd.length())) {
        LOG_ERROR << "[-] Failed to send exec command." << std::endl;
        return;
    }

    LOG_INFO << "[*] Executing: " << cmd << "" << std::endl;

    // Open a temporary read loop to catch stdout/stderr until exit
    uint8_t buf[4096];
    int actual;
    while (true) {
        int r = libusb_bulk_transfer(dev, 0x84, buf, sizeof(buf), &actual, 1000);
        
        if (r == 0 && actual > 0) {
            size_t offset = 0;
            while (offset + sizeof(PacketHeader) <= (size_t)actual) {
                PacketHeader* hdr = (PacketHeader*)(buf + offset);
                
                if (hdr->magic != PKT_MAGIC) {
                    offset++;
                    continue;
                }
                
                if (offset + sizeof(PacketHeader) + hdr->length <= (size_t)actual) {
                    uint8_t* payload = buf + offset + sizeof(PacketHeader);
                    
                    if (hdr->type == PKT_EXEC_OUT) {
                        std::cout.write((char*)payload, hdr->length);
                        std::cout.flush();
                    } 
                    else if (hdr->type == PKT_EXEC_ERR) {
                        std::cerr.write((char*)payload, hdr->length);
                        std::cerr.flush();
                    } 
                    else if (hdr->type == PKT_EXEC_EXIT) {
                        LOG_INFO << "\n[*] Process finished." << std::endl;
                        return;
                    }
                    offset += sizeof(PacketHeader) + hdr->length;
                } else {
                    break; // Fragmented
                }
            }
        } else if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
            LOG_ERROR << "\n[-] USB error or timeout waiting for process output." << std::endl;
            break;
        }
    }
}

static void rx_thread_mux(libusb_device_handle* dev_handle, std::atomic<bool>* keep_running) {
    uint8_t buf[4096];
    int actual_length;
    
    while (*keep_running) {
        int r = libusb_bulk_transfer(dev_handle, 0x84, buf, sizeof(buf), &actual_length, 1000);
        
        if (r == 0 && actual_length > 0) {
            size_t offset = 0;
            
            // Loop through the buffer in case multiple packets were aggregated
            while (offset + sizeof(PacketHeader) <= (size_t)actual_length) {
                PacketHeader* hdr = (PacketHeader*)(buf + offset);
                
                // Re-sync if we hit corrupted data
                if (hdr->magic != PKT_MAGIC) {
                    offset++;
                    continue;
                }
                
                // Verify the whole payload arrived in this USB transfer
                if (offset + sizeof(PacketHeader) + hdr->length <= (size_t)actual_length) {
                    uint8_t* payload = buf + offset + sizeof(PacketHeader);
                    
                    if (hdr->type == PKT_TTY_OUT) {
                        std::cout.write((char*)payload, hdr->length);
                        std::cout.flush(); 
                    }
                    
                    // Advance pointer to the next packet
                    offset += sizeof(PacketHeader) + hdr->length;
                } else {
                    // Fragmented payload (or a bad header). Break and wait for the rest.
                    break;
                }
            }
        } else if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
            *keep_running = false;
            break;
        }
    }
}

void PSVR2Bridge::shell(const std::string& shell_cmd) {
    if (!dev) {
        LOG_ERROR << "[-] USB device handle invalid." << std::endl;
        return;
    }
    
    LOG_INFO << "[*] Starting remote shell: '" << shell_cmd << "'" << std::endl;
    if (!send_packet(PKT_TTY_START, (const uint8_t*)shell_cmd.c_str(), shell_cmd.length())) {
        LOG_ERROR << "[-] Failed to send TTY start command." << std::endl;
        return;
    }

#ifdef _WIN32
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_mode;
    GetConsoleMode(hIn, &original_mode);
    SetConsoleMode(hIn, original_mode & ~ENABLE_PROCESSED_INPUT);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD original_out_mode;
    GetConsoleMode(hOut, &original_out_mode);
    SetConsoleMode(hOut, original_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
    struct termios original_mode;
    tcgetattr(STDIN_FILENO, &original_mode);
    struct termios raw = original_mode;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
#endif

    LOG_INFO << "[*] Entered headset shell session. Press Ctrl+] to exit." << std::endl;

    std::atomic<bool> keep_running{ true };
    std::thread t_rx(rx_thread_mux, dev, &keep_running);

    while (keep_running) {
        if (_kbhit()) {
            int c = _getch();
            if (c == 0x1D) { // Ctrl+]
                LOG_INFO << "\n[*] Exiting shell..." << std::endl;
                // Signal the headset to kill the shell process
                send_packet(PKT_TTY_STOP, nullptr, 0); 
                keep_running = false;
                break;
            }
#ifdef _WIN32
            if (c == 0x00 || c == 0xE0) {
                int ext = _getch();
                const char* seq = nullptr;
                switch (ext) {
                    case 72: seq = "\x1B[A"; break; // Up
                    case 80: seq = "\x1B[B"; break; // Down
                    case 77: seq = "\x1B[C"; break; // Right
                    case 75: seq = "\x1B[D"; break; // Left
                }
                if (seq) {
                    if (!send_packet(PKT_TTY_IN, (uint8_t*)seq, 3)) {
                        keep_running = false;
                        break;
                    }
                }
                continue;
            }
#endif
            if (c == '\r') c = '\n';
            if (c == '\b') c = 127;
            
            uint8_t out_byte = (uint8_t)c;
            if (!send_packet(PKT_TTY_IN, &out_byte, 1)) {
                keep_running = false;
                break;
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    if (t_rx.joinable()) t_rx.join();

#ifdef _WIN32
    SetConsoleMode(hIn, original_mode);
    SetConsoleMode(hOut, original_out_mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &original_mode);
#endif
}