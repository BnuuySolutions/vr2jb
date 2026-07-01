#include "bridge.hpp"
#include "logger.hpp"

#include "./vr2bridge/bridge_protocol.hpp"

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <cstring>
#include <chrono>
#include <vector>
#include <cstdio>

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

PSVR2Bridge::PSVR2Bridge(libusb_device_handle* dev_handle) : dev(dev_handle) {}

bool PSVR2Bridge::send_packet(uint8_t type, uint32_t session_id, const uint8_t* payload, uint16_t len) {
    PacketHeader hdr = { PKT_MAGIC, type, len, session_id };
    std::vector<uint8_t> tx_buf {};
    
    tx_buf.reserve(sizeof(hdr) + len);
    tx_buf.insert(tx_buf.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
    if (len > 0 && payload != nullptr) {
        tx_buf.insert(tx_buf.end(), payload, payload + len);
    }

    int actual;
    return (libusb_bulk_transfer(dev, 0x04, tx_buf.data(), static_cast<int>(tx_buf.size()), &actual, 1000) == 0);
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
    
    if (!send_packet(PKT_FILE_START, 0, (const uint8_t*)remote_path.c_str(), static_cast<uint16_t>(remote_path.length()))) {
        LOG_ERROR << "[-] Failed to send file start command." << std::endl;
        return;
    }

    uint8_t buffer[MAX_PAYLOAD_SIZE];
    size_t total_bytes = 0;
    while (file.read((char*)buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (!send_packet(PKT_FILE_DATA, 0, buffer, static_cast<uint16_t>(file.gcount()))) {
            LOG_ERROR << "[-] Failed to transmit file chunk." << std::endl;
            return;
        }
        total_bytes += file.gcount();
    }

    send_packet(PKT_FILE_END, 0, nullptr, 0);
    LOG_INFO << "[+] Upload complete (" << std::dec << total_bytes << " bytes)." << std::endl;
}

void PSVR2Bridge::download(const std::string& remote_path, const std::string& local_path) {
    if (!dev) {
        LOG_ERROR << "[-] USB device handle invalid." << std::endl;
        return;
    }

    std::ofstream file(local_path, std::ios::binary);
    if (!file) {
        LOG_ERROR << "[-] Failed to open local file '" << local_path << "' for writing." << std::endl;
        return;
    }

    LOG_INFO << "[*] Requesting download of '" << remote_path << "'..." << std::endl;

    if (!send_packet(PKT_DOWNLOAD_REQ, 0, (const uint8_t*)remote_path.c_str(), static_cast<uint16_t>(remote_path.length()))) {
        LOG_ERROR << "[-] Failed to send download request." << std::endl;
        return;
    }

    uint8_t rx_buf[4096];
    int actual_length;
    bool transmission_started = false;
    bool transmission_ended = false;
    size_t total_bytes = 0;
    std::vector<uint8_t> stream_buf;

    int timeouts = 0;
    while (!transmission_ended) {
        int r = libusb_bulk_transfer(dev, 0x84, rx_buf, sizeof(rx_buf), &actual_length, 2000);
        if (r == 0) {
            if (actual_length > 0) {
                timeouts = 0; // Reset timeout counter on successful read
                stream_buf.insert(stream_buf.end(), rx_buf, rx_buf + actual_length);
                
                size_t offset = 0;
                bool consumed_any = true;
                while (consumed_any && offset < stream_buf.size()) {
                    consumed_any = false;
                    
                    if (stream_buf[offset] != PKT_MAGIC) {
                        offset++;
                        consumed_any = true;
                        continue;
                    }

                    if (offset + sizeof(PacketHeader) <= stream_buf.size()) {
                        PacketHeader* hdr = (PacketHeader*)(stream_buf.data() + offset);
                        
                        if (offset + sizeof(PacketHeader) + hdr->length <= stream_buf.size()) {
                            uint8_t* payload = stream_buf.data() + offset + sizeof(PacketHeader);
                            
                            if (hdr->type == PKT_FILE_START) {
                                LOG_INFO << "[*] Download started." << std::endl;
                                transmission_started = true;
                            } else if (hdr->type == PKT_FILE_DATA) {
                                if (!transmission_started) {
                                    LOG_WARN << "[!] Received file data before start packet." << std::endl;
                                    transmission_started = true;
                                }
                                file.write((char*)payload, hdr->length);
                                total_bytes += hdr->length;
                            } else if (hdr->type == PKT_FILE_END) {
                                LOG_INFO << "[+] Download complete (" << std::dec << total_bytes << " bytes)." << std::endl;
                                transmission_ended = true;
                            } else if (hdr->type == PKT_FILE_ERR) {
                                std::string err_msg((char*)payload, hdr->length);
                                LOG_ERROR << "[-] Remote error: " << err_msg << std::endl;
                                transmission_ended = true;
                                file.close();
                                std::remove(local_path.c_str());
                            }
                            
                            offset += sizeof(PacketHeader) + hdr->length;
                            consumed_any = true;
                        }
                    }
                }
                
                if (offset > 0) {
                    stream_buf.erase(stream_buf.begin(), stream_buf.begin() + offset);
                }
            } else {
                // actual_length == 0 (ZLP), just continue reading
                continue;
            }
        } else if (r == LIBUSB_ERROR_TIMEOUT) {
            if (!transmission_started) {
                LOG_ERROR << "[-] Timeout waiting for download response." << std::endl;
                break;
            }
            timeouts++;
            if (timeouts > 5) {
                LOG_ERROR << "[-] Download timed out (no activity for 10 seconds)." << std::endl;
                break;
            }
        } else {
            LOG_ERROR << "[-] USB transfer error: " << r << std::endl;
            break;
        }
    }

    if (!transmission_ended) {
        LOG_ERROR << "[-] Download failed or interrupted." << std::endl;
        file.close();
        std::remove(local_path.c_str());
    }
}


struct RxThreadCtx {
    libusb_device_handle* dev_handle;
    std::atomic<bool>* keep_running;
    uint32_t session_id;
};

static void rx_thread_mux(RxThreadCtx* ctx) {
    uint8_t buf[4096];
    int actual_length;
    
    while (*ctx->keep_running) {
        int r = libusb_bulk_transfer(ctx->dev_handle, 0x84, buf, sizeof(buf), &actual_length, 1000);
        
        if (r == 0 && actual_length > 0) {
            size_t offset = 0;
            
            while (offset + sizeof(PacketHeader) <= (size_t)actual_length) {
                PacketHeader* hdr = (PacketHeader*)(buf + offset);
                
                if (hdr->magic != PKT_MAGIC) {
                    offset++;
                    continue;
                }
                
                if (offset + sizeof(PacketHeader) + hdr->length <= (size_t)actual_length) {
                    uint8_t* payload = buf + offset + sizeof(PacketHeader);
                    
                    if (hdr->type == PKT_TTY_OUT && hdr->session_id == ctx->session_id) {
                        std::cout.write((char*)payload, hdr->length);
                        std::cout.flush(); 
                    } else if (hdr->type == PKT_TTY_STOP && hdr->session_id == ctx->session_id) {
                        *ctx->keep_running = false;
                    }
                    
                    offset += sizeof(PacketHeader) + hdr->length;
                } else {
                    break;
                }
            }
        } else if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
            *ctx->keep_running = false;
            break;
        }
    }
}

void PSVR2Bridge::shell(const std::string& shell_cmd, uint32_t attach_session_id) {
    if (!dev) {
        LOG_ERROR << "[-] USB device handle invalid." << std::endl;
        return;
    }
    
    uint32_t current_session_id = attach_session_id;

    if (current_session_id == 0) {
        LOG_INFO << "[*] Starting remote shell: '" << shell_cmd << "'" << std::endl;
        if (!send_packet(PKT_TTY_START, 0, (const uint8_t*)shell_cmd.c_str(), static_cast<uint16_t>(shell_cmd.length()))) {
            LOG_ERROR << "[-] Failed to send TTY start command." << std::endl;
            return;
        }

        uint8_t buf[4096];
        int actual;
        while (current_session_id == 0) {
            int r = libusb_bulk_transfer(dev, 0x84, buf, sizeof(buf), &actual, 1000);
            if (r == 0 && actual > 0) {
                size_t offset = 0;
                while (offset + sizeof(PacketHeader) <= (size_t)actual) {
                    PacketHeader* hdr = (PacketHeader*)(buf + offset);
                    if (hdr->magic == PKT_MAGIC && hdr->type == PKT_TTY_STARTED) {
                        current_session_id = hdr->session_id;
                        break;
                    }
                    offset += sizeof(PacketHeader) + hdr->length;
                }
            } else if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
                LOG_ERROR << "[-] Failed to get session ID." << std::endl;
                return;
            }
        }
    } else {
        LOG_INFO << "[*] Attaching to session " << current_session_id << std::endl;
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

    LOG_INFO << "[*] Entered headset shell session " << current_session_id << ". Press Ctrl+] to detach." << std::endl;

    std::atomic<bool> keep_running{ true };
    RxThreadCtx ctx = { dev, &keep_running, current_session_id };
    std::thread t_rx(rx_thread_mux, &ctx);

    while (keep_running) {
        if (_kbhit()) {
            int c = _getch();
            if (c == 0x1D) { // Ctrl+]
                LOG_INFO << "\n[*] Detaching from shell..." << std::endl;
                send_packet(PKT_TTY_STOP, current_session_id, nullptr, 0);
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
                    if (!send_packet(PKT_TTY_IN, current_session_id, (uint8_t*)seq, 3)) {
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
            if (!send_packet(PKT_TTY_IN, current_session_id, &out_byte, 1)) {
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

void PSVR2Bridge::list_sessions() {
    if (!dev) return;
    
    if (!send_packet(PKT_TTY_LIST, 0, nullptr, 0)) return;

    uint8_t buf[4096];
    int actual;
    while (true) {
        int r = libusb_bulk_transfer(dev, 0x84, buf, sizeof(buf), &actual, 1000);
        if (r == 0 && actual > 0) {
            size_t offset = 0;
            while (offset + sizeof(PacketHeader) <= (size_t)actual) {
                PacketHeader* hdr = (PacketHeader*)(buf + offset);
                if (hdr->magic == PKT_MAGIC) {
                    if (hdr->type == PKT_TTY_LIST_RESP) {
                        uint8_t* payload = buf + offset + sizeof(PacketHeader);
                        std::cout << "\nActive Sessions:\n";
                        std::cout.write((char*)payload, hdr->length);
                        std::cout.flush();
                        return;
                    }
                    offset += sizeof(PacketHeader) + hdr->length;
                } else {
                    offset++;
                }
            }
        } else if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
            break;
        }
    }
}

void PSVR2Bridge::kill_session(uint32_t session_id) {
    if (!dev) return;
    send_packet(PKT_TTY_STOP, session_id, nullptr, 0);
    LOG_INFO << "[*] Sent kill signal to session " << session_id << "\n";
}