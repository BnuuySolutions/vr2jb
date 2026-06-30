#pragma once

#include <libusb.h>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

class PSVR2Device {
public:
    static constexpr uint16_t VID = 0x054c;
    static constexpr uint16_t PID = 0x0cde;
    static constexpr int CTRL_INTERFACE = 0;
    static constexpr int BRIDGE_INTERFACE = 4;
    static constexpr int KEEP_ALIVE_INTERVAL = 30;

    PSVR2Device();
    ~PSVR2Device();
    
    bool force_reboot();
    uint64_t retrieve_get_alt();

    bool connect();
    bool reconnect(int retries = 10);
    
    void send_keep_alive();
    void check_keep_alive();

    std::vector<uint8_t> hid_get(uint8_t report_id, uint8_t sub_id, uint16_t length);
    int hid_set(uint8_t report_id, uint8_t sub_id, const std::vector<uint8_t>& data);
    bool vendor_set(uint8_t report_id, uint16_t subcmd, const std::vector<uint8_t>& data = {}, int timeout = 1000);
    std::vector<uint8_t> get_config_desc(uint16_t length = 9);
    bool trigger_get_alt();
    
    libusb_device_handle* get_handle() const { return dev_handle; }
    int raw_ctrl(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, std::vector<uint8_t>& data, int timeout = 500);
    
    bool has_firmware_mismatch() const { return firmware_mismatch; }
private:
    libusb_context* ctx;
    libusb_device_handle* dev_handle;
    
    std::chrono::steady_clock::time_point last_keep_alive;
    
    std::thread recv_thread_handle;
    std::atomic<bool> running;

    bool firmware_mismatch = false;

    void recv_thread();
};