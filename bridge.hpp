#pragma once

#include <libusb.h>
#include <string>

class PSVR2Bridge {
public:
    PSVR2Bridge(libusb_device_handle* dev_handle);

    void upload(const std::string& local_path, const std::string& remote_path);
    void download(const std::string& remote_path, const std::string& local_path);
    void shell(const std::string& shell_cmd, uint32_t attach_session_id = 0);
    void list_sessions();
    void kill_session(uint32_t session_id);

private:
    libusb_device_handle* dev;
    
    bool send_packet(uint8_t type, uint32_t session_id, const uint8_t* payload, uint16_t len);
};