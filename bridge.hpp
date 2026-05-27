#pragma once

#include <libusb.h>
#include <string>

class PSVR2Bridge {
public:
    PSVR2Bridge(libusb_device_handle* dev_handle);

    void upload(const std::string& local_path, const std::string& remote_path);
    void exec(const std::string& cmd);
    void shell(const std::string& shell_cmd);

private:
    libusb_device_handle* dev;
    
    bool send_packet(uint8_t type, const uint8_t* payload, uint16_t len);
};