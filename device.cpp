#include "device.hpp"

#include <iomanip>
#include <sstream>
#include <thread>

#include "logger.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#pragma pack(push, 1)
struct FirmwareInfo {
    uint32_t Version;
    uint32_t Reserved0;
    char CommitHash[40];
    uint32_t Unknown0;
    uint32_t Unknown1;
    char PcbId[16];
    uint32_t Unknown2;
    uint32_t Reserved1;
    uint32_t RecoveryVersion;
};
#pragma pack(pop)

PSVR2Device::PSVR2Device() : ctx(nullptr), dev_handle(nullptr) { libusb_init(&ctx); }

PSVR2Device::~PSVR2Device() {
    if (dev_handle) {
        libusb_release_interface(dev_handle, CTRL_INTERFACE);
        libusb_close(dev_handle);
    }
    if (ctx) {
        libusb_exit(ctx);
    }
}

int PSVR2Device::raw_ctrl(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, std::vector<uint8_t>& data, int timeout) {
    if (!dev_handle) return -1;

    uint16_t wLength = static_cast<uint16_t>(data.size());

    return libusb_control_transfer(dev_handle, bmRequestType, bRequest, wValue, wIndex, data.data(), wLength, timeout);
}

bool PSVR2Device::connect(bool ignore_version) {
    disconnect();

    dev_handle = libusb_open_device_with_vid_pid(ctx, VID, PID);
    if (!dev_handle) return false;

    libusb_set_auto_detach_kernel_driver(dev_handle, 1);

    libusb_config_descriptor* cfg = nullptr;
    libusb_device* dev = libusb_get_device(dev_handle);

#ifndef _WIN32
    // Detach both the control interface (0) and our Bulk interface
    for (int iface : {CTRL_INTERFACE, BRIDGE_INTERFACE}) {
        if (libusb_kernel_driver_active(dev_handle, iface) == 1) {
            libusb_detach_kernel_driver(dev_handle, iface);
        }
    }
#endif

    // Explicitly claim the primary bulk interface
    libusb_claim_interface(dev_handle, CTRL_INTERFACE);
    libusb_claim_interface(dev_handle, BRIDGE_INTERFACE);

    firmware_mismatch = false;

    // Check firmware version
    uint32_t version = 0;
    while (version == 0 && !ignore_version) {
        std::vector<uint8_t> info_buffer(8 + sizeof(FirmwareInfo), 0);
        int ctrl_res = raw_ctrl(0xC2, 0x01, 0x81, CTRL_INTERFACE, info_buffer, 1000);
        if (ctrl_res < 0) {
            libusb_release_interface(dev_handle, CTRL_INTERFACE);
            libusb_release_interface(dev_handle, BRIDGE_INTERFACE);
            libusb_close(dev_handle);
            dev_handle = nullptr;
            return false;
        }
        if (ctrl_res >= static_cast<int>(8 + sizeof(FirmwareInfo))) {
            FirmwareInfo* fw_info = reinterpret_cast<FirmwareInfo*>(&info_buffer[8]);
            version = fw_info->Version;
        }
        if (version == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }

    if (version != 0x06000102 && !ignore_version) {
        firmware_mismatch = true;
        std::ostringstream oss_ver;
        oss_ver << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << version;
        std::string action = (version > 0x06000102) ? "downgrade" : "upgrade";
        LOG_ERROR << "Your headset is on firmware version " << oss_ver.str() << ", please " << action << " to 0x06000102 (v06.00) to use vr2jb." << std::endl;
        if (version > 0x06000102) {
#ifdef _WIN32
            const char* command = ".\\vr2jb.exe";
#else
            const char* command = "./vr2jb";
#endif
            LOG_ERROR << "Try running '" << command << " downgrade' to start downgrading." << std::endl;
        } else {
            LOG_ERROR << "Use PSVR2Updater to upgrade to firmware v06.00." << std::endl;
        }

        libusb_release_interface(dev_handle, CTRL_INTERFACE);
        libusb_release_interface(dev_handle, BRIDGE_INTERFACE);
        libusb_close(dev_handle);
        dev_handle = nullptr;
        return false;
    }

    return true;
}

bool PSVR2Device::reconnect(int retries) {
    for (int i = 0; i < retries; i++) {
        if (connect(true)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

void PSVR2Device::disconnect() {
    if (dev_handle) {
        libusb_release_interface(dev_handle, CTRL_INTERFACE);
        libusb_release_interface(dev_handle, BRIDGE_INTERFACE);
        libusb_close(dev_handle);
        dev_handle = nullptr;
    }
}

std::vector<uint8_t> PSVR2Device::hid_get(uint8_t report_id, uint8_t sub_id, uint16_t length) {
    std::vector<uint8_t> data(length, 0);

    int res = raw_ctrl(0xA1, 0x01, (sub_id << 8) | report_id, CTRL_INTERFACE, data);
    if (res < 0) return {};
    data.resize(res);
    return data;
}

int PSVR2Device::hid_set(uint8_t report_id, uint8_t sub_id, const std::vector<uint8_t>& data_in, int timeout) {
    std::vector<uint8_t> data = data_in;

    return raw_ctrl(0x21, 0x09, (sub_id << 8) | report_id, CTRL_INTERFACE, data, timeout);
}

bool PSVR2Device::vendor_set(uint8_t report_id, uint16_t subcmd, const std::vector<uint8_t>& data, int timeout) {
    std::vector<uint8_t> buf;
    buf.reserve(8 + data.size());
    buf.push_back(report_id);
    buf.push_back(0x00);
    buf.push_back(subcmd & 0xFF);
    buf.push_back((subcmd >> 8) & 0xFF);
    buf.push_back(data.size() & 0xFF);
    buf.push_back((data.size() >> 8) & 0xFF);
    buf.push_back(0x00);
    buf.push_back(0x00);
    buf.insert(buf.end(), data.begin(), data.end());

    int res = raw_ctrl(0x42, 0x09, 0, CTRL_INTERFACE, buf, timeout);

    return res >= 0;
}

std::vector<uint8_t> PSVR2Device::get_config_desc(uint16_t length) {
    std::vector<uint8_t> data(length, 0);
    int res = raw_ctrl(0x80, 0x06, (2 << 8) | 0, 1, data);
    if (res < 0) return {};
    data.resize(res);
    return data;
}

bool PSVR2Device::trigger_get_alt() {
    uint8_t buffer[1] = {0};
    int res = libusb_control_transfer(dev_handle, LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_INTERFACE, LIBUSB_REQUEST_GET_INTERFACE, 0, CTRL_INTERFACE, buffer,
                                      sizeof(buffer), 1000);
    return res >= 0;
}

bool PSVR2Device::force_reboot() {
    std::vector<uint8_t> payload = {};
    return vendor_set(0x05, 0x02, payload, 1000);
}