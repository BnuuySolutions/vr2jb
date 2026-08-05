#include "downgrade.hpp"
#include "logger.hpp"

#include <cstring>
#include <vector>

#define REPORT_ID_SET_AUTH1_DATA 0xF0
#define SUB_ID_H_CHALLENGE_1 0x01
#define SET_AUTH1_DATA_BLOCK_SIZE 56
#define SET_AUTH1_DATA_OVERFLOW_VAL 0x8B

struct usb_auth1_data {
    uint8_t report_id;
    uint8_t sub_id;
    uint8_t sequence_number;
    uint8_t block_number;
    uint8_t data[SET_AUTH1_DATA_BLOCK_SIZE];
    uint32_t crc32;
};

#pragma pack(push, 1)
struct usb_auth1_data_overflow {
    struct usb_auth1_data auth1_data;
    uint8_t extra;
};
#pragma pack(pop)

static uint16_t hmd2_dummy_set(PSVR2Device& usb) {
    if (!usb.get_handle()) {
        return 0;
    }

    struct usb_auth1_data auth1_data;
    memset(&auth1_data, 0, sizeof(auth1_data));
    auth1_data.report_id = REPORT_ID_SET_AUTH1_DATA;
    auth1_data.sub_id = SUB_ID_H_CHALLENGE_1;

    std::vector<uint8_t> data;
    data.reserve(sizeof(auth1_data));
    data.insert(data.end(), (uint8_t*)&auth1_data, (uint8_t*)&auth1_data + sizeof(auth1_data));

    return usb.hid_set(REPORT_ID_SET_AUTH1_DATA, SUB_ID_H_CHALLENGE_1, data, 250);
}

static uint16_t hmd2_overflow_val(PSVR2Device& usb, uint8_t val) {
    if (!usb.get_handle()) {
        return 0;
    }

    struct usb_auth1_data_overflow auth1_data_overflow;
    memset(&auth1_data_overflow, 0, sizeof(auth1_data_overflow));
    auth1_data_overflow.auth1_data.report_id = REPORT_ID_SET_AUTH1_DATA;
    auth1_data_overflow.auth1_data.sub_id = SUB_ID_H_CHALLENGE_1;
    auth1_data_overflow.extra = val;

    std::vector<uint8_t> data;
    data.reserve(sizeof(auth1_data_overflow));
    data.insert(data.end(), (uint8_t*)&auth1_data_overflow, (uint8_t*)&auth1_data_overflow + sizeof(auth1_data_overflow));

    return usb.hid_set(REPORT_ID_SET_AUTH1_DATA, SUB_ID_H_CHALLENGE_1, data, 250);
}

void do_downgrade(PSVR2Device& usb) {
    LOG_INFO << "This program will attempt to crash your PS VR2 as many times as "
             << "possible until you enter \"recovery mode\" (v01.10-v05.00), allowing you to "
             << "downgrade to any firmware at or above the recovery version of your headset.\n";
    LOG_INFO << "To get started, make sure your PS VR2 is powered off and plugged in, "
             << "when you see the \"Waiting for PS VR2\" message, press the power button.\n\n";

    LOG_INFO << "Instructions:\n";
    LOG_INFO << "1.) Wait until you see \"Successfully crashed PS VR2\", if you do "
             << "not get this message, your PS VR2 may be incompatible currently.\n";
    LOG_INFO << "2.) Upon getting that message, quickly (within 1-2 seconds) disconnect "
             << "your PS VR2 (unplug from adapter or unplug USB-C, DO NOT HOLD POWER BUTTON).\n";
    LOG_INFO << "3.) Plug your PS VR2 back in, and press the power button. If "
             << "everything goes correctly, the PS VR2 should get crashed immediately again on boot.\n";
    LOG_INFO << "4.) Repeat until you see \"Successfully entered recovery mode\", "
             << "after this, your PS VR2 will be in \"recovery mode\" (v01.10).\n";
    LOG_INFO << "4.1.) Please note that you may have to repeat this about 15 or more times until "
             << "recovery mode is entered.\n\n";

    LOG_INFO << "[*] Waiting for PS VR2...\n";

    while (1) {
        if (!usb.get_handle()) {
            usb.reconnect(100);
            continue;
        }

        if (hmd2_dummy_set(usb) != 64) {
            LOG_WARN << "[!] Initial dummy test failed. Attempting USB connection again...\n";
            usb.reconnect(100);
        } else {
            break;
        }
    }

    while (1) {
        if (!usb.get_handle()) {
            usb.reconnect(100);
            continue;
        }

        if (hmd2_dummy_set(usb) != 64) {
            usb.reconnect(100);
            continue;
        }

        LOG_INFO << "[*] Attempting to crash PS VR2...\n";

        uint16_t result = hmd2_overflow_val(usb, SET_AUTH1_DATA_OVERFLOW_VAL);
        if (result != sizeof(struct usb_auth1_data_overflow)) {
            LOG_WARN << "[!] Attempting to crash PS VR2 failed, got an unexpected result. result: "
                     << result << ", expected: " << sizeof(struct usb_auth1_data_overflow) << "\n";
            continue;
        }

        int did_crash = 0;

        if (hmd2_dummy_set(usb) != 64) {
            LOG_INFO << "[!] Successfully crashed PS VR2 (1), please follow the instructions.\n";
            usb.reconnect(100);
            did_crash = 1;
        }

        if (!did_crash) {
            if (hmd2_dummy_set(usb) != 64) {
                LOG_INFO << "[!] Successfully crashed PS VR2 (2), please follow the instructions.\n";
                usb.reconnect(100);
                did_crash = 1;
            }
        }

        if (!did_crash) {
            if (hmd2_dummy_set(usb) != 64) {
                LOG_INFO << "[!] Successfully crashed PS VR2 (3), please follow the instructions.\n";
                usb.reconnect(100);
                did_crash = 1;
            }
        }

        if (did_crash) {
            continue;
        }

        LOG_INFO << "[!] Successfully entered recovery mode!\n";
        break;
    }
}
