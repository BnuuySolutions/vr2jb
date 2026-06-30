#include "device.hpp"
#include "rw.hpp"
#include "shell.hpp"
#include "bridge.hpp"
#include "logger.hpp"

#include <iostream>
#include <thread>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    bool interactive = false;
    std::vector<std::string> command_args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i") {
            interactive = true;
        } else if (arg == "-v") {
            Logger::set_level(LogLevel::L_DEBUG);
        } else {
            command_args.push_back(arg);
        }
    }

    PSVR2Device usb;

    LOG_INFO << "[1/3] Connecting to PSVR2...\n";
    if (!usb.connect()) {
        if (usb.has_firmware_mismatch()) {
            return 1;
        }
        LOG_ERROR << "[-] Device not found. Check USB.\n";
        return 1;
    }
    LOG_INFO << "[+] Connected.\n";

    KernelRW krw(&usb);
    
    // Give it 10 tries. It can happen that we don't get the sauth heap.
    for (int i = 0; i < 10; i++) {
        LOG_INFO << "[2/3] Setting up read...\n";
        if (!krw.setup_read()) {
            LOG_ERROR << "[-] Exploit init failed. Rebooting HMD to try again...\n";
            usb.force_reboot();
        }
        else {
            break;
        }
        
        bool connected = false;
        for (int i = 0; i < 10; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            connected = usb.connect();

            if (connected) {
                break;
            }
        }

        if (!connected) {
            if (usb.has_firmware_mismatch()) {
                return 1;
            }
            LOG_ERROR << "[-] Unable to reconnect to HMD. Check your USB connections.\n";
        }
    }

    LOG_INFO << "[3/3] Setting up write...\n";
    
    if (!krw.setup_write()) {
        LOG_WARN << "[!] Write unavailable — rebooting.\n";
        usb.force_reboot();
        return 1;
    }
    
    krw.setup_jb_env();
    
    PSVR2Bridge bridge(usb.get_handle());
    bridge.upload("./busybox", "/tmp/busybox");
    bridge.shell("/tmp/busybox mkdir /tmp/bin");
    bridge.shell("/tmp/busybox --install /tmp/bin");

    // Start interactive shell
    PSVR2Shell shell(&usb, &krw, &bridge);

    if (interactive) {
        try {
            shell.cmdloop();
        } catch (...) {
            LOG_INFO << "[*] Bye.\n";
        }
    } else {
        if (!command_args.empty()) {
            shell.execute_command(command_args);
        } else {
            LOG_ERROR << "[-] No command specified. Use -i for interactive mode.\n";
        }
    }

    return 0;
}