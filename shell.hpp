#pragma once

#include "device.hpp"
#include "rw.hpp"
#include "bridge.hpp"

#include <string>
#include <vector>

class PSVR2Shell {
public:
    PSVR2Shell(PSVR2Device* usb, KernelRW* kernel_rw, PSVR2Bridge* bridge);
    void cmdloop();
    void execute_command(const std::vector<std::string>& args);

private:
    PSVR2Device* usb;
    KernelRW* krw;
    PSVR2Bridge* bridge;
    std::string prompt = "> ";

    // Helpers
    std::vector<std::string> split_args(const std::string& input);

    // Core Commands
    void do_write(const std::vector<std::string>& args);
    void do_reboot(const std::vector<std::string>& args);
    void do_get(const std::vector<std::string>& args);

    // Integration Commands
    void do_shell(const std::vector<std::string>& args);
    void do_upload(const std::vector<std::string>& args);
    void do_download(const std::vector<std::string>& args);
    void do_attach(const std::vector<std::string>& args);
    void do_kill(const std::vector<std::string>& args);
};