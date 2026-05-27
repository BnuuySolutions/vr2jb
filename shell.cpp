#include "bridge.hpp"
#include "device.hpp"
#include "shell.hpp"
#include "logger.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

PSVR2Shell::PSVR2Shell(PSVR2Device* device, KernelRW* kernel_rw, PSVR2Bridge* bridge) : usb(device), krw(kernel_rw), bridge(bridge) {
}

std::vector<std::string> PSVR2Shell::split_args(const std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) tokens.push_back(token);
    return tokens;
}

void PSVR2Shell::cmdloop() {
    std::string line;
    while (true) {
        std::cout << prompt;
        if (!std::getline(std::cin, line)) break;
        
        auto args = split_args(line);
        if (args.empty()) continue;
        
        std::string cmd = args[0];

        if (cmd == "exit" || cmd == "quit") break;
        
        execute_command(args);
    }
}

void PSVR2Shell::execute_command(const std::vector<std::string>& args) {
    if (args.empty()) return;

    std::string cmd = args[0];
    std::vector<std::string> cmd_args(args.begin() + 1, args.end());

    if (cmd == "get") do_get(cmd_args);
    else if (cmd == "write") do_write(cmd_args);
    else if (cmd == "reboot") do_reboot(cmd_args);
    else if (cmd == "shell") do_shell(cmd_args);
    else if (cmd == "upload") do_upload(cmd_args);
    else if (cmd == "exec") do_exec(cmd_args);
    else LOG_ERROR << "[-] Unknown command: " << cmd << "\n";
}

void PSVR2Shell::do_get(const std::vector<std::string>& args) {
    if (args.empty()) {
        LOG_ERROR << "Usage: get <hex_address> [size]\n";
        return;
    }
    
    uint64_t addr = std::stoull(args[0], nullptr, 16);
    size_t size = args.size() > 1 ? std::stoull(args[1], nullptr, 0) : 0x1000;
    
    std::string fname = "dump_" + args[0] + ".bin";
    LOG_INFO << "[*] Dumping memory 0x" << std::hex << addr << " (" << std::dec << size << "B)...\n";
    
    std::ofstream file(fname, std::ios::binary);
    size_t done = 0;
    while (done < size) {
        size_t cl = std::min((size_t)4096, size - done);
        auto data = krw->read(addr + done, cl);
        if (data.empty()) {
            LOG_ERROR << " [FAIL]\n";
            return;
        }
        file.write(reinterpret_cast<char*>(data.data()), data.size());
        done += data.size();
    }
    LOG_INFO << "[+] Saved " << fname << "\n";
}

void PSVR2Shell::do_write(const std::vector<std::string>& args) {
    if (args.size() != 2) {
        LOG_ERROR << "Usage: write <addr> <u64_value>\n";
        return;
    }
    uint64_t addr = std::stoull(args[0], nullptr, 16);
    uint64_t val = std::stoull(args[1], nullptr, 16);
    
    LOG_INFO << "[*] Writing 0x" << std::hex << val << " → 0x" << addr << "\n";
    if (krw->write_u64_slow(addr, val)) {
        LOG_INFO << "[+] Done.\n";
    } else {
        LOG_ERROR << "[-] Failed.\n";
    }
}

void PSVR2Shell::do_reboot(const std::vector<std::string>& args) {
    LOG_WARN << "[!] Rebooting device via USB COMMAND RESTART...\n";
    if (usb->force_reboot()) {
        LOG_INFO << "    Device is rebooting. Exiting shell.\n";
        exit(0);
    } else {
        LOG_ERROR << "[-] Failed to send reboot command.\n";
    }
}

void PSVR2Shell::do_upload(const std::vector<std::string>& args) {
    if (args.size() != 2) {
        LOG_ERROR << "Usage: upload <local_path> <remote_path>\n";
        return;
    }
    
    bridge->upload(args[0], args[1]);
}

void PSVR2Shell::do_exec(const std::vector<std::string>& args) {
    if (args.empty()) {
        LOG_ERROR << "Usage: exec <command> [args...]\n";
        return;
    }
    
    std::string cmd;
    for (const auto& a : args) cmd += a + " ";
    cmd.pop_back(); // Remove trailing space

    bridge->exec(cmd);
}

void PSVR2Shell::do_shell(const std::vector<std::string>& args) {
    // Determine which shell to run. Default to "sh" if no args provided.
    std::string shell_cmd = "sh";
    if (!args.empty()) {
        shell_cmd = "";
        for (const auto& a : args) shell_cmd += a + " ";
        shell_cmd.pop_back(); // Remove trailing space
    }

    bridge->shell(shell_cmd);
}