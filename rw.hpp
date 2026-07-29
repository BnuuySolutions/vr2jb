#pragma once

#include "device.hpp"

#include <string>
#include <vector>

struct Registers {
    uint64_t req = 0;
    uint64_t mep = 0;
    uint64_t x21 = 0;
};

class KernelRW {
public:
    KernelRW(PSVR2Device* device) : usb(device) {}
    
    bool setup_read();
    uint64_t retrieve_get_alt();
    void repair_descriptor();

    bool setup_write();
    Registers discover_registers();

    std::vector<uint8_t> read(uint64_t addr, size_t length);
    uint64_t read_ptr(uint64_t addr);

    bool direct_exchange(uint64_t target, uint64_t helper, uint8_t* out, size_t length);
    bool direct_read_raw(uint64_t address, uint8_t* out, size_t length);

    bool write_byte(uint64_t addr, uint8_t val);
    bool write_u64_slow(uint64_t addr, uint64_t val);
    bool write_u64_fast(uint64_t addr, uint64_t val);
    bool write_u64_safe(uint64_t addr, uint64_t val) { return write_u64_fast(addr, val); }

    bool write_data_slow(uint64_t addr, const std::vector<uint8_t>& data);
    bool write_data_fast(uint64_t addr, const std::vector<uint8_t>& data);
    bool execute_tlb_flush();
    bool setup_jb_env();
    bool trigger_workqueue(uint64_t target_func_addr);
    bool upload_to_tmp(const std::string& local_path, const std::string& remote_name);
    bool execute_elf(const std::string& target_path, const std::vector<std::string>& args);
    bool fast_mass_patch_pte(uint64_t vmalloc_base, size_t total_size);
    bool patch_rwx(uint64_t vaddr, size_t total_size);
private:
    PSVR2Device* usb;
    
    uint64_t request_buffer = 0;
    uint64_t sauth = 0;
    
    Registers cached_registers {};
    uint64_t rwx_base = 0;
    std::vector<uint8_t> _trigger_overflow(const std::vector<uint8_t>& payload);
};