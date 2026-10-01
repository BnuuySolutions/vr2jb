#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct Patch {
  std::string name;
  uint64_t offset;
  std::string hex_data;
};

std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

pid_t find_pid(const std::string &process_name) {
  DIR *dir = opendir("/proc");
  if (!dir)
    return -1;

  struct dirent *ent;
  while ((ent = readdir(dir)) != nullptr) {
    if (!isdigit(*ent->d_name))
      continue;

    pid_t pid = std::stoi(ent->d_name);
    std::string comm_path = std::string("/proc/") + ent->d_name + "/comm";
    std::ifstream comm_file(comm_path);
    std::string name;

    if (std::getline(comm_file, name)) {
      if (name == process_name) {
        closedir(dir);
        return pid;
      }
    }
  }
  closedir(dir);
  return -1;
}

uint64_t get_base_address(pid_t pid, const std::string &process_name) {
  std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream maps_file(maps_path);
  std::string line;

  while (std::getline(maps_file, line)) {
    // The first executable region we see should be the main binary .text section
    if (line.find("r-xp") != std::string::npos &&
        line.find(process_name) != std::string::npos) {
      size_t dash = line.find('-');
      if (dash != std::string::npos) {
        std::string start_str = line.substr(0, dash);
        return std::stoull(start_str, nullptr, 16);
      }
    }
  }
  return 0;
}

bool patch_process_memory(pid_t pid, uint64_t vaddr,
                          const std::vector<uint8_t> &bytes) {
  std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";

  int mem_fd = open(mem_path.c_str(), O_RDWR);
  if (mem_fd < 0) {
    perror("[-] Failed to open /proc/pid/mem");
    return false;
  }

  if (lseek(mem_fd, vaddr, SEEK_SET) == (off_t)-1) {
    perror("[-] Failed to seek to virtual address");
    close(mem_fd);
    return false;
  }

  ssize_t written = write(mem_fd, bytes.data(), bytes.size());
  close(mem_fd);

  if (written != (ssize_t)bytes.size()) {
    std::cerr << "[-] Wrote " << std::dec << written << " of " << bytes.size()
              << " bytes.\n";
    return false;
  }

  return true;
}

int main() {
  // Process name
  std::string target_proc = "VrhmdMain";

  // File name for executable
  std::string target_map = "vrhmd_main.elf";

  std::cout << "[*] Looking for process: " << target_proc << "\n";
  pid_t pid = find_pid(target_proc);

  if (pid <= 0) {
    std::cerr << "[-] Could not find " << target_proc << " running.\n";
    return 1;
  }

  std::cout << "[+] Found " << target_proc << " at PID " << pid << "\n";

  uint64_t base_addr = get_base_address(pid, target_map);
  if (base_addr == 0) {
    std::cerr << "[-] Could not determine executable base address.\n";
    return 1;
  }

  std::cout << "[+] Base Address: 0x" << std::hex << base_addr << "\n";

  std::vector<Patch> patches = {
      {"Patch 1", 0x1a088d, "00"},
      {"Patch 2", 0x1ee90, "1f400071"},
      {"Patch 3", 0x1ee98, "e01b8e92"},
      {"Patch 4", 0xc5bf4, "1f2003d5"},
      {"Patch 5", 0x11968, "680c00f01f3522391f2003d5"}
  };

  std::cout << "[*] Applying patches...\n";

  int success_count = 0;
  for (const auto &p : patches) {
    uint64_t target_vaddr = base_addr + p.offset;
    auto bytes = hex_to_bytes(p.hex_data);

    std::cout << "    -> " << p.name << " at 0x" << std::hex << target_vaddr
              << " (" << bytes.size() << " bytes)... ";

    if (patch_process_memory(pid, target_vaddr, bytes)) {
      std::cout << "OK\n";
      success_count++;
    } else {
      std::cout << "FAILED\n";
    }
  }

  std::cout << "[*] Complete. (" << std::dec << success_count << "/"
            << patches.size() << " successful)\n";
  return 0;
}