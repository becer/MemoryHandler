#include <iostream>
#include <string>
#include <sys/types.h>
#include <mutex>
#include <sstream>
#include <vector>
#include <dirent.h>
#include <thread>
#include <fstream>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>


//=======PRE SETS ====================================
const size_t BUFFER_SIZE = 4096;

struct MemoryRegion{
  uintptr_t start;
  uintptr_t end;
  std::string permissions;
};

//=======FUNCOES AUXILIARES ==========================

std::vector<MemoryRegion> getValidMemoryRegions(pid_t procID){
  std::vector<MemoryRegion> regions;

  std::string maps_path = "/proc/" + std::to_string(procID) + "/maps";
  std::ifstream maps_file(maps_path);
  if(!maps_file.is_open()) return regions;

  std::string line;
  while(std::getline(maps_file, line)){
    MemoryRegion region;
    std::stringstream ss(line);
    std::string addressRange;

    ss >> addressRange;

    size_t dash_pos = addressRange.find('-');
    if(dash_pos != std::string::npos){
      region.start = std::stoull(addressRange.substr(0, dash_pos), nullptr, 16);
      region.end = std::stoull(addressRange.substr(dash_pos + 1), nullptr, 16);
    }

    ss >> region.permissions;
    if(region.permissions.find('r') != std::string::npos) regions.push_back(region);
  }
  return regions;
}

bool readMemoryBlock(uintptr_t address, uint8_t* buffer, size_t size, pid_t procID){
  std::string mem_path = "/proc/" + std::to_string(procID) + "/mem";
  std::ifstream mem_file(mem_path, std::ios::binary);

  if(!mem_file.is_open()) return false;

  mem_file.seekg(address);
  mem_file.read(reinterpret_cast<char*>(buffer), size);

  bool success = !mem_file.fail();
  mem_file.close();

  return success;
}

template<typename T>
void scanRegion(const MemoryRegion& region, T value, std::vector<uintptr_t>& results, std::mutex& resultsMutex, pid_t procID){
  if(region.permissions.find('r') == std::string::npos) return; 

  std::vector<uintptr_t> localResults;
  std::vector<uint8_t> buffer(BUFFER_SIZE);
  for(uintptr_t address = region.start; address < region.end; address += BUFFER_SIZE){
    size_t bytesToRead = std::min(BUFFER_SIZE, size_t(region.end - address));

    if(readMemoryBlock(address, buffer.data(), bytesToRead, procID)){
      for(size_t offset = 0; offset + sizeof(T) <= bytesToRead; offset += sizeof(T)){
        T memoryValue;
        memcpy(&memoryValue, buffer.data() + offset, sizeof(T));
        if(memoryValue == value) localResults.push_back(address + offset);
      }
    }
  }

  if(!localResults.empty()){
    std::lock_guard<std::mutex> lock(resultsMutex);
    results.insert(results.end(), localResults.begin(), localResults.end());
  }
}

//=======MINHA CLASSE ===========================================

class MemoryHandler{
private:
  pid_t procID;
  std::mutex resultsMutex;
  std::string mem_path;
public:
  MemoryHandler(const std::string& procName){ Attach(procName);}
  void Attach(const std::string& procName){
    DIR* directory;
    struct dirent* entry;

    directory = opendir("/proc");
    if(directory == NULL) throw("FAILED::ATTACH::/PROC");

    while((entry = readdir(directory))){
      if(isdigit(entry->d_name[0])){
        std::string pid_string(entry->d_name);
        std::string comm_path = "/proc/" + pid_string + "/comm";
        std::ifstream comm_file(comm_path);

        if(comm_file.is_open()){
          std::string comm_name;
          std::getline(comm_file, comm_name);
          comm_file.close();

          if(!comm_name.empty() && comm_name.back() == '\n') comm_name.pop_back();
          if(comm_name == procName){
            mem_path = "/proc/" + pid_string + "/mem";
            procID = std::stoi(entry->d_name);
            closedir(directory);
            std::cout << "Found process: " << procName << " [PID]: " << procID << std::endl;
            return;
          }
        }
      }
    }
    closedir(directory);
    throw("FAILED::FOUNDING::PROCESS::" + procName);
  }

  template<typename T>
  T readMemory(std::uintptr_t address){
    T value;
    std::ifstream mem_file(mem_path, std::ios::binary);
    if(!mem_file.is_open()) throw("FAILED::OPENING::MEMFILE::FROM::READMEMORY");

    mem_file.seekg(address);
    mem_file.read(reinterpret_cast<char*>(&value), sizeof(T));

    if(!mem_file) throw("FAILED::READ::MEMFILE::FROM::READMEMORY");
    mem_file.close();
    return value;
  }

  template<typename T>
  bool writeMemory(std::uintptr_t address, T value){
    std::ofstream mem_file(mem_path, std::ios::binary);
    if(!mem_file.is_open()) throw("FAILED::OPENING::MEMFILE::FROM::WRITEMEMORY");

    mem_file.seekp(address);
    mem_file.write(reinterpret_cast<char*>(&value), sizeof(T));

    bool success = mem_file.good();
    mem_file.close();
    return success;
  }

  template<typename T>
  std::vector<uintptr_t> parallelScan(T value, int numThreads = 0){
    auto regions = getValidMemoryRegions(procID);
    std::vector<MemoryRegion> usefulRegions;
    size_t totalSize = 0;
    for(const auto& region : regions){
      if(region.permissions.find('r') == std::string::npos) continue;
      if(region.end - region.start < 500 * 1024 * 1024){
        usefulRegions.push_back(region);
        totalSize += (region.end - region.start);
      }
    }

    if(numThreads == 0) numThreads = std::thread::hardware_concurrency();
    size_t regionsPerThread = std::max(size_t(1), usefulRegions.size() / numThreads);
    std::cout << "Using " << numThreads << " threads, with " << regionsPerThread << " regions per thread" << std::endl;
 

    std::vector<uintptr_t> results;
    std::vector<std::thread> threads;

    for(int i = 0; i < numThreads; i++){
      size_t startID = i * regionsPerThread;
      size_t endID = std::min(startID + regionsPerThread, usefulRegions.size());

      if(startID >= usefulRegions.size()) break;
      threads.emplace_back([this, startID, endID, &usefulRegions, value, &results](){
        for(size_t j = startID; j < endID; j++) scanRegion(usefulRegions[j], value, results, resultsMutex, this->procID);
      });
    }

    for(auto& thread : threads) thread.join();

    return results;
  }

  template<typename T>
  std::vector<uintptr_t> refineScan(std::vector<uintptr_t>& addresses, T newValue){
    auto it = std::remove_if(addresses.begin(), addresses.end(), [this, newValue](uintptr_t address){
      try{
        T memValue = readMemory<T>(address);
        return memValue != newValue;
      }catch(...){return true;}
    });

    addresses.erase(it, addresses.end());
    std::cout << "Remaining: " << addresses.size() << " addresses" << std::endl;
    return addresses;
  }
};

int main() {
  try {
    MemoryHandler memHandler("Main Thread");
    std::vector<uintptr_t> addresses;
    int choice;

    do {
      std::cout << "\n=== MENU ===" << std::endl;
      std::cout << "1. New scan (initial value)" << std::endl;
      std::cout << "2. Refine scan (new value)" << std::endl;
      std::cout << "3. Show current addresses" << std::endl;
      std::cout << "4. Freeze an address" << std::endl;
      std::cout << "5. Exit" << std::endl;
      std::cout << "Choice: ";
      std::cin >> choice;

      switch (choice) {
        case 1: {
          int initialValue;
          std::cout << "Enter initial value: ";
          std::cin >> initialValue;
          addresses = memHandler.parallelScan<int>(initialValue, 8);
          break;
        }
        case 2: {
          if (addresses.empty()) {
            std::cout << "No addresses to refine. Do a scan first." << std::endl;
            break;
          }
          int newValue;
          std::cout << "Enter new value: ";
          std::cin >> newValue;
          addresses = memHandler.refineScan<int>(addresses, newValue);
          break;
        }
        case 3: {
          if (addresses.empty()) {
            std::cout << "No addresses to show." << std::endl;
            break;
          }
          std::cout << "\nCurrent addresses (" << addresses.size() << "):" << std::endl;
          for (size_t i = 0; i < addresses.size(); ++i) {
            try {
              int val = memHandler.readMemory<int>(addresses[i]);
              std::cout << "[" << i << "] 0x" << std::hex << addresses[i] << std::dec << " = " << val << std::endl;
            } catch (...) { std::cout << "[" << i << "] 0x" << std::hex << addresses[i] << std::dec << " = <read error>" << std::endl; }
          }
          break;
        }
        case 4: {
          if (addresses.empty()) {
            std::cout << "No addresses to freeze. Scan first." << std::endl;
            break;
          }
          size_t index;
          int freezeValue;
          std::cout << "Enter address index to freeze: ";
          std::cin >> index;
          if(index >= addresses.size()){
            std::cout << "Invalid index." << std::endl;
            break;
          }
          std::cout << "Enter value to freeze: ";
          std::cin >> freezeValue;

          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

          std::cout << "Freezing address 0x" << std::hex << addresses[index] << std::dec << " to " << freezeValue << std::endl;
          std::cout << "Press [ENTER] to stop freezing" << std::endl;

          std::atomic<bool> keepFreezing(true);

          std::thread freezeThread([&](){
              while(keepFreezing){
                memHandler.writeMemory<int>(addresses[index], freezeValue);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
              }
          });

          std::cin.get();
          keepFreezing = false;
          freezeThread.join();
          std::cout << "Stopping freeze[!]" << std::endl;
          break;
        }
        case 5:
          std::cout << "Exiting..." << std::endl;
          break;
        default:
          std::cout << "Invalid choice." << std::endl;
      }
    } while (choice != 5);
  } catch(...) {}
  return 0;
}
