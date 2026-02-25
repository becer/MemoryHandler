#include <iostream>
#include <unistd.h> 
#include <sys/types.h> 
#include <fstream> //HANDLE
#include <dirent.h> //dirent 
#include <cstdint> //uintptr
#include <iomanip>
#include <sstream>//stringstream
#include <string>
#include <cctype>
#include <cstring>
#include <exception>
#include <vector>
#include <chrono>
#include <thread>	
#include <filesystem>
#include <algorithm>
#include <queue>
#include <mutex>
#include <atomic>
#include <future>

class MemoryHandler{
private:
	pid_t procID;
	std::mutex resultsMutex;
	std::atomic<bool> scanningActive;

	std::string char_to_string(const wchar_t* input)
	{
		if(!input) return "";
		std::string result;
		size_t len = wcslen(input);
		result.resize(len);
		for(size_t i = 0; i < len; i++) result[i] = static_cast<char>(input[i]);
		return result;
	}

	struct MemoryRegion
    {
        uintptr_t start;
        uintptr_t end;
        std::string permissions;
	};

    //obtem todas as regioes de memoria validas do processo
    std::vector<MemoryRegion> getValidMemoryRegions()
	{
      	std::vector<MemoryRegion> regions;
    	std::string maps_path = "/proc/" + std::to_string(procID) + "/maps";
    	std::ifstream maps_file(maps_path);

    	if(!maps_file.is_open())return regions;
        	

        std::string line;
        while (std::getline(maps_file, line))
		{
        	MemoryRegion region;
    		std::stringstream ss(line);
    		std::string addr_range;

        	ss >> addr_range;

    		//parse enderecos
            size_t dash_pos = addr_range.find('-');
            if(dash_pos != std::string::npos)
			{
				region.start = std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
        		region.end = std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);
    		}
            
			ss >> region.permissions;

    		//so considera regioes com permissao de leitura
			if(region.permissions.find('r') != std::string::npos) regions.push_back(region);
            		
        }

        return regions;
    }
	//funcao de trabalho para cada thread
	template<typename T>
	void scanRegion(const MemoryRegion& region, T value, std::vector<uintptr_t>& results, std::atomic<size_t>& progress, size_t totalSize)
	{
		std::vector<uintptr_t> localResults;
		const size_t stepSize = sizeof(T);

		if(region.permissions.find('r') == std::string::npos) return;

		const size_t BUFFER_SIZE = 4096;//vetor para leituras em bloco
		std::vector<uint8_t> buffer(BUFFER_SIZE);
		for(uintptr_t addr = region.start; addr < region.end; addr += BUFFER_SIZE)
		{
			size_t bytesToRead = std::min(BUFFER_SIZE, size_t(region.end - addr));

			//le o bloco inteiro de uma vez
			if(readMemoryBlock(addr, reinterpret_cast<uint8_t*>(buffer.data()), bytesToRead))
			{
				for(size_t offset = 0; offset + sizeof(T) <= bytesToRead; offset += stepSize)
				{
					T memValue;
					memcpy(&memValue, buffer.data() + offset, sizeof(T));
					if(memValue == value) localResults.push_back(addr + offset);
				}
			}
			progress += bytesToRead; //atualiza o progresso

			static int lastPercent = 0;
			int percent = (progress * 100) / totalSize;
			if(percent >= lastPercent + 10)
			{
				lastPercent = percent;
				std::cout << "\rProgress: " << percent << "%" << std::flush;
			}
		}
		if(!localResults.empty()) //adiciona resultados locais no vetor global com mutex
		{
			std::lock_guard<std::mutex> lock(resultsMutex);
			results.insert(results.end(), localResults.begin(), localResults.end());
		}
	}

public:		
	MemoryHandler(const wchar_t* procName)
	{
		std::string procNameStr = char_to_string(procName);
    	attach(procNameStr);
    }    
	
    MemoryHandler(const std::string& procName)
	{
		attach(procName);
    }
	
	~MemoryHandler()
	{
		procID = -1;
	}

	void attach(const std::string& procName)
	{
		DIR *dirr;
		struct dirent *entry;

		dirr = opendir("/proc");
		if(dirr == NULL) throw std::runtime_error("Failed to open /proc directory");
		
		while((entry = readdir(dirr)) != NULL)
		{
			if(isdigit(entry->d_name[0]))
			{
				std::string pid_str(entry->d_name);
				std::string comm_path = "/proc/" + pid_str + "/comm";
				std::ifstream comm_file (comm_path);
		
				
				if(comm_file.is_open())
				{
					std::string comm_name;
					std::getline(comm_file, comm_name);
					comm_file.close();

					if(!comm_name.empty() && comm_name.back() == '\n') comm_name.pop_back(); 
					
					if(comm_name == procName)
				       	{
						procID = std::stoi(entry->d_name);
						closedir(dirr);
						std::cout << "Found process: " << procName << " [PID]: " << procID << std::endl;			
						return;
					}
				}
					
			}
		}
		closedir(dirr);
		throw std::runtime_error("Process not found: " + procName);
	}
	std::uintptr_t getModuleBaseAddress(const std::string& moduleName)
	{
		if(moduleName.empty()) throw std::runtime_error("empty moduleName to getModuleBaseAddress");
		
		std::string maps_path = "/proc/" + std::to_string(procID) + "/maps"; 	
		std::ifstream maps_file(maps_path);
		
		if(!maps_file.is_open()) throw std::runtime_error("file map failed to be opened to getModuleBaseAddress");
		std::string line;
		while(std::getline(maps_file, line))
		{

			if(line.find(moduleName) != std::string::npos)
			{
				std::stringstream ss(line);
				std::string address_range;
				ss >> address_range;
				
				size_t dash_pos = address_range.find('-');
				if(dash_pos != std::string::npos)
				{
					std::string start_addr_str = address_range.substr(0, dash_pos);
					uintptr_t base_addr = std::stoull(start_addr_str, nullptr, 16);
					
					std::string perms;
					ss >> perms;

					if(perms.find('x') != std::string::npos)
					{	
						maps_file.close();
						return base_addr;
					}
				}
			}
		}
		maps_file.close();
		return 0;
	}
	
	size_t getModuleSize(const std::string& moduleName)
	{
		std::string maps_path = "/proc/" + std::to_string(procID) + "/maps";
		std::ifstream maps_file(maps_path);

		if(!maps_file.is_open()) return 0;

		std::string line;
		uintptr_t moduleStart = 0;
		uintptr_t moduleEnd = 0;

		while(std::getline(maps_file, line))
		{
			if(line.find(moduleName) != std::string::npos)
			{
				std::stringstream ss(line);
				std::string address_range;
				ss >> address_range;
				
				size_t dash_pos = address_range.find('-');
				if(dash_pos != std::string::npos)
				{
					uintptr_t start = std::stoull(address_range.substr(0, dash_pos), nullptr, 16);
					uintptr_t end = std::stoull(address_range.substr(dash_pos + 1), nullptr, 16);

				if(moduleStart == 0 || start < moduleStart) moduleStart = start;
				if(end > moduleEnd) moduleEnd = end;
				}
			}
		}
		return moduleEnd - moduleStart;
	}

	std::uintptr_t findSignature(const std::string& moduleName, const std::vector<uint8_t>& signature)
	{
		uintptr_t moduleBase = getModuleBaseAddress(moduleName);
		if(!moduleBase) return 0;

		size_t moduleSize = getModuleSize(moduleName);
		if(moduleSize == 0) return 0;

		std::cout << "scanning module " << moduleName << " (0x" << std::hex << moduleBase << " - 0x" << moduleBase + moduleSize << std::dec << ") for signature..." << std::endl;
		
		const size_t BUFFER_SIZE = 4096; //4KB por vez
		std::vector<uint8_t> buffer(BUFFER_SIZE);

		for(uintptr_t addr = moduleBase; addr < moduleBase + moduleSize; addr += BUFFER_SIZE)
		{
			size_t bytesToRead = BUFFER_SIZE;
			if(addr + bytesToRead > moduleBase + moduleSize)	bytesToRead = moduleBase + moduleSize - addr;
			
			//le bloco de memoria, se n conseguir pula
			if(!readMemoryBlock(addr, buffer.data(), bytesToRead)) continue;
			//procura a signature no bloco lido
			for(size_t i = 0; i < bytesToRead - signature.size(); i++)
			{
				bool found = true;
				for(size_t j = 0; j < signature.size(); j++)
				{
					if(buffer[i + j] != signature[j])
					{
						found = false;
						break;	
					}
				}
				if(found)
				{
					std::cout <<" ✅ Signature found at: 0x" << std::hex << (addr + i) << std::dec << std::endl;
					return addr + i;
				}
			}
		}
		std::cout << "❌ Signature not found" << std::endl;
		return 0;
	}

	std::uintptr_t findPattern(const std::string& moduleName, const std::string& pattern)
	{
		//converte o padrao string para vetor de bytes com wildcards
		std::vector<std::pair<uint8_t, bool>> patternBytes; //bool = se e wild card
		std::stringstream ss(pattern);
		std::string byteStr;

		while(ss >> byteStr)
		{
			if(byteStr == "?" || byteStr == "??") patternBytes.push_back({0, true}); //wildcard
			else
			{
				uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
				patternBytes.push_back({byte, false});
			}
		}
		uintptr_t moduleBase = getModuleBaseAddress(moduleName);
		if(!moduleBase) return 0;

		size_t moduleSize = getModuleSize(moduleName);
		if(moduleSize == 0) return 0;

		std::cout << "scanning for patterns: " << pattern << std::endl;

		const size_t BUFFER_SIZE = 4096;
		std::vector<uint8_t> buffer(BUFFER_SIZE);

		for(uintptr_t addr = moduleBase; addr < moduleBase + moduleSize; addr += BUFFER_SIZE)
		{
			size_t bytesToRead = BUFFER_SIZE;
			if(addr + bytesToRead > moduleBase + moduleSize) bytesToRead = moduleBase + moduleSize - addr;

			if(!readMemoryBlock(addr, buffer.data(), bytesToRead)) continue;

			for(size_t i = 0; i < bytesToRead - patternBytes.size(); i++)
			{
				bool found = true;
				for(size_t j = 0; j < patternBytes.size(); j++)
				{
					if(!patternBytes[j].second && buffer [i + j] != patternBytes[j].first) 
					{
						found = false;
						break;
					}
				}
				if(found)
				{
					std::cout << "✅ Pattern found at: 0x" << std::hex << (addr + i) << std::dec << std::endl;
					return (addr + i);
				}
			}
		}
		std::cout << "❌ Pattern not found" << std::endl;
		return 0;
	}

	//funcao aux para ler blocos de memoria
	bool readMemoryBlock(uintptr_t addr, uint8_t* buffer, size_t size)
	{
		std::string mem_path = "/proc/" + std::to_string(procID) + "/mem";
		std::ifstream mem_file(mem_path, std::ios::binary);
		
		if(!mem_file.is_open()) return false;

		mem_file.seekg(addr);
		mem_file.read(reinterpret_cast<char*>(buffer), size);

		bool success = !mem_file.fail();
		mem_file.close();

		return success;
	}

	template<typename T>
	T readMemory(std::uintptr_t addr)
	{
		T value;
		std::string mem_path = "/proc/" + std::to_string(procID) + "/mem";
	       	std::ifstream mem_file(mem_path, std::ios::binary);
		
		if(!mem_file.is_open()) throw std::runtime_error("failed to open mem file");

		mem_file.seekg(addr);
		mem_file.read(reinterpret_cast<char*>(&value), sizeof(T));
		
		if(!mem_file) throw std::runtime_error("failed to read memory at the address: " + std::to_string(addr));
		mem_file.close();
		return value;	
	}

	template<typename T>
	bool writeMemory(std::uintptr_t addr, T val)
	{
		std::string mem_path = "/proc/" + std::to_string(procID) + "/mem";
		std::ofstream mem_file(mem_path, std::ios::binary);

		if(!mem_file.is_open()) return false;

		mem_file.seekp(addr);
		mem_file.write(reinterpret_cast<char*>(&val), sizeof(T));
		
		bool success = mem_file.good();
		mem_file.close();

		return success;
	
	}
	
	//funcoes de busca de ponteiro
	template<typename T>
	std::vector<uintptr_t> parallelScan(T value, int numThreads = 0)
	{
		auto startTime = std::chrono::high_resolution_clock::now();

		//detecta numero de threads se n especificado
		if(numThreads <= 0)
		{
			numThreads = std::thread::hardware_concurrency();
			if(numThreads <= 0) numThreads = 4;
		}
		std::cout << "Using " << numThreads << " threads" << std::endl;
		
		auto regions = getValidMemoryRegions();
		
		//filtra regioes uteis
		std::vector<MemoryRegion> usefulRegions;
		size_t totalSize = 0;

		for(const auto& region : regions)
		{	//so le arquivos ocm permissao
			if(region.permissions.find('r') == std::string::npos) continue;
			//pula regioes grandes
			if(region.end - region.start < 500 * 1024 * 1024)
			{
				usefulRegions.push_back(region);
				totalSize += (region.end - region.start);
			}
		}

		//prepara para scan paralelo
		std::vector<uintptr_t> results;
		std::vector<std::thread> threads;
		std::atomic<size_t> progress(0);
		
		//divide regioes entre threads
		size_t regionsPerThread = std::max(size_t(1), usefulRegions.size() / numThreads);		
		
		for(int i = 0; i < numThreads; i++)
		{
			size_t startIdx = i * regionsPerThread;
			size_t endIdx = std::min(startIdx + regionsPerThread, usefulRegions.size());
			if(startIdx >= usefulRegions.size()) break;
			threads.emplace_back([this, startIdx, endIdx, &usefulRegions, value, &results, &progress, totalSize](){
					for(size_t j = startIdx; j < endIdx; j++){
						scanRegion(usefulRegions[j], value, results, progress, totalSize);
					}
			});
		}
		for(auto& thread : threads) thread.join();

		auto endTime = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
		
		std::cout << "✅ Scan completed in " << duration.count() << " seconds" << "found " << results.size() << " matches " << std::endl;	
		return results;
	}

	template<typename T>
	std::vector<uintptr_t> refineScan(std::vector<uintptr_t>& addresses, T newValue)
	{
		auto it = std::remove_if(addresses.begin(), addresses.end(), [this, newValue](uintptr_t addr){
			try
			{
				T memValue = readMemory<T>(addr);
				return memValue != newValue;		
			
			}catch(...){return true;}
		});
		
		addresses.erase(it, addresses.end());
		std::cout << "Remainig: " << addresses.size() << " addresses" << std::endl;
		return addresses;
	}

	bool applyPayLoad(const std::string& moduleName, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& payload, int offset = 0)
	{
		uintptr_t sigAddress = findSignature(moduleName, signature);
		if(sigAddress) 
		{	
			std::cout << "Found signature at: 0x" << std::hex << sigAddress << std::dec << std::endl;

			//aplica payload no endereco encontrado + offset
			uintptr_t targetAddress = sigAddress + offset;	

			//escreve o payload
			for(size_t i = 0; i < payload.size(); i++)
			{
				if(!writeMemory<uint8_t>(targetAddress + i, payload[i]))
				{
					throw std::runtime_error("Failed to write payload at offset");
					return false;
				}
			}
			std::cout << "✅ Payload applied successfully at 0x" << std::hex << targetAddress << std::dec << std::endl;
        		return true;
		}

		std::cout << "❌ Signature not found, payload not applied" << std::endl;
        	return false;
	}


	pid_t GetPID() const{return procID;}

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
                            std::cout << "[" << i << "] 0x" << std::hex << addresses[i]
                                      << std::dec << " = " << val << std::endl;
                        } catch (...) {
                            std::cout << "[" << i << "] 0x" << std::hex << addresses[i]
                                      << std::dec << " = <read error>" << std::endl;
                        }
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
                    if (index >= addresses.size()) {
                        std::cout << "Invalid index." << std::endl;
                        break;
                    }
                    std::cout << "Enter value to freeze: ";
                    std::cin >> freezeValue;

                    std::cout << "Freezing address 0x" << std::hex << addresses[index]
                              << std::dec << " to " << freezeValue
                              << ". Press Ctrl+C to exit." << std::endl;

                    while (true) {
                        memHandler.writeMemory<int>(addresses[index], freezeValue);
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                    break;
                }
                case 5:
                    std::cout << "Exiting..." << std::endl;
                    break;
                default:
                    std::cout << "Invalid choice." << std::endl;
            }
        } while (choice != 5);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
