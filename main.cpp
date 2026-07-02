#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <fstream>
#include <string>

#define OPERATION_SIZE 4096

struct MemoryPage{
    unsigned long long m_start_address;
    unsigned long long m_end_address;
    std::size_t        m_size;
};

int main(int argc, const char* argv[])
{
    if(argc != 2){
        std::cerr << "Invalid arguments, expected : ./scandbg <Process ID>";
    }

    std::string pid_string { argv[1] };
    int pid_int;

    try{
        pid_int = std::stoi(pid_string);
    }catch(...){
        std::cerr << "Unable to convert PID";
        return 1;
    }

    std::cout << "Current pid : " + pid_string + "\n";

    std::string target_maps_path { "/proc/" + pid_string + "/maps" };

    std::ifstream target_ifstream(target_maps_path);

    std::string current_page{};

    std::vector<MemoryPage> valid_memory_pages{};

    while(std::getline(target_ifstream, current_page)){

        std::size_t dash_iter = current_page.find('-');
        std::size_t space_iter = current_page.find(' ');

        if(dash_iter == std::string::npos || space_iter == std::string::npos){
            continue;
        }

        //offset 1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
        //pages  A  B  C  D  E  F  G  -  A  B  C  D  E  F  G     p  -  -  r

        std::string start_address = current_page.substr(0, dash_iter);
        std::string end_address = current_page.substr(dash_iter + 1, space_iter - (dash_iter + 1));
        std::string permission = current_page.substr(space_iter + 1, 4);

        if(permission[0] != 'r'){
            continue;
        }

        unsigned long long ull_start_address;
        unsigned long long ull_end_address;
        std::size_t size;

        try{
            ull_start_address = std::stoull(start_address, nullptr, 16);
            ull_end_address = std::stoull(end_address, nullptr, 16);
            size = ull_end_address - ull_start_address;
        }catch(...){
            std::cerr << "An error encountered whilst trying to convert addresses";
            return 1;
        }

        valid_memory_pages.push_back({
            .m_start_address = ull_start_address,
            .m_end_address = ull_end_address,
            .m_size = size
        });

    }
    target_ifstream.close();

    int value_to_find{};
    std::cout << "Enter integer value to find in remote process : ";
    std::cin >> value_to_find;

    if(std::cin.fail()){
        std::cerr << "Error : invalid number / number is too large";
        return 1;
    }

    std::vector<char> bytes_map(OPERATION_SIZE);

    int match_count{};

    for(const auto& current_memory_page : valid_memory_pages){
        for(
            unsigned long long current_chunk_address = current_memory_page.m_start_address;
            current_chunk_address < current_memory_page.m_end_address;
            current_chunk_address += OPERATION_SIZE
            ) {

            std::size_t reading_size = OPERATION_SIZE;
            if(current_chunk_address + OPERATION_SIZE > current_memory_page.m_end_address){
                reading_size = current_memory_page.m_end_address - current_chunk_address;
            }

            struct iovec local_region{
                .iov_base = bytes_map.data(),
                .iov_len = reading_size
            };

            struct iovec remote_region{
                .iov_base = reinterpret_cast<void*>(current_chunk_address),
                .iov_len = reading_size
            };

            ssize_t bytes_read = process_vm_readv(pid_int, &local_region, 1, &remote_region, 1, 0);
            if(bytes_read == -1){
                continue;
            }



            for(std::size_t i{0}; i + sizeof(int) <= reading_size; i++){
                char* current_byte = &bytes_map[i];
                int possible_int = *reinterpret_cast<int*>(current_byte);
                if(possible_int == value_to_find){
                    std::cout << "Found match, address : 0x" << std::hex << current_chunk_address + i << std::dec << "\n";
                    match_count += 1;
                }
            }
        }
    }

    if(match_count == 0){
        std::cout << "Value not found.\n";
    }
    else
    {
        std::cout << "Total matches : " << match_count << "\n";
    }



}