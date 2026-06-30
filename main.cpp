#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <fstream>
#include <string>
#include <limits>

struct MemoryBlueprint
{
    unsigned long long m_start_address;
    unsigned long long m_end_address;
    std::size_t m_size;
};


int main(int argc, char* argv[])
{
    if(argc != 2){
        std::cerr << "Invalid usage. Expected : scandbg <PID>";
        return 1;
    }

    std::string pid_string = argv[1];

    int pid_int{};

    try {

        pid_int = std::stoi(pid_string);

    } catch (...) {

        std::cerr << "Unable to parse PID.";
        return 1;
    }

    std::string target_mem_path = "/proc/" + pid_string + "/maps";

    std::ifstream target_mem_file(target_mem_path);

    std::vector<MemoryBlueprint> target_mem_available{};

    std::string target_mem_line;

    while (std::getline(target_mem_file, target_mem_line)) {

        size_t dash_index = target_mem_line.find('-');
        size_t first_space_index = target_mem_line.find(' ');

        if (dash_index == std::string::npos || first_space_index == std::string::npos) {
            continue;
        }

        std::string start_hex = target_mem_line.substr(0, dash_index);

        std::string end_hex = target_mem_line.substr(dash_index + 1, first_space_index - (dash_index + 1));

        std::string perms = target_mem_line.substr(first_space_index + 1, 4);

        if (perms[0] != 'r') {
            continue;
        }

        MemoryBlueprint region;
        region.m_start_address = std::stoull(start_hex, nullptr, 16);
        region.m_end_address   = std::stoull(end_hex, nullptr, 16);
        region.m_size  = region.m_end_address - region.m_start_address;

        target_mem_available.push_back(region);
    }

    int value_to_find{};
    while(true)
    {
        write(1, "\033[2J\033[1;1H", 7);
        std::cout << "Enter value to find : ";

        std::cin >> value_to_find;

        if(std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        break;
    }

    int target_fd = open(target_mem_path.c_str(), O_RDONLY);
    if(target_fd == -1){
        std::cerr << "Unable to open " + target_mem_path;
        return 1;
    }

    for( auto region : target_mem_available )
    {
        for (unsigned long long current_addr = region.m_start_address;
             current_addr <= region.m_end_address - sizeof(int);
             current_addr += sizeof(int))
        {
            int local_int_buffer = 0;

            struct iovec local_region {
                .iov_base = &local_int_buffer,
                .iov_len = sizeof(local_int_buffer)
            };

            struct iovec remote_region {
                .iov_base = (void*)current_addr,
                .iov_len = sizeof(local_int_buffer)
            };

            ssize_t bytes_read = process_vm_readv(pid_int, &local_region, 1, &remote_region, 1, 0);

            if(bytes_read == -1)
            {
                break;
            }

            if(local_int_buffer == value_to_find)
            {
                std::cout << "Found match at address: 0x" << std::hex << current_addr << std::dec << "\n";
            }
        }
    }


    close(target_fd);
    return 0;
}
