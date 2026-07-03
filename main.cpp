#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <fstream>
#include <string>
#include <limits.h>

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
        return 1;
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
    std::vector<unsigned long long> address_matches{};

    int match_count{};
    int print_count{};
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

                    unsigned long long current_int_address = current_chunk_address + i;

                    std::cout << "0x" << std::hex << current_int_address << std::dec;

                    print_count += 1;

                    if(print_count >= 4){
                        std::cout << "\n";
                        print_count = 0;
                    }else{
                        std::cout << " ";
                    }



                    address_matches.push_back(current_int_address);
                    match_count += 1;
                }
            }
        }
    }

    std::cout << "\n";
    if(match_count == 0){
        std::cout << "Value not found.\n";
        return 1;
    }
    else
    {
        std::cout << "Total matches : " << match_count << "\n";
    }

    //clearning cin buffer
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    //

    std::cout << "Type address to be written into : ";
    std::string selected_address_string{};
    std::getline(std::cin, selected_address_string);


    std::string selected_address_valid_string{};
    std::string selected_address_slice = selected_address_string.substr(0, 2);
    if(selected_address_slice == "0x"){
        selected_address_valid_string = selected_address_string;
    }else{
        selected_address_valid_string = "0x" + selected_address_string;
    }

    unsigned long long selected_address_ull{};
    try{
        selected_address_ull = std::stoull(selected_address_valid_string, nullptr, 16);
    }catch(...){
        std::cerr << "Unable to convert selected address";
        return 1;
    }

    bool selected_address_isfound{false};
    for(const auto address : address_matches){
        if(address == selected_address_ull){
            selected_address_isfound = true;
            break;
        }
    }
    if(!selected_address_isfound){
        std::cerr << "Address isnt valid";
        return 1;
    }

    int int_write_value{};
    std::cout << "Type int number to overwrite object at " + selected_address_valid_string + " : ";
    std::cin >> int_write_value;
    if(std::cin.fail()){
        std::cerr << "std::cin fails.";
        return 1;
    }

    struct iovec local_region{
        .iov_base  = &int_write_value,
        .iov_len  = sizeof(int_write_value)
    };

    struct iovec remote_region{
        .iov_base = (void*)selected_address_ull,
        .iov_len = sizeof(int_write_value)
    };

    ssize_t bytes_written = process_vm_writev(pid_int, &local_region, 1, &remote_region, 1, 0);
    if(bytes_written == -1){
        std::perror("writev fails ");
    }

    return 0;
}