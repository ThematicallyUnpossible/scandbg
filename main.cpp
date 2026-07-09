#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <limits>
#include <optional>
#include <type_traits>
#include "core.h"

#define STANDARD_OPERATION_SIZE 4096

void clean_cin(){
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

#define nl std::numeric_limits
template<typename T>
    requires std::is_arithmetic_v<T>
void prompt_mutate_unified(T& x,std::string_view prefix,T minimum = nl<T>::min(),T maximum = nl<T>::max()){
    std::cout << prefix;
    T temporary{};
    while(true){
        std::cin >> temporary;
        if(std::cin.fail()){
            std::cout << prefix;
            clean_cin();
            continue;
        }
        if(temporary < minimum || temporary > maximum){
            std::cout << prefix;
            clean_cin();
            continue;
        }
        break;
    }
    x = temporary;
}

void print_addresses(std::vector<ScannedObject>& list){

    int print_count{};
    std::cout << "\n--------------------------------------------\n";
    for(const auto address : list){
        std::cout << "0x" << std::hex << address.m_address << std::dec;
        print_count += 1;

        if(print_count < 3){
            std::cout << " ";
        }else{
            std::cout << "\n";
            print_count = 0;
        }
    }
    std::cout << "\n--------------------------------------------\n";

}

const std::string G_action_list = "---------------------------\n"
                            "[1] scan new\n"
                            "[2] scan captured\n"
                            "[3] overwrite a value\n"
                            "[4] rescan memory region.\n"
                            "[5] capture last scanned addresses\n"
                            "[6] print current address buffer"
                            "\n---------------------------";
#define MINIMUM_ACTION 1
#define MAXIMUM_ACTION 8

int main(int argc, const char* argv[]){
    std::cout << "\n";
    if(argc != 2){
        std::cerr << "[x] invalid usage. sudo ./scandbg <pid>";
    }
    auto system_object = ProcessDebugger::create(argv[1]);
    if(!system_object){
        std::cerr << "[x] unable to construct a system_object. is pid valid?\n";
        return 1;
    }
    std::cout << "[*] system initialized with pid " << system_object.value().get_pid_string() << "\n";

    auto valid_address_list = system_object.value().scan_memory_map();
    if(!valid_address_list){
        std::cerr << "[x] unable to get the list of valid addresses\n";
        return 1;
    }
    std::cout << "[*] found regions of readable addresses.\n";

    int current_action_choice{};

    std::optional<std::vector<ScannedObject>> address_buffer{};
    std::vector<ScannedObject> capture_buffer{};

    while(true){
        std::cout << "\n" << G_action_list << "\n";
        prompt_mutate_unified<int>(current_action_choice, "[?] type your n choice : ", MINIMUM_ACTION, MAXIMUM_ACTION);
        if(current_action_choice == 1){

            std::cout <<  "[1] int "
                      <<  "[2] float "
                      <<  "[3] double\n";
            int type_choice{};
            prompt_mutate_unified(type_choice, "[?] choose data type : ", 1, 3);
            if(type_choice  == 1){
                int value_to_find{};
                prompt_mutate_unified<int>(value_to_find, "[?] type the value to be scanned : ");
                address_buffer = system_object.value().scan_value<int>(valid_address_list.value(), value_to_find);
                if(!address_buffer || address_buffer.value().empty()){
                    std::cout << "[x] no value found.\n";
                    continue;
                }else{
                    print_addresses(address_buffer.value());
                }
            }
            else if(type_choice == 2){
                float value_to_find{};
                prompt_mutate_unified<float>(value_to_find, "[?] type the value to be scanned : ");
                address_buffer = system_object.value().scan_value<float>(valid_address_list.value(), value_to_find);
                if(!address_buffer || address_buffer.value().empty()){
                    std::cout << "[x] no value found.\n";
                    continue;
                }
                else{
                    print_addresses(address_buffer.value());
                }
            }
            else if(type_choice == 3){
                double value_to_find{};
                prompt_mutate_unified<double>(value_to_find, "[?] type the value to be scanned : ");
                address_buffer = system_object.value().scan_value<double>(valid_address_list.value(), value_to_find);
                if(!address_buffer || address_buffer.value().empty()){
                    std::cout << "[x] no value found.\n";
                    continue;
                }
                else{
                    print_addresses(address_buffer.value());
                }
            }

        }
        else if(current_action_choice  ==  2){
            if(capture_buffer.empty()){
                std::cerr << "[!] capture buffer is empty";
                continue;
            }
            std::cout <<  "[1] int "
                      <<  "[2] float "
                      <<  "[3] double\n";
            int type_choice{};
            prompt_mutate_unified(type_choice, "[?] choose data type : ", 1, 3);

            if(type_choice == 1){
                int value_to_find{};
                prompt_mutate_unified(value_to_find, "[?] type the value to be scanned : ");
                auto result = system_object.value().scan_captured<int>(capture_buffer, value_to_find);
                if(!result){
                    std::cerr << "[!] no value found\n";
                    continue;
                }
                address_buffer = result.value();
                print_addresses(result.value());
            }
            else if(type_choice == 2){
                float value_to_find{};
                prompt_mutate_unified(value_to_find, "[?] type the value to be scanned : ");
                auto result = system_object.value().scan_captured<float>(capture_buffer, value_to_find);
                if(!result){
                    std::cerr << "[!] no value found\n";
                    continue;
                }
                address_buffer = result.value();
                print_addresses(result.value());
            }
            else if(type_choice  == 3){
                double value_to_find{};
                prompt_mutate_unified(value_to_find, "[?] type the value to be scanned : ");
                auto result = system_object.value().scan_captured<double>(capture_buffer, value_to_find);
                if(!result){
                    std::cerr << "[!] no value found\n";
                    continue;
                }
                address_buffer = result.value();
                print_addresses(result.value());
            }
        }
        else if(current_action_choice == 3){
            clean_cin();
            std::cout << "[?] type the address which value you want to overwrite : ";
            std::string selected_address;
            std::getline(std::cin, selected_address);
            unsigned long long selected_address_ull{};
            try{
                selected_address_ull = std::stoull(selected_address, nullptr, 16);
            }catch(...){
                std::cout << "[!] unable to convert (" + selected_address + "). continuing anyway";
                continue;
            }

            std::cout <<  "[1] int "
                      <<  "[2] float "
                      <<  "[3] double\n";
            int type_choice{};
            prompt_mutate_unified(type_choice, "[?] choose data type : ", 1, 3);

            if(type_choice ==  1){
                int overwrite_with{};
                prompt_mutate_unified<int>(overwrite_with, "[?] type a integer value to overwrite with : ");

                struct iovec local_write_region {
                    .iov_base = &overwrite_with,
                    .iov_len = sizeof(overwrite_with)
                };
                struct iovec remote_write_region{
                    .iov_base = reinterpret_cast<void*>(selected_address_ull),
                    .iov_len = sizeof(overwrite_with)
                };

                ssize_t bytes_written = process_vm_writev(system_object.value().get_pid_int(), &local_write_region, 1, &remote_write_region, 1, 0);
                if(bytes_written == -1){
                    std::cerr << "[!] failed to write at address. continuing anyway";
                }else{
                    std::cout << "[*] succesfulyl written";
                    continue;
                }
            }
            else if(type_choice ==  2){
                float overwrite_with{};
                prompt_mutate_unified<float>(overwrite_with, "[?] type a float value to overwrite with : ");

                struct iovec local_write_region {
                    .iov_base = &overwrite_with,
                    .iov_len = sizeof(overwrite_with)
                };
                struct iovec remote_write_region{
                    .iov_base = reinterpret_cast<void*>(selected_address_ull),
                    .iov_len = sizeof(overwrite_with)
                };

                ssize_t bytes_written = process_vm_writev(system_object.value().get_pid_int(), &local_write_region, 1, &remote_write_region, 1, 0);
                if(bytes_written == -1){
                    std::cerr << "[!] failed to write at address. continuing anyway";
                }else{
                    std::cout << "[*] succesfulyl written";
                    continue;
                }
            }
            else if(type_choice == 3){
                double overwrite_with{};
                prompt_mutate_unified<double>(overwrite_with, "[?] type a double value to overwrite with : ");

                struct iovec local_write_region {
                    .iov_base = &overwrite_with,
                    .iov_len = sizeof(overwrite_with)
                };
                struct iovec remote_write_region{
                    .iov_base = reinterpret_cast<void*>(selected_address_ull),
                    .iov_len = sizeof(overwrite_with)
                };

                ssize_t bytes_written = process_vm_writev(system_object.value().get_pid_int(), &local_write_region, 1, &remote_write_region, 1, 0);
                if(bytes_written == -1){
                    std::cerr << "[!] failed to write at address. continuing anyway";
                }else{
                    std::cout << "[*] succesfulyl written";
                    continue;
                }
            }
        }

        else if(current_action_choice == 4){
            valid_address_list = system_object.value().scan_memory_map();
            if(!valid_address_list){
                std::cerr << "[x] unable to get the list of valid addresses\n";
                return 1;
            }
            std::cout << "[*] refreshed regions of readable addresses.\n";
        }

        else if(current_action_choice == 5){
            if(!address_buffer){
                std::cerr << "[!] attempted to copy invalid vector. scan first";
                continue;
            }
            capture_buffer = address_buffer.value();
            std::cout << "[*] copied " << address_buffer.value().size() << " addresses into capture buffer \n";
        }

        else if(current_action_choice == 6){
            if(!address_buffer){
                std::cerr << "[!] address buffer is empty";
                continue;
            }
            if(address_buffer.value().empty()){
                std::cerr << "[!] address buffer is empty";
                continue;
            }

            print_addresses(address_buffer.value());
        }

    }































    return 0;
}