#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <optional>
#include "core.h"
#include "core_helper.h"
#include "utility.h"

#define STANDARD_OPERATION_SIZE 4096

const std::string G_action_list = "---------------------------\n"
                            "[1] scan new\n"
                            "[2] scan captured\n"
                            "[3] overwrite a value\n"
                            "[4] rescan memory region.\n"
                            "[5] capture last scanned addresses\n"
                            "[6] print current address buffer"
                            "\n---------------------------";
constexpr int G_MINIMUM_ACTION = 1;
constexpr int MAXIMUM_ACTION = 8;


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
        prompt_mutate_unified<int>(current_action_choice, "[?] type your n choice : ", G_MINIMUM_ACTION, MAXIMUM_ACTION);
        if(current_action_choice == 1){

            std::cout <<  "[1] int "
                      <<  "[2] float "
                      <<  "[3] double\n";
            int type_choice{};
            prompt_mutate_unified(type_choice, "[?] choose data type : ", 1, 3);
            if(type_choice  == 1){
                helper_scan_value<int>(system_object, valid_address_list, address_buffer);
            }
            else if(type_choice == 2){
                helper_scan_value<float>(system_object, valid_address_list, address_buffer);
            }
            else if(type_choice == 3){
                helper_scan_value<double>(system_object, valid_address_list, address_buffer);
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
                helper_scan_captured<int>(system_object, capture_buffer, address_buffer);
            }
            else if(type_choice == 2){
                helper_scan_captured<float>(system_object, capture_buffer, address_buffer);
            }
            else if(type_choice  == 3){
                helper_scan_captured<double>(system_object, capture_buffer, address_buffer);
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
                helper_write_value<int>(system_object, selected_address_ull);
            }
            else if(type_choice ==  2){
                helper_write_value<float>(system_object, selected_address_ull);
            }
            else if(type_choice == 3){
                helper_write_value<double>(system_object, selected_address_ull);
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