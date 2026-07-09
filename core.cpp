#include "core.h"
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <optional>
#include <filesystem>
#include <fstream>
#include <cstring>

ProcessDebugger::ProcessDebugger(int pid_int, std::string pid_string):
    m_pid_int{pid_int},
    m_pid_string{pid_string}{}

int ProcessDebugger::get_pid_int() const {
    return m_pid_int;
}

std::string ProcessDebugger::get_pid_string() const {
    return m_pid_string;
}

std::optional<ProcessDebugger> ProcessDebugger::create(std::string pid_string){
    int validated_pid_int{};

    try{
        validated_pid_int = std::stoi(pid_string);
    }catch(...){
        return std::nullopt;
    }

    std::string maps_path = "/proc/" + pid_string + "/maps";

    if(!std::filesystem::exists(maps_path)){
        return std::nullopt;
    }

    return ProcessDebugger(validated_pid_int, std::move(pid_string));
}

std::optional<std::vector<AddressContainer>> ProcessDebugger::scan_memory_map(){
    std::string path_to_maps = "/proc/" + m_pid_string + "/maps";
    std::ifstream ifstream_to_maps(path_to_maps);
    if(!ifstream_to_maps.is_open()){
        return std::nullopt;
    }

    std::vector<AddressContainer> temporary_valid_address_list{};
    std::string current_page;
    while(std::getline(ifstream_to_maps, current_page)){
        std::size_t dash_index = current_page.find('-');
        std::size_t space_index = current_page.find(' ');

        //skipping invalid mem page
        if(dash_index == std::string::npos || space_index == std::string::npos){
            continue;
        }

        std::string start_address =  current_page.substr(0, dash_index);
        std::string end_address = current_page.substr(dash_index + 1, space_index -  (dash_index + 1));
        std::string permission = current_page.substr(space_index + 1, 4);

        if(permission[0] != 'r'){
            continue;
        }

        try{
            unsigned long long start_ull = std::stoull(start_address, nullptr,  16);
            unsigned long long end_ull = std::stoull(end_address, nullptr, 16);

            temporary_valid_address_list.push_back({
                start_ull,
                end_ull,
            });
        }catch(...){
            return std::nullopt;
        }
    }
    return temporary_valid_address_list;
}

template <typename T>
    requires std::is_arithmetic_v<T>
std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_value(const std::vector<AddressContainer>& valid_address_container, T value_to_find){

    std::vector<ScannedObject> temporary_matching_address{};
    std::vector<char> bytes_container(STANDARD_OPERATION_SIZE);

    int match_count{};
    for(const auto& AddressBlock : valid_address_container){

        for(unsigned long long current_address = AddressBlock.m_start_address; current_address < AddressBlock.m_end_address;  current_address +=  STANDARD_OPERATION_SIZE){

            std::size_t used_operation_size = STANDARD_OPERATION_SIZE;
            if((current_address + STANDARD_OPERATION_SIZE) >  AddressBlock.m_end_address){
                used_operation_size = (AddressBlock.m_end_address - current_address);
            }

            struct iovec local_read_region{
                .iov_base = bytes_container.data(),
                .iov_len = used_operation_size
            };

            struct iovec remote_read_region{
                .iov_base = reinterpret_cast<void*>(current_address),
                .iov_len = used_operation_size
            };

            ssize_t bytes_read = process_vm_readv(m_pid_int, &local_read_region, 1, &remote_read_region, 1 ,0);
            if(bytes_read != -1 && bytes_read >= 4){

                for(std::size_t index{}; index + sizeof(T) <= static_cast<std::size_t>(bytes_read); index += sizeof(T)){
                    T possible_value{};
                    std::memcpy(&possible_value, &bytes_container[index], sizeof(T));
                    if(possible_value == value_to_find){
                        temporary_matching_address.push_back({current_address + index});
                        match_count += 1;
                    }
                }
            }

        }

    }
    if(match_count <= 0){
        return std::nullopt;
    }

    return temporary_matching_address;
}

template <typename T>
    requires std::is_arithmetic_v<T>
std::optional<std::vector<ScannedObject>>  ProcessDebugger::scan_captured(const std::vector<ScannedObject>& obj_list, T value_to_find){
    std::vector<ScannedObject> temporary{};

    int match_count{};
    for(auto& object : obj_list){

        T read_value{};
        struct iovec local_read_region{
            .iov_base = &read_value,
            .iov_len = sizeof(read_value)
        };
        struct iovec remote_read_region{
            .iov_base = reinterpret_cast<void*>(object.m_address),
            .iov_len  = sizeof(read_value)
        };
        ssize_t bytes_read = process_vm_readv(m_pid_int, &local_read_region, 1, &remote_read_region, 1, 0);
        if(bytes_read == -1){
            continue;
        }
        if(read_value == value_to_find){
            temporary.push_back({object.m_address});
            match_count += 1;
        }
    }

    if(match_count <= 0){
        return std::nullopt;
    }
    return temporary;
}


//explicitly instantiating the types
template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_value<int>(const std::vector<AddressContainer>&, int);
template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_value<float>(const std::vector<AddressContainer>&, float);
template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_value<double>(const std::vector<AddressContainer>&, double);

template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_captured<int>(const std::vector<ScannedObject>&, int);
template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_captured<float>(const std::vector<ScannedObject>&, float);
template std::optional<std::vector<ScannedObject>> ProcessDebugger::scan_captured<double>(const std::vector<ScannedObject>&, double);