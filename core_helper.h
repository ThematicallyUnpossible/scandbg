#ifndef CORE_HELPER_H
#define CORE_HELPER_H
#include "core.h"
#include  "utility.h"

template <typename T>
void helper_scan_value(std::optional<ProcessDebugger>& system_object, std::optional<std::vector<AddressContainer>>&  valid_address_list, std::optional<std::vector<ScannedObject>>& address_buffer){
    T value_to_find{};
    prompt_mutate_unified<T>(value_to_find, "[?] type the value to be scanned : ");
    address_buffer = system_object.value().multithread_scan_value<T>(valid_address_list.value(), value_to_find);
    if(!address_buffer || address_buffer.value().empty()){
        std::cout << "[x] no value found.\n";
        return;
    }else{
        print_addresses(address_buffer.value());
    }
}

template  <typename T>
void helper_write_value(std::optional<ProcessDebugger>&  system_object, unsigned  long long  selected_address_ull){
    T overwrite_with{};
    prompt_mutate_unified<T>(overwrite_with, "[?] type a integer value to overwrite with : ");
    bool result = system_object.value().write_value(selected_address_ull, overwrite_with);
    if(!result){
        std::cerr << "[!] failed to write at address. continuing anyway";
    }
    else{
        std::cout << "[*] succesfulyl written";
    }
}

template <typename T>
void helper_scan_captured(std::optional<ProcessDebugger>& system_object, std::vector<ScannedObject>& capture_buffer, std::optional<std::vector<ScannedObject>>& address_buffer){
    int value_to_find{};
    prompt_mutate_unified(value_to_find, "[?] type the value to be scanned : ");
    auto result = system_object.value().scan_captured<int>(capture_buffer, value_to_find);
    if(!result){
        std::cerr << "[!] no value found\n";
        return;
    }
    address_buffer = result.value();
    print_addresses(result.value());
}

#endif // CORE_HELPER_H
