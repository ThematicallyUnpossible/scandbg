#ifndef CORE_H
#define CORE_H

#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <optional>
#include <type_traits>

#define STANDARD_OPERATION_SIZE 4096

struct AddressContainer{
    unsigned long long m_start_address;
    unsigned long long m_end_address;
};

struct ScannedObject{
    unsigned long long m_address;
};

class ProcessDebugger{
private :
    int m_pid_int{};
    std::string m_pid_string{};
    std::vector<AddressContainer> m_valid_address_list{};

    ProcessDebugger(int pid_int, std::string pid_string);

public:
    ProcessDebugger() = delete;

    int get_pid_int() const;

    std::string get_pid_string() const;

    static std::optional<ProcessDebugger> create(std::string pid_string);

    std::optional<std::vector<AddressContainer>> scan_memory_map();

    template <typename T>
        requires std::is_arithmetic_v<T>
    std::optional<std::vector<ScannedObject>> scan_value(const std::vector<AddressContainer>& valid_address_container, T value_to_find);

    template <typename T>
        requires std::is_arithmetic_v<T>
    std::optional<std::vector<ScannedObject>>  scan_captured(const std::vector<ScannedObject>& obj_list, T value_to_find);

    template <typename T>
        requires std::is_arithmetic_v<T>
    bool write_value(unsigned long long selected_address_ull, T overwrite_with);
};


#endif // CORE_H
