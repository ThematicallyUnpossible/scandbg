#include <iostream>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char* argv[])
{
    if(argc != 2){
        std::cout << "Invalid usage. Expected : scandbg <PID>";
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


    std::string address_string{};

    std::cout << "Type the virtual address you want to read : ";
    std::cin >> address_string;

    unsigned long long remote_pointer = std::stoull(address_string, nullptr, 16);

    int target_int;

    struct iovec local_object;
    local_object.iov_base = &target_int;
    local_object.iov_len = sizeof(target_int);

    struct iovec remote_object;
    remote_object.iov_base = (void*)remote_pointer;
    remote_object.iov_len = sizeof(target_int);

    ssize_t bytes_read = process_vm_readv(pid_int, &local_object, 1, &remote_object, 1, 0);
    if(bytes_read == -1){
        std::cerr << "Unable to read int virtual memory space.";
        return 1;
    }

    std::cout << target_int;


    return 0;
}
