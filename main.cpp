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

    std::string path = "/proc/" + pid_string + "/maps";

    int target_fd = open(path.c_str(), O_RDONLY);

    if(target_fd == -1){
        std::cerr << "Unable to open file [ " << path << " ] \n";
        return 1;
    }

    return 0;
}
