#ifndef UTILITY_H
#define UTILITY_H
#include <limits>
#include <iostream>
#include <type_traits>
#include "core.h"


inline void clean_cin(){
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

#define nl std::numeric_limits
template<typename T>
    requires std::is_arithmetic_v<T>
inline void prompt_mutate_unified(T& x,std::string_view prefix,T minimum = nl<T>::min(),T maximum = nl<T>::max()){
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

inline  void print_addresses(std::vector<ScannedObject>& list){

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
#endif // UTILITY_H
