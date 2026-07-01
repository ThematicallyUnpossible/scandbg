cmake_minimum_required(VERSION 3.16)

project(scandbg LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(scandbg main.cpp
    main.cpp)

include(GNUInstallDirs)
install(TARGETS scandbg
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
