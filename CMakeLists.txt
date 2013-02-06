project(mingwdumper)
cmake_minimum_required(VERSION 2.6)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(mingwdumper_SRCS main.cpp)
add_executable(mingwdumper ${mingwdumper_SRCS})

# install(TARGETS mingwdumper RUNTIME DESTINATION bin)
