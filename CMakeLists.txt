cmake_minimum_required(VERSION 3.17)

set(CMAKE_CXX_STANDARD 14)

include("cmake/HunterGate.cmake")

HunterGate(
        URL "https://github.com/cpp-pm/hunter/archive/v0.16.15.tar.gz"
        SHA1 "6974c2150fc0d3b09de3ad1efcbf15d360647ffa"
)

project(assymetric)

add_library(steps STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/sources/steps.cpp
        )

add_library(tools STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/sources/tools.cpp
        )

target_include_directories(steps PUBLIC
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(tools PUBLIC
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

add_executable(assymetric main.cpp)

target_link_libraries(tools PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(steps PUBLIC OpenSSL::SSL OpenSSL::Crypto tools)
target_link_libraries(assymetric PUBLIC OpenSSL::SSL OpenSSL::Crypto steps tools)