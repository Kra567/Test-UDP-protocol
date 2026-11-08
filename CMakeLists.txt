
cmake_minimum_required(VERSION 3.16)

project(udp_handshake LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(cryptography STATIC
    src/cryptography.cpp
    src/secure_zero.c
    third_party/sha256.c
)

target_include_directories(cryptography PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(cryptography PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_compile_options(cryptography PRIVATE -Wall -Wextra -Werror)

add_executable(exec_main src/main.cpp)
target_link_libraries(exec_main PRIVATE cryptography)

add_executable(server src/server.cpp)
target_link_libraries(server PRIVATE cryptography)

add_executable(client src/client.cpp)
target_link_libraries(client PRIVATE cryptography)

target_compile_options(exec_main PRIVATE -Wall -Wextra -Werror)
target_compile_options(server PRIVATE -Wall -Wextra -Werror)
target_compile_options(client PRIVATE -Wall -Wextra -Werror)
