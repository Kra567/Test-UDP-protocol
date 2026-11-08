cmake_minimum_required(VERSION 3.16)
project(udp_handshake LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(crypto_backend STATIC
    src/secure_zero.c
    third_party/sha-256.c
)
target_include_directories(crypto_backend PUBLIC include)
target_compile_options(crypto_backend PRIVATE -Wall -Wextra -Werror)

add_executable(server src/run_server.cpp)
target_link_libraries(server PRIVATE crypto_backend)
target_compile_options(server PRIVATE -Wall -Wextra -Werror)

add_executable(client src/run_client.cpp)
target_link_libraries(client PRIVATE crypto_backend)
target_compile_options(client PRIVATE -Wall -Wextra -Werror)
