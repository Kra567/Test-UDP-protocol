#include "server.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: server <bind-ipv4> <port> (0 = free port)\n";
        return 1;
    }

    try {
        std::size_t length = 0;
        const unsigned long port = std::stoul(argv[2], &length);
        if (argv[2][length] != '\0' || port > 65535) {
            throw std::invalid_argument("Invalid port");
        }

        Server server;
        const auto bound = server.bind({argv[1], static_cast<std::uint16_t>(port)});
        if (!bound) {
            std::cerr << "Failed to bind " << argv[1] << ':' << port << '\n';
            return 1;
        }

        std::cout << "listening " << bound->ip << ':' << bound->port << std::endl;
        server.run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
