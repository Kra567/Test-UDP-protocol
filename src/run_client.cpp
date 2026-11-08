#include "client.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: client <server-ipv4> <port>\n";
        return 1;
    }

    try {
        std::size_t length = 0;
        const unsigned long port = std::stoul(argv[2], &length);
        if (argv[2][length] != '\0' || port == 0 || port > 65535) {
            throw std::invalid_argument("Invalid server port");
        }

        const UdpAddress address{argv[1], static_cast<std::uint16_t>(port)};
        if (!address.to_sockaddr()) {
            throw std::invalid_argument("Invalid server IPv4 address");
        }
        Client client{address};
        return client.run() ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
