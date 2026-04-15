#include "udp_scanner.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define HOST "10.158.56.43"
#define PORT_START 9000
#define PORT_END   9100
#define TIMEOUT_SEC 2

std::string scanUDP(int groupNumber, int &foundPort) {
    foundPort = -1;

    // Build the query string
    std::string query = "group " + std::to_string(groupNumber);

    for (int port = PORT_START; port <= PORT_END; port++) {
        // 1. Create a UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        // 2. Set a receive timeout so we don't hang forever
        struct timeval tv;
        tv.tv_sec = TIMEOUT_SEC;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 3. Set up the remote address
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, HOST, &addr.sin_addr);

        // 4. Send the query
        sendto(sock, query.c_str(), query.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));

        // 5. Wait for a response
        char buffer[256];
        memset(buffer, 0, sizeof(buffer));
        socklen_t addrLen = sizeof(addr);
        int received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                (struct sockaddr*)&addr, &addrLen);

        close(sock);

        if (received <= 0) continue; // no response, port likely closed

        std::string response(buffer, received);

        // 6. Check for error message
        if (response.substr(0, 5) == "Error") {
            std::cout << "Port " << port << " error: " << response << "\n";
            continue;
        }

        // 7. Check for valid 16-byte key
        if (received == 16) {
            foundPort = port;
            std::cout << "UDP open port found: " << port << "\n";
            return response; // this is the secret key
        }
    }

    return ""; // nothing found
}