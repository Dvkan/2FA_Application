#include "server.h"

std::vector<std::string> shared_secret_keys = {"23DX52@czS-@#jdaSJUDn-fk21@54dXV"};
std::map<int, std::string> socket_to_username;
std::map<int, std::string> client_requests; 
std::map<std::string, std::string> otp_store; 
std::map<std::string, bool> user_sessions; 

int main() {
    initialize_database();

    int server_fd, new_socket, max_sd, activity;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[4096];

    fd_set readfds;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "2FA Server is listening on port " << PORT << std::endl;

    int client_sockets[MAX_CLIENTS] = {0};

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            if (sd > max_sd) {
                max_sd = sd;
            }
        }

        activity = select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);

        if (activity < 0 && errno != EINTR) {
            perror("Select error");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                                     (socklen_t*)&addrlen)) < 0) {
                perror("Accept error");
                exit(EXIT_FAILURE);
            }

            std::cout << "New connection: socket fd = " << new_socket
                      << ", IP = " << inet_ntoa(address.sin_addr)
                      << ", port = " << ntohs(address.sin_port) << std::endl;

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];

            if (FD_ISSET(sd, &readfds)) {
                int valread = read(sd, buffer, 1024);
                if (valread == 0) {
                    handle_disconnection(sd, socket_to_username);
                    getpeername(sd, (struct sockaddr*)&address,
                                (socklen_t*)&addrlen);
                    std::cout << "Client disconnected: IP = " << inet_ntoa(address.sin_addr)
                              << ", port = " << ntohs(address.sin_port) << std::endl;
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    buffer[valread] = '\0';
                    std::string command(buffer);
                    std::string user = "user" + std::to_string(sd); 
                    std::string response = handle_request(command, sd, socket_to_username);
                    send(sd, response.c_str(), response.size(), 0);
                }
            }
        }
    }

    return 0;
}
