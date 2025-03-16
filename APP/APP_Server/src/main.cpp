#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define PORT 8083
#define TWOFA_SERVER_IP "127.0.0.1"
#define TWOFA_SERVER_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    int logged_in;
    char* username;
} Client;

const char* display_choices = "Choose an option:\n1)OTP\n2)Remote Approuval\nEnter choice: ";

bool communicate_with_twofa(Client *client, const char* message) {
    int sock;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TWOFA_SERVER_PORT);

    if (inet_pton(AF_INET, TWOFA_SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection to external server failed");
        close(sock);
        return false;
    }

    char auth_message[BUFFER_SIZE] = "Authorization: 23DX52@czS-@#jdaSJUDn-fk21@54dXV\n";
    strcat(auth_message, message);  

    send(sock, auth_message, strlen(auth_message), 0);
    std::cout << "Message sent to TWOFA server: " << auth_message << std::endl;

    char buffer[1024] = {0};

    int valread = read(sock, buffer, 1024);
    if (valread > 0) {
        std::cout << "Response from TWOFA server: " << buffer << std::endl;

        close(sock);
        if (strncmp(buffer, "Y", 1) == 0) return true;
        else return false;
    } else {
        std::cerr << "Error reading response from TWOFA server." << std::endl;
        close(sock);
        return false;
    }

    close(sock);
    return true;
}

void handle_client_message(Client *client, char *message) {
    char buffer[BUFFER_SIZE];

    if (strncmp(message, "login", 5) == 0) {
        if (client->logged_in) {
            send(client->socket, "Already logged in\n", 19, 0);
        } else {
            send(client->socket, display_choices, strlen(display_choices), 0);

            // nume default
            client->username = "vlad";

            int bytes_read = read(client->socket, buffer, BUFFER_SIZE - 1);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0'; 

                if (strcmp(buffer, "1") == 0) {
                    char request[BUFFER_SIZE] = "Command: REQ_OTP ";
                    strcat(request, client->username);

                    if (communicate_with_twofa(client, request)) {
                        send(client->socket, "Enter OTP: ", 11, 0);
                        bytes_read = read(client->socket, buffer, BUFFER_SIZE - 1);
                        if (bytes_read > 0) {
                            buffer[bytes_read] = '\0';
                            char request2[BUFFER_SIZE] = "Command: VAL_OTP ";
                            strcat(request2, client->username);
                            strcat(request2, " ");
                            strcat(request2, buffer);

                            if (communicate_with_twofa(client, request2)) {
                                send(client->socket, "Login approved.\n", 17, 0);
                                client->logged_in = 1;
                            } else {
                                send(client->socket, "Invalid OTP.\n", 13, 0);
                            }
                        }
                    } else {
                        send(client->socket, "Error sending OTP request.\n", 27, 0);
                    }
                } else if (strcmp(buffer, "2") == 0) {
                    char request[BUFFER_SIZE] = "Command: REQ_APPR ";
                    strcat(request, client->username);

                    if (communicate_with_twofa(client, request)) {
                        send(client->socket, "Access granted.\n", 17, 0);
                        client->logged_in = 1;
                    } else {
                        send(client->socket, "Access denied.\n", 16, 0);
                    }
                } else {
                    send(client->socket, "Invalid choice.\n", 16, 0);
                }
            } else {
                send(client->socket, "Error reading choice.\n", 22, 0);
            }
        }
    } else if (strncmp(message, "logout", 6) == 0) {
        if (client->logged_in) {
            client->logged_in = 0;
            send(client->socket, "Logout successful\n", 19, 0);
        } else {
            send(client->socket, "Not logged in\n", 14, 0);
        }
    } else if (strncmp(message, "exit", 4) == 0) {
        send(client->socket, "Goodbye\n", 8, 0);
        close(client->socket);
        client->socket = 0;
        client->logged_in = 0;
    } else {
        send(client->socket, "Invalid command\n", 17, 0);
    }
}

int main() {
    int server_fd, new_socket, max_sd, sd, activity;
    struct sockaddr_in address;
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    Client clients[MAX_CLIENTS];

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = 0;
        clients[i].logged_in = 0;
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d\n", PORT);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = clients[i].socket;
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            if (sd > max_sd) {
                max_sd = sd;
            }
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            socklen_t addrlen = sizeof(address);
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
                perror("Accept failed");
                exit(EXIT_FAILURE);
            }
            printf("New connection: socket fd %d, ip %s, port %d\n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == 0) {
                    clients[i].socket = new_socket;
                    clients[i].logged_in = 0;
                    printf("Added client to slot %d\n", i);
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = clients[i].socket;
            if (FD_ISSET(sd, &readfds)) {
                int valread = read(sd, buffer, BUFFER_SIZE);
                if (valread == 0) {
                    socklen_t addrlen = sizeof(address);
                    getpeername(sd, (struct sockaddr *)&address, &addrlen);
                    printf("Client disconnected: ip %s, port %d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    close(sd);
                    clients[i].socket = 0;
                    clients[i].logged_in = 0;
                } else {
                    buffer[valread] = '\0';
                    handle_client_message(&clients[i], buffer);
                }
            }
        }
    }

    return 0;
}
