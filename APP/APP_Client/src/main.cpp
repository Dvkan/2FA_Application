#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

void handle_server_communication(int sock) {
    char buffer[BUFFER_SIZE];
    fd_set readfds;
    int activity;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        activity = select(sock + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
                buffer[strcspn(buffer, "\n")] = '\0';  
                send(sock, buffer, strlen(buffer), 0);

                if (strcmp(buffer, "exit") == 0) {
                    printf("Exiting...\n");
                    break;
                }
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            int valread = read(sock, buffer, BUFFER_SIZE);
            if (valread == 0) {
                printf("Server disconnected\n");
                break;
            } else if (valread > 0) {
                buffer[valread] = '\0';
                printf("Server: %s\n", buffer);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    int sock;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server at %s:%d\n", server_ip, server_port);

    handle_server_communication(sock);

    close(sock);
    return 0;
}
