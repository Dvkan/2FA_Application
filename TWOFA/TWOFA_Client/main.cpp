#include <iostream>
#include <cstring>
#include <sstream>
#include <vector>
#include <limits>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1" // Server IP address
#define SERVER_PORT 8080      // Server port

bool send_command(int sock, const std::string& command) {
    if (send(sock, command.c_str(), command.size(), 0) < 0) {
        std::cerr << "Failed to send command to server.\n";
        return false;
    }

    return true;
}

std::string receive_response(int sock) {
    char buffer[4096] = {0};
    
    int valread = read(sock, buffer, 1024);
    if (valread > 0) {
        buffer[valread] = '\0';
    } else {
        std::cerr << "Failed to read response from server.\n";
        return "failure";
    }

    std::string return_value(buffer);
    return return_value;
}
 
int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error\n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/Address not supported\n";
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection to the server failed\n";
        return -1;
    }

    std::cout << "Connected to the 2FA server.\n";

    char buffer[4096];
    std::string response;
    std::string username;
    bool logged_in = false;

    while (true) {
        if (!logged_in) {
            // First menu: Login, Register, or Exit
            std::cout << "Available commands: \n"
                        "- LOGIN <username> <password>\n"
                        "- REGISTER <username> <password>\n"
                        "- EXIT\n";
            std::cout << "> ";

            std::string input;
            std::getline(std::cin, input);

            std::vector<std::string> commandParts;
            std::istringstream stream(input);
            std::string word;
            while (stream >> word) {
                commandParts.push_back(word);
            }

            if (commandParts.empty()) {
                std::cout << "Invalid command. Try again.\n";
                continue;
            }

            const std::string& command = commandParts[0];

            if (command == "LOGIN" && commandParts.size() == 3) {
                std::string username = commandParts[1];
                std::string password = commandParts[2];
                std::string fullCommand = "LOGIN " + username + " " + password;

                if (send_command(sock, fullCommand)) {
                    response = receive_response(sock);
                    if (response.substr(0, 2) == "12") { // Success
                        std::cout << response.substr(3) << std::endl;
                        logged_in = true;
                    } else { // Failure
                        std::cout << "Login failed. Reason: " << response.substr(3) << std::endl;
                    }
                } else {
                    std::cerr << "Failed to send. Try again.\n";
                }
            } else if (command == "REGISTER" && commandParts.size() == 3) {
                std::string username = commandParts[1];
                std::string password = commandParts[2];
                std::string fullCommand = "REGISTER " + username + " " + password;

                if (send_command(sock, fullCommand)) {
                    response = receive_response(sock);
                    if (response.substr(0, 2) == "10") { // Success
                        std::cout << response.substr(3) << std::endl;
                        logged_in = true;
                    } else { // Failure
                        std::cout << "Registration failed. Reason: " << response.substr(3) << std::endl;
                    }
                } else {
                    std::cerr << "Failed to send. Try again.\n";
                }
            } else if (command == "EXIT") {
                std::cout << "Quitting the client.\n";
                close(sock);
                return 0;
            } else {
                std::cout << "Invalid command. Try again.\n";
            }
        } else {
            // Second menu: Logout, Inbox, or Exit
            std::cout << "Available commands: \n"
                        "- LOGOUT\n"
                        "- INBOX\n"
                        "- EXIT\n";
            std::cout << "> ";

            std::string input;
            std::getline(std::cin, input);

            if (input == "LOGOUT") {
                std::string command = "LOGOUT " + username;
                if (send_command(sock, command)) {
                    response = receive_response(sock);
                    if (response.substr(0, 2) == "09") { 
                        std::cout << response.substr(3) << std::endl;
                        logged_in = false;
                        username.clear();
                    } else { 
                        std::cout << "Logout failed. Reason: " << response.substr(3) << std::endl;
                    }
                } else {
                    std::cerr << "Failed to send. Try again.\n";
                }
            } else if (input == "INBOX") {
                std::string command = "INBOX " + username;
                if (send_command(sock, command)) {
                    response = receive_response(sock);
                    if (response.substr(0, 2) == "86") { 
                        std::cout << response.substr(3) << std::endl;
                    } else { 
                        std::cout << "Retrieval failed. Reason: " << response.substr(3) << std::endl;
                    }
                } else {
                    std::cerr << "Failed to send. Try again.\n";
                }
            } else if (input == "EXIT") {
                std::string command = "LOGOUT " + username;
                if (send_command(sock, command)) {
                    response = receive_response(sock);
                    if (response.substr(0, 2) == "09") { // Success
                        std::cout << response.substr(3) << std::endl;
                        logged_in = false;
                        username.clear();
                    }
                }
                std::cout << "Exiting client.\n";
                close(sock);
                return 0;
            } else {
                std::cout << "Invalid command. Try again.\n";
            }
        }
    }

    return 0;
}
