#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <map>
#include <vector>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define PORT 8080
#define MAX_CLIENTS 1000
#define BUFFER_SIZE 4096

extern std::vector<std::string> shared_secret_keys;

extern std::map<int, std::string> socket_to_username;
extern std::map<int, std::string> client_requests; 
extern std::map<std::string, std::string> otp_store; 
extern std::map<std::string, bool> user_sessions; 
extern const char* DB_FILE;

void initialize_database();
void add_otp_entry(const std::string& username, const std::string& otp);
bool is_otp_valid(const std::string& username, const std::string& otp, int validity_duration_seconds = 120);

int find_key_by_value(const std::map<int, std::string>& my_map, const std::string& value);
std::string hash_password(const std::string& password);
bool register_user(const std::string& username, const std::string& password);
bool validate_login(const std::string& username, const std::string& password);
void logout_user(const std::string& username);


std::string generate_time_based_otp(const std::string& secret, int interval = 30);
std::string handle_request(const std::string& command, int client_socket, std::map<int, std::string>& socket_to_username);
void handle_disconnection(int client_socket, std::map<int, std::string>& socket_to_username);
bool validate_shared_secret(const std::string& secret_key);
