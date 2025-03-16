#include "server.h"

const char* DB_FILE = "users.db";

void initialize_database() {
    sqlite3* db;
    char* err_msg = nullptr;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        exit(EXIT_FAILURE);
    }

    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            status INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS otp (
            username TEXT PRIMARY KEY,
            otp TEXT NOT NULL,
            generation_time INTEGER NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
        );
    )";

    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << "\n";
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    sqlite3_close(db);
}

void add_otp_entry(const std::string& username, const std::string& otp) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        return;
    }

    std::time_t generation_time = std::time(nullptr);

    const char* sql = R"(
        INSERT INTO otp (username, otp, generation_time) VALUES (?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET otp = excluded.otp, generation_time = excluded.generation_time;
    )";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << "\n";
        sqlite3_close(db);
        return;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, otp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, generation_time);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << "\n";
    } else {
        std::cout << "OTP entry added or updated successfully for user: " << username << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

bool is_otp_valid(const std::string& username, const std::string& otp, int validity_duration_seconds) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    const char* sql = "SELECT otp, generation_time FROM otp WHERE username = ? AND otp = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << "\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, otp.c_str(), -1, SQLITE_STATIC);

    bool otp_found = false;
    std::string db_otp;
    std::time_t db_generation_time = 0;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        otp_found = true;
        db_otp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        db_generation_time = sqlite3_column_int64(stmt, 1);
    }

    sqlite3_finalize(stmt);

    if (!otp_found) {
        std::cerr << "OTP not found for user: " << username << "\n";
        sqlite3_close(db);
        return false;
    }

    std::time_t current_time = std::time(nullptr);
    if (db_otp == otp && current_time - db_generation_time <= validity_duration_seconds) {
        std::cout << "OTP is valid for user: " << username << "\n";
        sqlite3_close(db);
        return true;
    } else {
        std::cerr << "OTP is invalid or expired for user: " << username << "\n";
        sqlite3_close(db);
        return false;
    }
}

std::string hash_password(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    std::ostringstream hashed_password;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashed_password << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return hashed_password.str();
}

bool register_user(const std::string& username, const std::string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    const char* check_sql = "SELECT COUNT(*) FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    int username_exists = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        username_exists = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (username_exists > 0) {
        std::cerr << "Username already exists\n";
        sqlite3_close(db);
        return false;
    }

    std::string hashed_password = hash_password(password);

    const char* insert_sql = "INSERT INTO users (username, password, status) VALUES (?, ?, 0)";
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert user into the database\n";
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    std::cout << "User registered successfully: " << username << "\n";
    return true;
}

bool validate_login(const std::string& username, const std::string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    std::string hashed_password = hash_password(password);

    const char* sql = "SELECT * FROM users WHERE username = ? AND password = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password.c_str(), -1, SQLITE_STATIC);

    bool valid = (sqlite3_step(stmt) == SQLITE_ROW);

    if (valid) {
        const char* update_sql = "UPDATE users SET status = 1 WHERE username = ?";
        sqlite3_stmt* update_stmt;
        sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, nullptr);
        sqlite3_bind_text(update_stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(update_stmt);
        sqlite3_finalize(update_stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return valid;
}

void logout_user(const std::string& username) {
    sqlite3* db;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
        return;
    }

    const char* sql = "UPDATE users SET status = 0 WHERE username = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
    } else {
        std::cerr << "Failed to prepare logout statement\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::string generate_time_based_otp(const std::string& secret, int interval) {
    std::time_t current_time = std::time(nullptr) / interval;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    HMAC(EVP_sha256(),
         secret.c_str(), secret.size(),
         reinterpret_cast<unsigned char*>(&current_time), sizeof(current_time),
         hash, &hash_len);

    unsigned int offset = hash[hash_len - 1] & 0x0F;
    unsigned int binary =
        (hash[offset] & 0x7f) << 24 |
        (hash[offset + 1] & 0xff) << 16 |
        (hash[offset + 2] & 0xff) << 8 |
        (hash[offset + 3] & 0xff);

    unsigned int otp = binary % 1000000;

    std::ostringstream otp_stream;
    otp_stream << std::setw(6) << std::setfill('0') << otp;
    return otp_stream.str();
}

std::string handle_request(const std::string& command, int client_socket, std::map<int, std::string>& socket_to_username) {
    std::string user = (socket_to_username.count(client_socket) > 0) ? socket_to_username[client_socket] : "";

    size_t auth_pos = command.find("Authorization: ");
    if (auth_pos != std::string::npos) {
        std::string secret_key = command.substr(auth_pos + strlen("Authorization: "));
        secret_key.erase(secret_key.find("\n")); 

        if (!validate_shared_secret(secret_key)) {
            return "Error: Unauthorized Access - Invalid Shared Secret Key";
        } else {
            size_t space_pos = command.find(' ', auth_pos + strlen("Authorization: "));
    
            if (space_pos == std::string::npos) {
                return "Error: Invalid command format.";
            }

            std::string actual_command = command.substr(space_pos + 1);
            std::cout << actual_command << std::endl;

            if (actual_command.substr(0, 7) == "REQ_OTP") {
                std::istringstream iss(actual_command);
                std::string cmd, username;
                iss >> cmd >> username;

                if (username.empty()) {
                    return "04_Username is missing for REQ_OTP.";
                }

                add_otp_entry(username, generate_time_based_otp(username, 60));
                return "Y_Succes: Created OTP";

            } else if(actual_command.substr(0, 7) == "VAL_OTP") {
                std::istringstream iss(actual_command);
                std::string cmd, username, otp;
                iss >> cmd >> username >> otp;

                if(is_otp_valid(username, otp)) return "Y_SUCCES";
                else return "FAILURE";

            } else if (actual_command.substr(0, 8) == "REQ_APPR") {
                std::istringstream iss(actual_command);
                std::string cmd, username;
                iss >> cmd >> username;

                if (username.empty()) {
                    return "04_Username is missing for REQ_APPR.";
                }

                if(!user_sessions[username]) {
                    return "User not online. Failed to request approval.";
                } else {
                    char message[BUFFER_SIZE] = "Grant access?[Y/N]";
                    int client_sock = find_key_by_value(socket_to_username, username);
                    send(client_sock, message, strlen(message), 0);

                    char buffer[BUFFER_SIZE];
                    int bytes_read = read(client_sock, buffer, BUFFER_SIZE);
                    if(bytes_read == 0) {
                        return "Client did not respond.";
                    } else if(bytes_read > 0) {
                        buffer[bytes_read] = '\0';
                        return buffer;
                    }
                }
            } else {
                return "ERR.";
            }
        }
    }

    if (command.substr(0, 8) == "REGISTER") {
        std::istringstream iss(command);
        std::string cmd, uname, pwd;
        iss >> cmd >> uname >> pwd;

        if (register_user(uname, pwd)) {
            user_sessions[uname] = true;
            socket_to_username[client_socket] = uname; 
            return "10_Registration successful.";
        } else {
            return "11_Username may already exist.";
        }
    }
    else if (command.substr(0, 5) == "LOGIN") {
        std::istringstream iss(command);
        std::string cmd, uname, pwd;
        iss >> cmd >> uname >> pwd;

        if (user_sessions[uname]) {
            return "14_User already logged in.";
        }

        if (validate_login(uname, pwd)) {
            user_sessions[uname] = true;             
            socket_to_username[client_socket] = uname; 
            return "12_Login successful.";
        } else {
            return "13_Invalid credentials.";
        }
    }
    else if (command.substr(0, 6) == "LOGOUT") {
        if (user.empty()) {
            return "08_User is not logged in.";
        }

        if (user_sessions[user]) {
            logout_user(user);
            user_sessions[user] = false;

            socket_to_username.erase(client_socket);

            return "09_Logout successful for " + user;
        } else {
            return "08_User is not logged in.";
        }
    }
    else if (!user.empty() && user_sessions[user]) {
        if (command.substr(0, 5) == "INBOX") {
            std::cout << "Retrieving inbox for " << user << std::endl;
            return "86_inbox_get()"; 
        }
    } else {
        return "Access denied. Please log in first.";
    }

    return "Unknown error.";
}

void handle_disconnection(int client_socket, std::map<int, std::string>& socket_to_username) {
    auto it = socket_to_username.find(client_socket);
    if (it != socket_to_username.end()) {
        std::string username = it->second;

        user_sessions[username] = false;

        socket_to_username.erase(it);

        std::cout << "User " << username << " logged out due to disconnection.\n";
    }

    // Close the socket
    close(client_socket);
}

bool validate_shared_secret(const std::string& secret_key) {
    for (const auto& key : shared_secret_keys) {
        if (key == secret_key) {
            return true;
        }
    }
    return false;
}

int find_key_by_value(const std::map<int, std::string>& my_map, const std::string& value) {
    for (const auto& pair : my_map) {
        if (pair.second == value) {
            return pair.first;  
        }
    }
    return -1;  
}