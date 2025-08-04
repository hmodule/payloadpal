#include <iostream>
#include <thread>
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "json.hpp"
#include "httplib.h"

using json = nlohmann::json;

const std::string SERVER_URL = "http://localhost:1200";
const std::string ENCRYPTION_KEY = "your-32-char-encryption-key-here"; // Should match server

bool keepRunning = true;
std::mutex consoleMutex;
bool moduleDownloaded = false;
std::string authToken;
std::string userRole;

// Encryption utilities
std::string decryptData(const std::string& encryptedData, const std::string& iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        std::cerr << "Failed to create cipher context" << std::endl;
        return "";
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          (const unsigned char*)ENCRYPTION_KEY.c_str(), 
                          (const unsigned char*)iv.c_str()) != 1) {
        std::cerr << "Failed to initialize decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::string decrypted;
    int len;
    unsigned char outbuf[1024];

    // Convert hex string to binary
    std::string binaryData;
    for(size_t i = 0; i < encryptedData.length(); i += 2) {
        std::string byteString = encryptedData.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        binaryData += byte;
    }

    if(EVP_DecryptUpdate(ctx, outbuf, &len, 
                         (const unsigned char*)binaryData.c_str(), 
                         binaryData.length()) != 1) {
        std::cerr << "Failed to decrypt data" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    decrypted.append((char*)outbuf, len);

    if(EVP_DecryptFinal_ex(ctx, outbuf, &len) != 1) {
        std::cerr << "Failed to finalize decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    decrypted.append((char*)outbuf, len);

    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

// Login function with password authentication
bool login(const std::string& name, const std::string& role, const std::string& password) {
    httplib::Client client(SERVER_URL.c_str());

    json packet = {
        {"type", "login"},
        {"payload", {
            {"name", name}, 
            {"role", role},
            {"password", password}
        }}
    };

    auto res = client.Post("/login", packet.dump(), "application/json");
    std::lock_guard<std::mutex> lock(consoleMutex);

    if (!res || res->status != 200) {
        std::cerr << "Failed to login. Server response: "
                  << (res ? res->body : "No response") << "\n";
        return false;
    }

    try {
        auto responseJson = json::parse(res->body);
        if (responseJson.contains("token")) {
            authToken = responseJson["token"];
            userRole = responseJson["role"];
            std::cout << "Login successful! Role: " << userRole << "\n";
            return true;
        } else {
            std::cerr << "No token received from server\n";
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse login response: " << e.what() << "\n";
        return false;
    }
}

void sendHeartbeat(const std::string& name, const std::string& role) {
    while (keepRunning) {
        httplib::Client client(SERVER_URL.c_str());
        
        // Add authorization header
        httplib::Headers headers = {
            {"Authorization", "Bearer " + authToken}
        };

        json packet = {
            {"type", "heartbeat"},
            {"payload", {{"name", name}, {"role", role}}}
        };

        auto res = client.Post("/heartbeat", headers, packet.dump(), "application/json");

        std::lock_guard<std::mutex> lock(consoleMutex);
        if (!res || res->status != 200) {
            std::cerr << "Failed to send heartbeat. Status: "
                      << (res ? std::to_string(res->status) : "No response") << "\n";
            if (res && res->status == 401) {
                std::cerr << "Authentication failed. Please login again.\n";
                break;
            }
        } else {
            std::cout << "Heartbeat sent successfully.\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

bool downloadModule(const std::string& name, const std::string& moduleName) {
    httplib::Client client(SERVER_URL.c_str());
    
    // Add authorization header
    httplib::Headers headers = {
        {"Authorization", "Bearer " + authToken}
    };

    json packet = {
        {"type", "download_module"},
        {"payload", {{"name", name}, {"module_name", moduleName}}}
    };

    auto res = client.Post("/download_module", headers, packet.dump(), "application/json");
    std::lock_guard<std::mutex> lock(consoleMutex);
    
    if (res && res->status == 200) {
        try {
            auto responseJson = json::parse(res->body);
            
            if (responseJson.contains("error")) {
                std::cerr << "Error: " << responseJson["error"] << "\n";
                return false;
            }

            std::string fileName = responseJson["fileName"];
            std::string encryptedData = responseJson["module_data"];
            std::string iv = responseJson["iv"];

            // Decrypt the module data
            std::string decryptedData = decryptData(encryptedData, iv);
            if (decryptedData.empty()) {
                std::cerr << "Failed to decrypt module data\n";
                return false;
            }

            // Save the decrypted module
            std::ofstream outFile(fileName + "_decrypted.txt");
            outFile << decryptedData;
            outFile.close();

            std::cout << "Module downloaded and decrypted successfully: " << fileName << "_decrypted.txt\n";
            std::cout << "Module content preview:\n" << decryptedData.substr(0, 200) << "...\n";
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse module response: " << e.what() << "\n";
            return false;
        }
    } else {
        std::cerr << "Failed to download module. Server response: " 
                  << (res ? res->body : "No response") << "\n";
        return false;
    }
}

void logout(const std::string& name) {
    httplib::Client client(SERVER_URL.c_str());
    
    // Add authorization header
    httplib::Headers headers = {
        {"Authorization", "Bearer " + authToken}
    };

    json packet = {
        {"type", "logout"},
        {"payload", {{"name", name}}}
    };

    auto res = client.Post("/logout", headers, packet.dump(), "application/json");
    std::lock_guard<std::mutex> lock(consoleMutex);
    if (res && res->status == 200) {
        std::cout << "Logged out successfully.\n";
    } else {
        std::cerr << "Failed to logout properly.\n";
    }
}

void getUsers(const std::string& name, const std::string& role) {
    httplib::Client client(SERVER_URL.c_str());
    
    // Add authorization header
    httplib::Headers headers = {
        {"Authorization", "Bearer " + authToken}
    };

    auto res = client.Get("/get_users", headers);
    std::lock_guard<std::mutex> lock(consoleMutex);
    
    if(res && res->status == 200) {
        try {
            auto responseJson = json::parse(res->body);
            std::cout << "\n=== Active Users ===\n";
            std::cout << "Total users: " << responseJson["total"] << "\n";
            
            for (const auto& user : responseJson["users"]) {
                std::cout << "User: " << user["name"] 
                          << " | Role: " << user["role"]
                          << " | Module: " << user["module"]
                          << " | Active: " << (user["isActive"] ? "Yes" : "No")
                          << " | IP: " << user["ip"] << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse users response: " << e.what() << "\n";
        }
    } else {
        std::cerr << "Failed to get users. Status: " 
                  << (res ? std::to_string(res->status) : "No response") << "\n";
    }
}

void showMenu() {
    std::cout << "\n=== Secure Module Transfer Client ===\n";
    std::cout << "1. Download Module\n";
    std::cout << "2. Get All Clients (Admin only)\n";
    std::cout << "3. Logout\n";
    std::cout << "4. Exit\n";
    std::cout << "Your choice: ";
}

int main() {
    std::string name, moduleName, role, password;

    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "=== Secure Module Transfer System ===\n";
        std::cout << "Enter your name: ";
    }
    std::cin >> name;

    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "Enter your role (user/admin): ";
    }
    std::cin >> role;

    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "Enter your password: ";
    }
    std::cin >> password;

    // Login step
    if (!login(name, role, password)) {
        std::cerr << "Login failed. Exiting.\n";
        return 1;
    }

    // Start heartbeat thread
    std::thread heartbeatThread(sendHeartbeat, name, role);

    while (true) {
        showMenu();
        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1:
                if (!moduleDownloaded) {
                    std::cout << "Enter the module you want to download: ";
                    std::cin >> moduleName;
                    if (downloadModule(name, moduleName)) {
                        moduleDownloaded = true;
                    }
                } else {
                    std::cout << "You have already downloaded a module in this session.\n";
                }
                break;

            case 2:
                if (userRole == "admin") {
                    getUsers(name, role);
                } else {
                    std::cout << "Admin access required for this operation.\n";
                }
                break;

            case 3:
                logout(name);
                keepRunning = false;
                heartbeatThread.join();
                return 0;

            case 4:
                keepRunning = false;
                heartbeatThread.join();
                return 0;

            default:
                std::cout << "Invalid option. Please try again.\n";
                break;
        }
    }

    return 0;
}
