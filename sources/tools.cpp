//
// Created by Роберт Артур Меликян on 04/05/2021.
//

#include <tools.h>
#include <fstream>
#include <openssl/sha.h>
#include <random>
#include <sstream>

void write_keys_to_directory(const std::string& directory, const std::pair<std::string, std::string>& keypair){
    std::string file_name_pub = directory + "_pubkey.pem";
    std::string file_name_pri = directory + "_prikey.pem";

    std::ofstream file_pub(directory+"/"+file_name_pub);
    if (! file_pub) {
        throw std::runtime_error{"Can not write key to a file"};
    }
    file_pub << keypair.first;
    file_pub.close();

    std::ofstream file_pri(directory+"/"+file_name_pri);
    if (!file_pri) {
        throw std::runtime_error{"Can not write key to a file"};
    }
    file_pri << keypair.second;
    file_pri.close();
}



std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (unsigned char i : hash){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return ss.str();
}



long long get_random_number(){
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long long > distrib(INT64_MIN, INT64_MAX);
    return distrib(gen);
}