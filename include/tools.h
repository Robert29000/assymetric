//
// Created by Роберт Артур Меликян on 04/05/2021.
//

#ifndef ASSYMETRIC_TOOLS_H
#define ASSYMETRIC_TOOLS_H

#include <string>
#include <utility>

void write_keys_to_directory(const std::string& directory, const std::pair<std::string, std::string>& keypair);
std::string sha256(const std::string& data);
long long get_random_number();

#endif //ASSYMETRIC_TOOLS_H
