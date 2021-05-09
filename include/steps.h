//
// Created by Роберт Артур Меликян on 04/05/2021.
//

#ifndef ASSYMETRIC_STEPS_H
#define ASSYMETRIC_STEPS_H

#include <utility>
#include <string>

std::pair<std::string, std::string> generate_rsa_keys(); // first element - public key, second element - private key
void exchange_public_keys();
long long trinket_generate_handshake(int command);
std::pair<long long, unsigned char*> car_process_handshake(long long challenge); // first element - challenge, second element - signature
bool check_car_signature(long long challenge, unsigned char* signature);
unsigned char* trinket_process_challenge(long long challenge);
bool check_trinket_signature(long long challenge, unsigned char* signature);

#endif //ASSYMETRIC_STEPS_H
