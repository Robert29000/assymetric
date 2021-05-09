//
// Created by Роберт Артур Меликян on 04/05/2021.
//

#include <steps.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <tools.h>
#include <fstream>
#include <iostream>

std::pair<std::string, std::string> generate_rsa_keys(){
    int ret = 0;
    BIGNUM *bne = NULL;
    auto e = RSA_F4;
    RSA *keypair = NULL;

    bne = BN_new();
    ret = BN_set_word(bne, e);

    assert(ret == 1);

    keypair = RSA_new();
    ret = RSA_generate_key_ex(keypair, 2048, bne, NULL);

    assert(ret == 1);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char *pri_key = new char[pri_len + 1];
    char *pub_key = new char[pub_len + 1];

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    std::pair<std::string, std::string> res = {pub_key, pri_key};

    // free allocated memory

    delete[] pri_key;
    delete[] pub_key;
    RSA_free(keypair);
    BIO_free_all(pri);
    BIO_free_all(pub);
    BN_free(bne);

    return res;
}

void exchange_public_keys(){
    std::ifstream trinket_pub_key("trinket/trinket_pubkey.pem");
    std::ofstream car_key_dir("car/suitable_trinkets/trinket_pubkey.pem");

    car_key_dir << trinket_pub_key.rdbuf();
    trinket_pub_key.close();
    car_key_dir.close();

    std::ifstream car_pub_key("car/car_pubkey.pem");
    std::ofstream trinket_key_dir("trinket/suitable_cars/car_pubkey.pem");

    trinket_key_dir << car_pub_key.rdbuf();
    car_pub_key.close();
    trinket_key_dir.close();
}

long long trinket_generate_handshake(int command){
    auto challenge_for_car = get_random_number();
    return challenge_for_car;
}

std::pair<long long, unsigned char*> car_process_handshake(long long challenge){
    auto challenge_for_trinket = get_random_number();

    FILE *file_private_key = fopen("car/car_prikey.pem", "r");
    RSA* private_key = PEM_read_RSAPrivateKey(file_private_key, NULL, NULL, NULL);

    size_t data_size = RSA_size(private_key);
    std::string data_to_enc = std::to_string(challenge);
    auto *signature = new unsigned char[data_size];

    int res = RSA_private_encrypt(data_size, (unsigned char*)data_to_enc.c_str(),
                                  signature, private_key, RSA_NO_PADDING);

    if (res == -1){
        throw std::runtime_error{"Encryption failed"};
    }
    return {challenge_for_trinket, signature};
}

bool check_car_signature(long long challenge, unsigned char* signature){
    FILE* file_pub_key = fopen("trinket/suitable_cars/car_pubkey.pem", "r");
    RSA* car_public_key = PEM_read_RSAPublicKey(file_pub_key, NULL, NULL, NULL);

    size_t data_size = RSA_size(car_public_key);
    std::string s_challenge = std::to_string(challenge);
    unsigned char dec_challenge[data_size];

    int res = RSA_public_decrypt(data_size, signature, dec_challenge, car_public_key, RSA_NO_PADDING);
    if (res == 1){
        throw std::runtime_error{"Decryption failed"};
    }
    std::string s_dec(dec_challenge, dec_challenge + s_challenge.size());
    delete[] signature;
    return s_challenge == s_dec;
}

unsigned char* trinket_process_challenge(long long challenge){
    FILE *file_private_key = fopen("trinket/trinket_prikey.pem", "r");
    RSA* private_key = PEM_read_RSAPrivateKey(file_private_key, NULL, NULL, NULL);

    size_t data_size = RSA_size(private_key);
    std::string data_to_enc = std::to_string(challenge);
    auto *signature = new unsigned char[data_size];

    int res = RSA_private_encrypt(data_size, (unsigned char*)data_to_enc.c_str(),
                                  signature, private_key, RSA_NO_PADDING);

    if (res == -1){
        throw std::runtime_error{"Encryption failed"};
    }

    return signature;
}

bool check_trinket_signature(long long challenge, unsigned char* signature){
    FILE* file_pub_key = fopen("car/suitable_trinkets/trinket_pubkey.pem", "r");
    RSA* car_public_key = PEM_read_RSAPublicKey(file_pub_key, NULL, NULL, NULL);

    size_t data_size = RSA_size(car_public_key);
    std::string s_challenge = std::to_string(challenge);
    unsigned char dec_challenge[data_size];

    int res = RSA_public_decrypt(data_size, signature, dec_challenge, car_public_key, RSA_NO_PADDING);
    if (res == 1){
        throw std::runtime_error{"Decryption failed"};
    }

    std::string s_dec(dec_challenge, dec_challenge + s_challenge.size());
    delete[] signature;
    return s_challenge == s_dec;
}