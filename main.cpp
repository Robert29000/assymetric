#include <iostream>
#include <tools.h>
#include <steps.h>

int main() {
    int step = 0;
    //  keypair generation for car. Comment if keys already exists
    auto car_keys = generate_rsa_keys();
    write_keys_to_directory("car", car_keys);
    auto car_id = sha256(car_keys.first);  // hash from public key
    std::cout << step << ": " << "(generation) " << car_id << " (public and private keys written to car)" << std::endl;

    step++;

    //  keypair generation for trinket. Comment if keys already exists
    auto trinket_keys = generate_rsa_keys();
    write_keys_to_directory("trinket", trinket_keys);
    auto trinket_id = sha256(trinket_keys.first);
    std::cout << step << ": " << "(generation) " << trinket_id << " (public and private keys written to trinket)" << std::endl;

    step++;

    //  registration, only for the first time. Comment if public keys already exchanged
    exchange_public_keys();
    std::cout << step << ": " << "(registration) " <<
        trinket_id << " (trinket pubkey written to car), " << car_id << " (car pubkey written to trinket)" << std::endl;

    step++;
    int attempt_count = 1;
    int command = 1;
    long long challenge_for_car;
    long long challenge_for_trinket;

    while(attempt_count < 5) {
        // send from trinket to car command and challenge
        challenge_for_car = trinket_generate_handshake(command);
        std::cout << step << ": " << "(handshake) trinket -> car: " << command << " (command id), " << challenge_for_car << " (challenge for car)" << std::endl;

        step++;

        // send from car to trinket challenge and car's signature
        auto res = car_process_handshake(challenge_for_car);
        challenge_for_trinket = res.first;
        std::cout << step << ": " << "(challenge) car -> trinket: " << challenge_for_trinket << " (challenge for trinket), " << res.second << " (car signature)" << std::endl;

        step++;

        // trinket checks car's signature. If it fails, process will start over
        if (check_car_signature(challenge_for_car, res.second)){
            std::cout << step << ": " << "(verification) trinket: true (car signature checked)" << std::endl;
            step++;
        } else {
            std::cout << step << ": " << "(verification) trinket: false (car signature failed)" << std::endl;
            attempt_count++;
            step++;
            continue;
        }

        // send from trinket to car trinket's signature
        auto signature = trinket_process_challenge(challenge_for_trinket);
        std::cout << step << ": " << "(response) trinket -> car: " << signature << " (trinket signature)" << std::endl;

        step++;

        // car checks trinket's signature. If it fails, process will start over
        if (check_trinket_signature(challenge_for_trinket, signature)) {
            std::cout << step << ": " << "(verification) car: true (trinket signature checked)" << std::endl;
            step++;
        } else {
            std::cout << step << ": " << "(verification) car: false (trinket signature failed)" << std::endl;
            attempt_count++;
            step++;
            continue;
        }

        std::cout << step << ": " << "(action) car: OPEN DOOR";
        break;
    }

    if (attempt_count == 5) {
        std::cout << "Too many attempts. Terminating process." << std::endl;
    }

    return 0;
}





