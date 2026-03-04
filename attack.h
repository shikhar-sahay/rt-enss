#ifndef ATTACK_H
#define ATTACK_H

#include <systemc.h>
#include "network.h"

SC_MODULE(AttackInjector) {

    Network* net;

    void inject() {

        wait(50, SC_MS);

        //Hardcoded Spoofing Attack
        Message fake;
        fake.sender = 99;
        fake.data = 999;
        fake.timestamp = sc_time_stamp();

        std::cout << "Spoofing Attack Injected\n";
        net->transmit(fake);

        wait(50, SC_MS);

        //Harcoded DoS Attack
        std::cout << "DoS Attack Injected\n";
        for (int i = 0; i < 30; i++) {
            Message flood;
            flood.sender = 99;
            flood.data = rand();
            flood.timestamp = sc_time_stamp();
            net->transmit(flood);
        }
    }

    SC_HAS_PROCESS(AttackInjector);

    AttackInjector(sc_module_name name, Network* network)
        : sc_module(name), net(network) {
        SC_THREAD(inject);
    }
};

#endif