#ifndef NETWORK_H
#define NETWORK_H

#include <systemc.h>
#include <queue>
#include <iostream>

struct Message {
    int sender;
    int data;
    sc_time timestamp;
};

SC_MODULE(Network) {
    std::queue<Message> bus;
    int max_capacity = 20;

    void transmit(Message msg) {
        if (bus.size() < (size_t)max_capacity) {
            bus.push(msg);
            std::cout << "[NETWORK] Message from Node "
                      << msg.sender << " at "
                      << sc_time_stamp() << std::endl;
        }
    }

    SC_CTOR(Network) {}

};

#endif