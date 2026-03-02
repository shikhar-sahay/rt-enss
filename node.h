#ifndef NODE_H
#define NODE_H

#include <systemc.h>
#include "network.h"

SC_MODULE(Node) {

    int node_id;
    Network* net;

    void run() {
        while (true) {

            Message msg;
            msg.sender = node_id;
            msg.data = rand() % 100;
            msg.timestamp = sc_time_stamp();

            net->transmit(msg);

            wait(10, SC_MS);
        }
    }

    SC_HAS_PROCESS(Node);

    Node(sc_module_name name, int id, Network* network)
        : sc_module(name), node_id(id), net(network) {
        SC_THREAD(run);
    }
};

#endif