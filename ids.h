#ifndef IDS_H
#define IDS_H

#include <systemc.h>
#include "network.h"
#include "scheduler.h"

SC_MODULE(IDS) {

    Network* net;
    Scheduler* sched;

    void monitor() {

        while (true) {

            if (!net->bus.empty()) {

                Message msg = net->bus.front();
                net->bus.pop();

                // Spoofing detection
                if (msg.sender > 10) {
                    std::cout << "⚠ Spoofing Detected at "
                              << sc_time_stamp() << std::endl;
                    sched->enter_safe_mode();
                }

                // DoS detection
                if (net->bus.size() > 15) {
                    std::cout << "⚠ DoS Detected at "
                              << sc_time_stamp() << std::endl;
                    sched->enter_safe_mode();
                }
            }

            wait(1, SC_MS);
        }
    }

    SC_HAS_PROCESS(IDS);

    IDS(sc_module_name name, Network* network, Scheduler* scheduler)
        : sc_module(name), net(network), sched(scheduler) {
        SC_THREAD(monitor);
    }
};

#endif