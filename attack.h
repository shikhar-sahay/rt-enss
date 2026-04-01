#ifndef ATTACK_H
#define ATTACK_H

#include <systemc.h>
#include "network.h"
#include <vector>

SC_MODULE(AttackInjector) {

    Network* net;

    // Captured legitimate messages for replay
    std::vector<Message> replay_cache;

    void inject() {

        // -----------------------------------------------
        // Phase 1 @ 60ms: SPOOFING ATTACK
        // Injects a message with a fake sender ID
        // -----------------------------------------------
        wait(60, SC_MS);
        logEvent("ATTACK", "SPOOFING_START",
            "sender=99 target=broadcast");

        Message fake;
        fake.sender_id    = 99;   // not in whitelist
        fake.receiver_id  = 2;
        fake.type         = MessageType::CONTROL_CMD;
        fake.priority     = Priority::CRITICAL;
        fake.data         = 1;
        fake.timestamp    = sc_time_stamp();
        fake.is_malicious = true;
        fake.sequence_num = 9999;
        fake.tag          = "spoofed_control";
        net->transmit(fake);

        // -----------------------------------------------
        // Phase 2 @ 100ms: REPLAY ATTACK
        // Re-broadcasts captured message with old timestamp
        // -----------------------------------------------
        wait(40, SC_MS);  // t=100ms

        // Grab a message from traffic log to replay
        if (!net->traffic_log.empty()) {
            Message replayed = net->traffic_log.front();
            replayed.is_malicious = true;
            replayed.tag          = "replayed_msg";
            // timestamp stays OLD — IDS detects staleness
            logEvent("ATTACK", "REPLAY_START",
                "replaying seq=" + std::to_string(replayed.sequence_num) +
                " original_sender=" + std::to_string(replayed.sender_id));
            net->transmit(replayed);
        }

        // -----------------------------------------------
        // Phase 3 @ 140ms: DoS ATTACK
        // Floods bus with junk to starve legitimate traffic
        // -----------------------------------------------
        wait(40, SC_MS);  // t=140ms
        logEvent("ATTACK", "DOS_START",
            "flooding 25 messages");

        for (int i = 0; i < 25; i++) {
            Message flood;
            flood.sender_id    = 99;
            flood.receiver_id  = -1;
            flood.type         = MessageType::UNKNOWN;
            flood.priority     = Priority::LOW;
            flood.data         = rand();
            flood.timestamp    = sc_time_stamp();
            flood.is_malicious = true;
            flood.sequence_num = 8000 + i;
            flood.tag          = "dos_flood";
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