#ifndef NODE_H
#define NODE_H

#include <systemc.h>
#include "network.h"

// -------------------------------------------------------
// Node roles matching real embedded system topologies
// -------------------------------------------------------
enum class NodeRole {
    SENSOR,      // Node 1: periodic sensor readings
    CONTROL,     // Node 2: control commands to actuator
    ACTUATOR,    // Node 3: receives commands, sends acks
    GATEWAY      // Node 4: relays messages, monitors bus
};

inline std::string roleStr(NodeRole r) {
    switch(r) {
        case NodeRole::SENSOR:   return "SENSOR";
        case NodeRole::CONTROL:  return "CONTROL";
        case NodeRole::ACTUATOR: return "ACTUATOR";
        case NodeRole::GATEWAY:  return "GATEWAY";
        default:                 return "?";
    }
}

SC_MODULE(Node) {

    int      node_id;
    NodeRole role;
    Network* net;
    int      seq = 0;

    // Heartbeat interval (all nodes send periodic heartbeats)
    int heartbeat_ms = 50;

    void run() {
        while (true) {
            Message msg;
            msg.sender_id    = node_id;
            msg.timestamp    = sc_time_stamp();
            msg.is_malicious = false;
            msg.sequence_num = seq++;

            switch (role) {
                case NodeRole::SENSOR:
                    msg.type        = MessageType::SENSOR_DATA;
                    msg.priority    = Priority::HIGH;
                    msg.receiver_id = 2;  // to Control
                    msg.data        = 20 + rand() % 60;  // simulated sensor value
                    msg.tag         = "temp_reading";
                    wait(10, SC_MS);
                    break;

                case NodeRole::CONTROL:
                    msg.type        = MessageType::CONTROL_CMD;
                    msg.priority    = Priority::CRITICAL;
                    msg.receiver_id = 3;  // to Actuator
                    msg.data        = rand() % 2;  // 0=off, 1=on
                    msg.tag         = "actuator_cmd";
                    wait(20, SC_MS);
                    break;

                case NodeRole::ACTUATOR:
                    msg.type        = MessageType::SENSOR_DATA;
                    msg.priority    = Priority::NORMAL;
                    msg.receiver_id = 2;  // ack back to Control
                    msg.data        = rand() % 100;
                    msg.tag         = "actuator_ack";
                    wait(30, SC_MS);
                    break;

                case NodeRole::GATEWAY:
                    msg.type        = MessageType::GATEWAY_RELAY;
                    msg.priority    = Priority::LOW;
                    msg.receiver_id = -1;  // broadcast
                    msg.data        = net->load();  // reports bus load
                    msg.tag         = "bus_status";
                    wait(40, SC_MS);
                    break;
            }

            net->transmit(msg);
        }
    }

    void heartbeat() {
        while (true) {
            wait(heartbeat_ms, SC_MS);
            Message hb;
            hb.sender_id    = node_id;
            hb.receiver_id  = -1;
            hb.type         = MessageType::HEARTBEAT;
            hb.priority     = Priority::LOW;
            hb.data         = node_id;
            hb.timestamp    = sc_time_stamp();
            hb.is_malicious = false;
            hb.sequence_num = seq++;
            hb.tag          = "heartbeat";
            net->transmit(hb);
        }
    }

    SC_HAS_PROCESS(Node);

    Node(sc_module_name name, int id, NodeRole r, Network* network)
        : sc_module(name), node_id(id), role(r), net(network) {
        SC_THREAD(run);
        SC_THREAD(heartbeat);
        logEvent("NODE", "INIT",
            "id=" + std::to_string(id) + " role=" + roleStr(role));
    }
};

#endif
