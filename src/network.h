#ifndef NETWORK_H
#define NETWORK_H

#include <systemc.h>
#include <queue>
#include <vector>
#include <iostream>
#include <string>
#include <map>

enum class MessageType {
    SENSOR_DATA, CONTROL_CMD, HEARTBEAT, GATEWAY_RELAY, UNKNOWN
};

enum class Priority {
    CRITICAL = 0, HIGH = 1, NORMAL = 2, LOW = 3
};

struct Message {
    int         sender_id    = 0;
    int         receiver_id  = -1;
    MessageType type         = MessageType::UNKNOWN;
    Priority    priority     = Priority::NORMAL;
    int         data         = 0;
    sc_time     timestamp;
    bool        is_malicious = false;
    std::string tag;
    int         sequence_num = 0;
};

inline std::string msgTypeStr(MessageType t) {
    switch(t) {
        case MessageType::SENSOR_DATA:   return "SENSOR";
        case MessageType::CONTROL_CMD:   return "CONTROL";
        case MessageType::HEARTBEAT:     return "HEARTBEAT";
        case MessageType::GATEWAY_RELAY: return "GATEWAY";
        default:                         return "UNKNOWN";
    }
}

inline std::string priorityStr(Priority p) {
    switch(p) {
        case Priority::CRITICAL: return "CRITICAL";
        case Priority::HIGH:     return "HIGH";
        case Priority::NORMAL:   return "NORMAL";
        case Priority::LOW:      return "LOW";
        default:                 return "?";
    }
}

inline void logEvent(const std::string& source,
                     const std::string& event,
                     const std::string& detail = "") {
    std::cout << "[" << source << "] " << event;
    if (!detail.empty()) std::cout << " | " << detail;
    std::cout << " | " << sc_time_stamp() << std::endl;
    std::cout.flush();
}

SC_MODULE(Network) {
public:
    static const int MAX_CAPACITY = 30;

    std::queue<Message>  bus;
    std::vector<Message> traffic_log;
    std::map<int, std::vector<sc_time>> sender_times;
    std::vector<int> whitelist = {1, 2, 3, 4};

    // Plain integers — updated by any thread freely (no sc_signal conflict)
    int bus_load_val   = 0;
    int congested_val  = 0;

    // Signals owned and written ONLY by the monitor() thread below
    sc_signal<int>  sig_bus_load;
    sc_signal<bool> sig_congested;

    // Background thread that samples bus size and updates signals safely
    // This is the ONLY process that writes sig_bus_load / sig_congested
    void monitor() {
        while (true) {
            wait(1, SC_MS);
            sig_bus_load.write(bus_load_val);
            sig_congested.write(bus_load_val > MAX_CAPACITY * 7 / 10);
        }
    }

    void transmit(Message msg) {
        if ((int)bus.size() >= MAX_CAPACITY) {
            logEvent("NETWORK","BUS_FULL",
                "dropped from=" + std::to_string(msg.sender_id));
            return;
        }
        bus.push(msg);
        traffic_log.push_back(msg);
        sender_times[msg.sender_id].push_back(sc_time_stamp());
        bus_load_val = (int)bus.size();   // plain int, safe from any thread
        congested_val = (bus_load_val > MAX_CAPACITY * 7 / 10) ? 1 : 0;

        std::string detail =
            "from="  + std::to_string(msg.sender_id) +
            " type=" + msgTypeStr(msg.type) +
            " prio=" + priorityStr(msg.priority) +
            " data=" + std::to_string(msg.data) +
            " seq="  + std::to_string(msg.sequence_num) +
            (msg.is_malicious ? " MALICIOUS=1" : " MALICIOUS=0");
        logEvent("NETWORK", "MSG_TX", detail);
    }

    // IDS reads messages via these — no signal writes
    bool    hasMessages() const { return !bus.empty(); }
    int     load()        const { return (int)bus.size(); }
    Message front()             { return bus.front(); }
    void    pop()               { bus.pop(); bus_load_val = (int)bus.size(); }

    int senderRate(int id, double window_ms) {
        auto it = sender_times.find(id);
        if (it == sender_times.end()) return 0;
        sc_time cutoff = sc_time_stamp() - sc_time(window_ms, SC_MS);
        int count = 0;
        for (auto& t : it->second)
            if (t >= cutoff) count++;
        return count;
    }

    SC_CTOR(Network)
        : sig_bus_load("sig_bus_load"),
          sig_congested("sig_congested") {
        sig_bus_load.write(0);
        sig_congested.write(false);
        SC_THREAD(monitor);
    }
};

#endif
