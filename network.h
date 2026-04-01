#ifndef NETWORK_H
#define NETWORK_H

#include <systemc.h>
#include <queue>
#include <vector>
#include <iostream>
#include <string>
#include <map>

// Message types representing real embedded network traffic
enum class MessageType {
    SENSOR_DATA,
    CONTROL_CMD,
    HEARTBEAT,
    GATEWAY_RELAY,
    UNKNOWN
};

// Priority levels (lower = higher priority, like CAN bus)
enum class Priority {
    CRITICAL = 0,
    HIGH = 1,
    NORMAL = 2,
    LOW = 3
};

struct Message {
    int         sender_id;
    int         receiver_id;  // -1 = broadcast
    MessageType type;
    Priority    priority;
    int         data;
    sc_time     timestamp;
    bool        is_malicious = false;
    std::string tag;          // human-readable label

    // For replay attack detection
    int         sequence_num;
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

// -------------------------------------------------------
// Structured event logger — emits parseable lines for GUI
// -------------------------------------------------------
inline void logEvent(const std::string& source,
                     const std::string& event,
                     const std::string& detail = "") {
    // Format: [SOURCE] EVENT | detail | time
    std::cout << "[" << source << "] "
              << event;
    if (!detail.empty())
        std::cout << " | " << detail;
    std::cout << " | " << sc_time_stamp()
              << std::endl;
    std::cout.flush();
}

// -------------------------------------------------------
// Network Bus — shared CAN/UART-style message bus
// -------------------------------------------------------
SC_MODULE(Network) {

    static const int MAX_CAPACITY = 30;

    // Priority queue: lower priority value = higher priority
    struct Cmp {
        bool operator()(const Message& a, const Message& b) {
            return static_cast<int>(a.priority) >
                   static_cast<int>(b.priority);
        }
    };

    std::priority_queue<Message, std::vector<Message>, Cmp> bus;
    std::vector<Message> traffic_log;  // full history for IDS

    // Per-sender message rate tracking (sliding window)
    std::map<int, std::vector<sc_time>> sender_times;

    // Whitelist of legitimate sender IDs
    std::vector<int> whitelist = {1, 2, 3, 4};

    sc_signal<int> sig_bus_load;
    sc_signal<bool> sig_congested;

    void transmit(Message msg) {
        if ((int)bus.size() >= MAX_CAPACITY) {
            logEvent("NETWORK", "BUS_FULL",
                     "dropped msg from node " + std::to_string(msg.sender_id));
            return;
        }

        bus.push(msg);
        traffic_log.push_back(msg);
        sender_times[msg.sender_id].push_back(sc_time_stamp());

        bool congested = (int)bus.size() > MAX_CAPACITY * 0.7;
        sig_bus_load.write((int)bus.size());
        sig_congested.write(congested);

        std::string detail =
            "from=" + std::to_string(msg.sender_id) +
            " type=" + msgTypeStr(msg.type) +
            " prio=" + priorityStr(msg.priority) +
            " data=" + std::to_string(msg.data) +
            " seq="  + std::to_string(msg.sequence_num) +
            (msg.is_malicious ? " MALICIOUS=1" : " MALICIOUS=0");

        logEvent("NETWORK", "MSG_TX", detail);
    }

    Message receive() {
        Message m = bus.top();
        bus.pop();
        sig_bus_load.write((int)bus.size());
        return m;
    }

    bool hasMessages() { return !bus.empty(); }
    int  load()        { return (int)bus.size(); }

    // Returns message rate for a sender in last window_ms milliseconds
    int senderRate(int id, double window_ms) {
        if (sender_times.find(id) == sender_times.end()) return 0;
        auto& times = sender_times[id];
        sc_time cutoff = sc_time_stamp() - sc_time(window_ms, SC_MS);
        int count = 0;
        for (auto& t : times)
            if (t >= cutoff) count++;
        return count;
    }

    SC_CTOR(Network)
        : sig_bus_load("sig_bus_load"),
          sig_congested("sig_congested") {
        sig_bus_load.write(0);
        sig_congested.write(false);
    }
};

#endif
