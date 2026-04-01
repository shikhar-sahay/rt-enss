#ifndef IDS_H
#define IDS_H

#include <systemc.h>
#include <map>
#include <vector>
#include <string>
#include <cmath>
#include "network.h"
#include "scheduler.h"

// -------------------------------------------------------
// Threat confidence levels
// -------------------------------------------------------
enum class ThreatLevel {
    CLEAN    = 0,
    SUSPECT  = 1,   // anomalous but not confirmed
    ATTACK   = 2    // confirmed — escalate scheduler
};

struct IDSRecord {
    int    sender_id;
    int    msg_count         = 0;
    int    anomaly_score     = 0;
    double avg_interval_ms   = 0.0;
    sc_time last_seen        = SC_ZERO_TIME;
    int    last_seq          = -1;
};

SC_MODULE(IDS) {

    Network*   net;
    Scheduler* sched;

    // Per-sender behavioral profiles
    std::map<int, IDSRecord> profiles;

    // Detection thresholds
    static const int WHITELIST_VIOLATION_SCORE = 60;
    static const int RATE_ANOMALY_SCORE        = 30;
    static const int REPLAY_SCORE              = 40;
    static const int DOS_SCORE                 = 50;
    static const int ALERT_THRESHOLD           = 60;   // GUARDED
    static const int EMERGENCY_THRESHOLD       = 100;  // EMERGENCY

    // Rate limit: msgs per sender per 20ms window
    static const int MAX_MSGS_PER_WINDOW = 5;

    // Max tolerable age for a message timestamp (ms)
    static const int MAX_MSG_AGE_MS = 30;

    sc_signal<int>  sig_threat_level;
    sc_signal<int>  sig_anomaly_score;

    void monitor() {
        while (true) {
            wait(1, SC_MS);

            if (!net->hasMessages()) continue;

            // Process up to 5 messages per cycle (bounded latency)
            int processed = 0;
            while (net->hasMessages() && processed < 5) {
                Message msg = net->front(); net->pop();
                processed++;

                int score = 0;
                std::string reasons = "";

                // ---- Check 1: Sender whitelist ----
                bool whitelisted = false;
                for (int id : net->whitelist)
                    if (id == msg.sender_id) { whitelisted = true; break; }

                if (!whitelisted) {
                    score += WHITELIST_VIOLATION_SCORE;
                    reasons += "UNKNOWN_SENDER ";
                }

                // ---- Check 2: Message rate anomaly ----
                int rate = net->senderRate(msg.sender_id, 20.0);
                if (rate > MAX_MSGS_PER_WINDOW) {
                    int excess = rate - MAX_MSGS_PER_WINDOW;
                    score += std::min(DOS_SCORE, RATE_ANOMALY_SCORE + excess * 5);
                    reasons += "RATE_ANOMALY(rate=" + std::to_string(rate) + ") ";
                }

                // ---- Check 3: Replay detection (stale timestamp) ----
                double age_ms = (sc_time_stamp() - msg.timestamp).to_seconds() * 1000.0;
                if (age_ms > MAX_MSG_AGE_MS && msg.type != MessageType::HEARTBEAT) {
                    score += REPLAY_SCORE;
                    reasons += "STALE_MSG(age=" + std::to_string((int)age_ms) + "ms) ";
                }

                // ---- Check 4: Sequence number regression ----
                auto& rec = profiles[msg.sender_id];
                if (rec.last_seq >= 0 && msg.sequence_num < rec.last_seq &&
                    msg.sequence_num != 0) {
                    score += REPLAY_SCORE;
                    reasons += "SEQ_REGRESSION ";
                }

                // ---- Check 5: Bus-level DoS ----
                if (net->load() > (int)(Network::MAX_CAPACITY * 0.75)) {
                    score += DOS_SCORE;
                    reasons += "BUS_CONGESTION ";
                }

                // Update profile
                rec.sender_id = msg.sender_id;
                rec.msg_count++;
                rec.anomaly_score = score;
                rec.last_seq      = msg.sequence_num;
                rec.last_seen     = sc_time_stamp();

                sig_anomaly_score.write(score);

                // ---- Classify and respond ----
                ThreatLevel threat = ThreatLevel::CLEAN;
                if (score >= EMERGENCY_THRESHOLD) {
                    threat = ThreatLevel::ATTACK;
                } else if (score >= ALERT_THRESHOLD) {
                    threat = ThreatLevel::SUSPECT;
                }

                sig_threat_level.write(static_cast<int>(threat));

                if (threat == ThreatLevel::ATTACK) {
                    logEvent("IDS", "ATTACK_CONFIRMED",
                        "sender=" + std::to_string(msg.sender_id) +
                        " score=" + std::to_string(score) +
                        " reasons=" + reasons);
                    sched->escalate(SafeLevel::EMERGENCY);
                } else if (threat == ThreatLevel::SUSPECT) {
                    logEvent("IDS", "SUSPECT_DETECTED",
                        "sender=" + std::to_string(msg.sender_id) +
                        " score=" + std::to_string(score) +
                        " reasons=" + reasons);
                    sched->escalate(SafeLevel::GUARDED);
                }
            }

            // ---- Recovery: check if threat has passed ----
            // If bus load is back to normal and no anomalies for 10ms, recover
            if (sched->safe_level != SafeLevel::NORMAL &&
                net->load() < (int)(Network::MAX_CAPACITY * 0.3)) {
                sched->recover();
            }
        }
    }

    SC_HAS_PROCESS(IDS);

    IDS(sc_module_name name, Network* network, Scheduler* scheduler)
        : sc_module(name), net(network), sched(scheduler),
          sig_threat_level("sig_threat_level"),
          sig_anomaly_score("sig_anomaly_score") {
        sig_threat_level.write(0);
        sig_anomaly_score.write(0);
        SC_THREAD(monitor);
        logEvent("IDS", "INIT",
            "thresholds: alert=" + std::to_string(ALERT_THRESHOLD) +
            " emergency=" + std::to_string(EMERGENCY_THRESHOLD));
    }
};

#endif
