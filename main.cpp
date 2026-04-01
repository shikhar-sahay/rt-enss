#include <systemc.h>
#include "scheduler.h"
#include "network.h"
#include "node.h"
#include "attack.h"
#include "ids.h"

int sc_main(int argc, char* argv[]) {

    std::cout << "=== RT-ENSS v2.0 ===" << std::endl;
    std::cout.flush();

    Network   network("Network");
    Scheduler scheduler("Scheduler");

    scheduler.tasks.push_back({1, "SensorPoll",    20, 3,  1, true,  SC_ZERO_TIME});
    scheduler.tasks.push_back({2, "ControlLoop",   30, 5,  2, true,  SC_ZERO_TIME});
    scheduler.tasks.push_back({3, "ActuatorCheck", 50, 8,  3, false, SC_ZERO_TIME});
    scheduler.tasks.push_back({4, "GatewayDiag",   80, 10, 4, false, SC_ZERO_TIME});

    Node node1("Node1", 1, NodeRole::SENSOR,   &network);
    Node node2("Node2", 2, NodeRole::CONTROL,  &network);
    Node node3("Node3", 3, NodeRole::ACTUATOR, &network);
    Node node4("Node4", 4, NodeRole::GATEWAY,  &network);

    AttackInjector attacker("Attacker", &network);
    IDS            ids("IDS", &network, &scheduler);

    sc_trace_file* tf = sc_create_vcd_trace_file("rt_enss_trace");
    sc_trace(tf, scheduler.sig_safe_mode,    "safe_mode");
    sc_trace(tf, scheduler.sig_running_task, "running_task");
    sc_trace(tf, scheduler.sig_safe_level,   "safe_level");
    sc_trace(tf, network.sig_bus_load,       "bus_load");
    sc_trace(tf, network.sig_congested,      "bus_congested");
    sc_trace(tf, ids.sig_threat_level,       "threat_level");
    sc_trace(tf, ids.sig_anomaly_score,      "anomaly_score");

    // Run in 1ms slices, printing a TICK every slice so Python
    // can pace the visualization regardless of how fast SystemC runs.
    for (int t = 0; t < 300; t += 1) {
        sc_start(1, SC_MS);
        std::cout << "[TICK] t=" << t+1 << std::endl;
        std::cout.flush();
    }

    sc_close_vcd_trace_file(tf);
    std::cout << "=== SIMULATION COMPLETE ===" << std::endl;
    std::cout.flush();
    return 0;
}
