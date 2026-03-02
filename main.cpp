#include <systemc.h>
#include "scheduler.h"
#include "network.h"
#include "node.h"
#include "attack.h"
#include "ids.h"

int sc_main(int argc, char* argv[]) {

    Network network("Network");
    Scheduler scheduler("Scheduler");

    scheduler.tasks.push_back({1, 20, 5, SC_ZERO_TIME});
    scheduler.tasks.push_back({2, 50, 10, SC_ZERO_TIME});

    Node node1("Node1", 1, &network);
    Node node2("Node2", 2, &network);

    AttackInjector attacker("Attacker", &network);
    IDS ids("IDS", &network, &scheduler);

    // VCD Trace
    sc_trace_file* tf = sc_create_vcd_trace_file("rt_enss_trace");
    sc_trace(tf, scheduler.sig_safe_mode, "safe_mode");
    sc_trace(tf, scheduler.sig_running_task, "running_task");

    sc_start(200, SC_MS);

    sc_close_vcd_trace_file(tf);

    return 0;
}