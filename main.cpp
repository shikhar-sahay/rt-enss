#include <systemc.h>
#include "scheduler.h"
#include "network.h"
#include "node.h"
#include "attack.h"
#include "ids.h"

int sc_main(int argc, char* argv[]) {

    Network network("Network");
    Scheduler scheduler("Scheduler");

    // Add Tasks
    scheduler.tasks.push_back({1, 20, 5, SC_ZERO_TIME});
    scheduler.tasks.push_back({2, 50, 10, SC_ZERO_TIME});

    Node node1("Node1", 1, &network);
    Node node2("Node2", 2, &network);

    AttackInjector attacker("Attacker", &network);
    IDS ids("IDS", &network, &scheduler);

    sc_start(200, SC_MS);

    return 0;
}