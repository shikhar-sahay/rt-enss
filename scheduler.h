#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <systemc.h>
#include <vector>
#include <algorithm>
#include <iostream>

struct Task {
    int id;
    int period;
    int execution_time;
    sc_time next_release;
};

SC_MODULE(Scheduler) {

    std::vector<Task> tasks;
    bool safe_mode = false;

    void schedule() {
        while (true) {

            std::sort(tasks.begin(), tasks.end(),
                [](Task &a, Task &b) {
                    return a.period < b.period;  // RMS
                });

            for (auto &task : tasks) {
                if (sc_time_stamp() >= task.next_release) {

                    std::cout << "[SCHEDULER] Running Task "
                              << task.id << " at "
                              << sc_time_stamp() << std::endl;

                    wait(task.execution_time, SC_MS);

                    task.next_release += sc_time(task.period, SC_MS);
                }
            }

            wait(1, SC_MS);
        }
    }

    void enter_safe_mode() {
        safe_mode = true;
        std::cout << "⚠ SYSTEM ENTERED SAFE MODE\n";
    }

    SC_CTOR(Scheduler) {
        SC_THREAD(schedule);
    }
};

#endif