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
    sc_signal<bool> sig_safe_mode;
    sc_signal<int> sig_running_task;

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

                    sig_running_task.write(task.id);

                    wait(task.execution_time, SC_MS);

                    sig_running_task.write(0);
                    task.next_release += sc_time(task.period, SC_MS);
                }
            }

            wait(1, SC_MS);
        }
    }

    void enter_safe_mode() {
        safe_mode = true;
        sig_safe_mode.write(true);
        std::cout << "[SCHEDULER] SYSTEM ENTERED SAFE MODE" << std::endl;
    }

    SC_CTOR(Scheduler) : sig_safe_mode("sig_safe_mode"), sig_running_task("sig_running_task") {
        SC_THREAD(schedule);
    }
};

#endif