#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <systemc.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include "network.h"

enum class SafeLevel {
    NORMAL    = 0,  // all tasks run
    GUARDED   = 1,  // low-priority tasks suspended
    EMERGENCY = 2   // only critical tasks run
};

struct Task {
    int         id;
    std::string name;
    int         period_ms;        // RMS period
    int         exec_time_ms;     // WCET (worst-case execution time)
    int         priority;         // assigned by RMS (shorter period = higher)
    bool        is_critical;      // survives EMERGENCY mode
    sc_time     next_release;
    int         deadline_misses = 0;
    int         completions     = 0;
};

SC_MODULE(Scheduler) {

    std::vector<Task> tasks;
    SafeLevel safe_level = SafeLevel::NORMAL;

    // VCD-traceable signals
    sc_signal<bool> sig_safe_mode;
    sc_signal<int>  sig_running_task;
    sc_signal<int>  sig_safe_level;

    void schedule() {
        while (true) {
            // RMS: sort by period (shorter = higher priority)
            std::sort(tasks.begin(), tasks.end(),
                [](const Task& a, const Task& b) {
                    return a.period_ms < b.period_ms;
                });

            for (auto& task : tasks) {
                // Skip low-priority tasks in GUARDED mode
                if (safe_level == SafeLevel::GUARDED && !task.is_critical &&
                    task.priority > 1) continue;

                // Skip non-critical tasks in EMERGENCY mode
                if (safe_level == SafeLevel::EMERGENCY && !task.is_critical)
                    continue;

                if (sc_time_stamp() >= task.next_release) {
                    // Deadline check
                    if (sc_time_stamp() > task.next_release + sc_time(task.period_ms, SC_MS)) {
                        task.deadline_misses++;
                        logEvent("SCHEDULER", "DEADLINE_MISS",
                            "task=" + task.name +
                            " misses=" + std::to_string(task.deadline_misses));
                    }

                    sig_running_task.write(task.id);
                    logEvent("SCHEDULER", "TASK_START",
                        "task=" + task.name +
                        " period=" + std::to_string(task.period_ms) +
                        "ms exec=" + std::to_string(task.exec_time_ms) + "ms" +
                        " safe_level=" + safeStr(safe_level));

                    wait(task.exec_time_ms, SC_MS);
                    task.completions++;
                    task.next_release += sc_time(task.period_ms, SC_MS);

                    logEvent("SCHEDULER", "TASK_DONE",
                        "task=" + task.name +
                        " completions=" + std::to_string(task.completions));

                    sig_running_task.write(0);
                }
            }
            wait(1, SC_MS);
        }
    }

    void escalate(SafeLevel level) {
        if (level <= safe_level) return;  // don't de-escalate here
        safe_level = level;
        sig_safe_mode.write(level != SafeLevel::NORMAL);
        sig_safe_level.write(static_cast<int>(level));
        logEvent("SCHEDULER", "SAFE_MODE_ESCALATE",
            "level=" + safeStr(level));
    }

    void recover() {
        if (safe_level == SafeLevel::NORMAL) return;
        safe_level = SafeLevel::NORMAL;
        sig_safe_mode.write(false);
        sig_safe_level.write(0);
        logEvent("SCHEDULER", "RECOVERED", "level=NORMAL");
    }

    std::string safeStr(SafeLevel l) {
        switch(l) {
            case SafeLevel::NORMAL:    return "NORMAL";
            case SafeLevel::GUARDED:   return "GUARDED";
            case SafeLevel::EMERGENCY: return "EMERGENCY";
            default:                   return "?";
        }
    }

    SC_CTOR(Scheduler)
        : sig_safe_mode("sig_safe_mode"),
          sig_running_task("sig_running_task"),
          sig_safe_level("sig_safe_level") {
        sig_safe_mode.write(false);
        sig_running_task.write(0);
        sig_safe_level.write(0);
        SC_THREAD(schedule);
    }
};

#endif
