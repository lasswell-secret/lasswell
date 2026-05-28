#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MAX_PROCESS 20
#define MAX_GANTT 10000

#define NICE_0_LOAD 1024.0
#define SCHED_LATENCY 12
#define MIN_GRANULARITY 1

typedef struct {
    int pid;
    int arrival;
    int burst;
    int remaining;
    int priority;
    int start_time;
    int finish_time;
    int waiting_time;
    int turnaround_time;
    int response_time;
    double vruntime;
    double weight;
    int completed;
} Process;

typedef struct {
    int pid;
    int start;
    int end;
} Gantt;

Process origin[MAX_PROCESS] = {
    {1, 0, 8, 8, 3, -1, 0, 0, 0, 0, 0, 1024, 0},
    {2, 1, 4, 4, 1, -1, 0, 0, 0, 0, 0, 2048, 0},
    {3, 2, 9, 9, 4, -1, 0, 0, 0, 0, 0, 820, 0},
    {4, 3, 5, 5, 2, -1, 0, 0, 0, 0, 0, 1536, 0},
    {5, 5, 2, 2, 5, -1, 0, 0, 0, 0, 0, 512, 0}
};

int n = 5;

void copy_process(Process dest[], Process src[]) {
    for (int i = 0; i < n; i++) {
        dest[i] = src[i];
        dest[i].remaining = src[i].burst;
        dest[i].start_time = -1;
        dest[i].finish_time = 0;
        dest[i].waiting_time = 0;
        dest[i].turnaround_time = 0;
        dest[i].response_time = 0;
        dest[i].vruntime = 0;
        dest[i].completed = 0;
    }
}

void add_gantt(Gantt g[], int *gcnt, int pid, int start, int end) {
    if (start == end) return;

    if (*gcnt > 0 && g[*gcnt - 1].pid == pid && g[*gcnt - 1].end == start) {
        g[*gcnt - 1].end = end;
    } else {
        g[*gcnt].pid = pid;
        g[*gcnt].start = start;
        g[*gcnt].end = end;
        (*gcnt)++;
    }
}

void calculate_result(Process p[]) {
    for (int i = 0; i < n; i++) {
        p[i].turnaround_time = p[i].finish_time - p[i].arrival;
        p[i].waiting_time = p[i].turnaround_time - p[i].burst;
        p[i].response_time = p[i].start_time - p[i].arrival;
    }
}

void print_result(const char *name, Process p[], Gantt g[], int gcnt) {
    double avg_wait = 0;
    double avg_turnaround = 0;
    double avg_response = 0;

    printf("\n================ %s ================\n", name);
    printf("PID\tAT\tBT\tPRI\tST\tFT\tWT\tTAT\tRT\n");

    for (int i = 0; i < n; i++) {
        avg_wait += p[i].waiting_time;
        avg_turnaround += p[i].turnaround_time;
        avg_response += p[i].response_time;

        printf("P%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
               p[i].pid,
               p[i].arrival,
               p[i].burst,
               p[i].priority,
               p[i].start_time,
               p[i].finish_time,
               p[i].waiting_time,
               p[i].turnaround_time,
               p[i].response_time);
    }

    printf("\nAverage Waiting Time    : %.2f\n", avg_wait / n);
    printf("Average Turnaround Time : %.2f\n", avg_turnaround / n);
    printf("Average Response Time   : %.2f\n", avg_response / n);

    printf("\nGantt Chart:\n");
    for (int i = 0; i < gcnt; i++) {
        if (g[i].pid == -1)
            printf("| Idle %d-%d ", g[i].start, g[i].end);
        else
            printf("| P%d %d-%d ", g[i].pid, g[i].start, g[i].end);
    }
    printf("|\n");
}

void fcfs() {
    Process p[MAX_PROCESS];
    Gantt g[MAX_GANTT];
    int gcnt = 0;

    copy_process(p, origin);

    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (p[j].arrival > p[j + 1].arrival) {
                Process temp = p[j];
                p[j] = p[j + 1];
                p[j + 1] = temp;
            }
        }
    }

    int time = 0;

    for (int i = 0; i < n; i++) {
        if (time < p[i].arrival) {
            add_gantt(g, &gcnt, -1, time, p[i].arrival);
            time = p[i].arrival;
        }

        p[i].start_time = time;
        time += p[i].burst;
        p[i].finish_time = time;

        add_gantt(g, &gcnt, p[i].pid, p[i].start_time, p[i].finish_time);
    }

    calculate_result(p);
    print_result("FCFS First Come First Serve", p, g, gcnt);
}

void sjf() {
    Process p[MAX_PROCESS];
    Gantt g[MAX_GANTT];
    int gcnt = 0;

    copy_process(p, origin);

    int completed = 0;
    int time = 0;

    while (completed < n) {
        int idx = -1;
        int min_burst = INT_MAX;

        for (int i = 0; i < n; i++) {
            if (!p[i].completed && p[i].arrival <= time) {
                if (p[i].burst < min_burst) {
                    min_burst = p[i].burst;
                    idx = i;
                }
            }
        }

        if (idx == -1) {
            add_gantt(g, &gcnt, -1, time, time + 1);
            time++;
            continue;
        }

        p[idx].start_time = time;
        time += p[idx].burst;
        p[idx].finish_time = time;
        p[idx].completed = 1;
        completed++;

        add_gantt(g, &gcnt, p[idx].pid, p[idx].start_time, p[idx].finish_time);
    }

    calculate_result(p);
    print_result("SJF Shortest Job First", p, g, gcnt);
}

void priority_schedule() {
    Process p[MAX_PROCESS];
    Gantt g[MAX_GANTT];
    int gcnt = 0;

    copy_process(p, origin);

    int completed = 0;
    int time = 0;

    while (completed < n) {
        int idx = -1;
        int best_priority = INT_MAX;

        for (int i = 0; i < n; i++) {
            if (!p[i].completed && p[i].arrival <= time) {
                if (p[i].priority < best_priority) {
                    best_priority = p[i].priority;
                    idx = i;
                }
            }
        }

        if (idx == -1) {
            add_gantt(g, &gcnt, -1, time, time + 1);
            time++;
            continue;
        }

        p[idx].start_time = time;
        time += p[idx].burst;
        p[idx].finish_time = time;
        p[idx].completed = 1;
        completed++;

        add_gantt(g, &gcnt, p[idx].pid, p[idx].start_time, p[idx].finish_time);
    }

    calculate_result(p);
    print_result("Priority Scheduling", p, g, gcnt);
}

void round_robin(int quantum) {
    Process p[MAX_PROCESS];
    Gantt g[MAX_GANTT];
    int gcnt = 0;

    copy_process(p, origin);

    int queue[MAX_GANTT];
    int front = 0;
    int rear = 0;

    int time = 0;
    int completed = 0;
    int visited[MAX_PROCESS] = {0};

    while (completed < n) {
        for (int i = 0; i < n; i++) {
            if (!visited[i] && p[i].arrival <= time) {
                queue[rear++] = i;
                visited[i] = 1;
            }
        }

        if (front == rear) {
            add_gantt(g, &gcnt, -1, time, time + 1);
            time++;
            continue;
        }

        int idx = queue[front++];

        if (p[idx].start_time == -1) {
            p[idx].start_time = time;
        }

        int run_time = quantum;
        if (p[idx].remaining < quantum) {
            run_time = p[idx].remaining;
        }

        add_gantt(g, &gcnt, p[idx].pid, time, time + run_time);

        time += run_time;
        p[idx].remaining -= run_time;

        for (int i = 0; i < n; i++) {
            if (!visited[i] && p[i].arrival <= time) {
                queue[rear++] = i;
                visited[i] = 1;
            }
        }

        if (p[idx].remaining > 0) {
            queue[rear++] = idx;
        } else {
            p[idx].finish_time = time;
            p[idx].completed = 1;
            completed++;
        }
    }

    calculate_result(p);
    print_result("Round Robin", p, g, gcnt);
}

void cfs() {
    Process p[MAX_PROCESS];
    Gantt g[MAX_GANTT];
    int gcnt = 0;

    copy_process(p, origin);

    int time = 0;
    int completed = 0;

    while (completed < n) {
        int idx = -1;
        double min_vruntime = 1e18;
        double total_weight = 0;

        for (int i = 0; i < n; i++) {
            if (!p[i].completed && p[i].arrival <= time) {
                total_weight += p[i].weight;
            }
        }

        for (int i = 0; i < n; i++) {
            if (!p[i].completed && p[i].arrival <= time) {
                if (p[i].vruntime < min_vruntime) {
                    min_vruntime = p[i].vruntime;
                    idx = i;
                }
            }
        }

        if (idx == -1) {
            add_gantt(g, &gcnt, -1, time, time + 1);
            time++;
            continue;
        }

        if (p[idx].start_time == -1) {
            p[idx].start_time = time;
        }

        int time_slice = (int)(SCHED_LATENCY * p[idx].weight / total_weight);

        if (time_slice < MIN_GRANULARITY) {
            time_slice = MIN_GRANULARITY;
        }

        if (time_slice > p[idx].remaining) {
            time_slice = p[idx].remaining;
        }

        add_gantt(g, &gcnt, p[idx].pid, time, time + time_slice);

        time += time_slice;
        p[idx].remaining -= time_slice;

        p[idx].vruntime += time_slice * NICE_0_LOAD / p[idx].weight;

        if (p[idx].remaining == 0) {
            p[idx].finish_time = time;
            p[idx].completed = 1;
            completed++;
        }
    }

    calculate_result(p);
    print_result("CFS Completely Fair Scheduler", p, g, gcnt);
}

void print_original_processes() {
    printf("Original Process Information:\n");
    printf("PID\tArrival\tBurst\tPriority\tWeight\n");

    for (int i = 0; i < n; i++) {
        printf("P%d\t%d\t%d\t%d\t\t%.0f\n",
               origin[i].pid,
               origin[i].arrival,
               origin[i].burst,
               origin[i].priority,
               origin[i].weight);
    }
}

int main() {
    print_original_processes();

    fcfs();
    sjf();
    priority_schedule();
    round_robin(3);
    cfs();

    printf("\n================ CFS Analysis ================\n");
    printf("CFS uses virtual runtime to measure how much CPU time each process has fairly received.\n");
    printf("The process with the smallest virtual runtime is selected to run first.\n");
    printf("A process with larger weight gets a longer CPU time slice, so its virtual runtime grows more slowly.\n");

    printf("\nAdvantages of CFS:\n");
    printf("1. It provides better fairness than simple priority or round-robin scheduling.\n");
    printf("2. It avoids fixed time quantum problems and dynamically allocates CPU time according to process weight.\n");
    printf("3. It is suitable for interactive and multi-task operating systems.\n");

    printf("\nDisadvantages of CFS:\n");
    printf("1. It is more complex than FCFS, SJF and RR.\n");
    printf("2. It needs to maintain virtual runtime and runnable process order.\n");
    printf("3. For very short jobs, SJF may still produce a lower average waiting time.\n");

    return 0;
}