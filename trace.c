#include <linux/sched.h>
/* TOTAL COST */
BPF_HASH(est_uring);
BPF_HASH(est_native);
BPF_HASH(est_glibc);

/* SUBMISSION COST */
BPF_HASH(in_submit_uring);
BPF_HASH(out_submit_uring);
BPF_HASH(in_submit_native);
BPF_HASH(out_submit_native);
BPF_HASH(in_submit_glibc);
BPF_HASH(out_submit_glibc);

/* POLL LOST*/
BPF_HASH(in_peek);
BPF_HASH(out_peek);
BPF_HASH(in_poll_native);
BPF_HASH(out_poll_native);
BPF_HASH(in_poll_glibc);
BPF_HASH(out_poll_glibc);
/* ADVANCE LOST */
BPF_HASH(in_advance);
BPF_HASH(out_advance);

/* SYSCALL COUNTER */
BPF_HASH(sysc_uring);
BPF_HASH(sysc_native);
BPF_HASH(sysc_glibc);

void usdt_in_uring (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* update visit-times */
    key = 0;
    cnt = est_uring.lookup(&key);
    if (cnt == 0) {val = 1;}
    else {val = *cnt+1; }
    est_uring.update(&key, &val);

    /* update kernel time */
    est_uring.update(&val, &time); 
}

void usdt_out_uring (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* lookup visit-times */
    key = 0;
    cnt = est_uring.lookup(&key);
    if (cnt == 0) {key = 1;}    // just for passing verifier
    else {key = *cnt; } 

    /* update delta time */    
    u64 *nsp = est_uring.lookup(&key);
    if (nsp != 0) {time -= *nsp;}
    else {time = 0;} 
    est_uring.update(&key, &time); 
}

void usdt_in_advance (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    //PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_advance.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_advance.update(&key, &time);
}

void usdt_out_advance (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    //PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_advance.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_advance.update(&key, &time);
}

void usdt_in_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* update visit-times */
    key = 0;
    cnt = est_native.lookup(&key);
    if (cnt == 0) {val = 1;}
    else {val = *cnt+1; }
    est_native.update(&key, &val);

    /* update kernel time */
    est_native.update(&val, &time); 
}


void usdt_out_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* lookup visit-times */
    key = 0;
    cnt = est_native.lookup(&key);
    if (cnt == 0) {key = 1;}    
    else {key = *cnt; } 

    /* update delta time */    
    u64 *nsp = est_native.lookup(&key);
    if (nsp != 0) {time -= *nsp;}
    else {time = 0;} 
    est_native.update(&key, &time); 
}

void usdt_in_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* update visit-times */
    key = 0;
    cnt = est_glibc.lookup(&key);
    if (cnt == 0) {val = 1;}
    else {val = *cnt+1; }
    est_glibc.update(&key, &val);

    /* update kernel time */
    est_glibc.update(&val, &time); 
}

void usdt_out_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u64 key, val;
    u64 *cnt; 
    
    /* lookup visit-times */
    key = 0;
    cnt = est_glibc.lookup(&key);
    if (cnt == 0) {key = 1;}    
    else {key = *cnt; }     

    /* update delta time */    
    u64 *nsp = est_glibc.lookup(&key);
    if (nsp != 0) {time -= *nsp;}
    else {time = 0;} 
    est_glibc.update(&key, &time); 
}

/* one test may multi-submit    */
void trace_in_submit_uring (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_submit_uring.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_submit_uring.update(&key, &time);
}

void trace_out_submit_uring (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_submit_uring.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_submit_uring.update(&key, &time);
}

void trace_in_peek (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_peek.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_peek.update(&key, &time);
}

void trace_out_peek (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_uring.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_peek.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_peek.update(&key, &time);
}

void trace_in_submit_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_native.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_submit_native.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_submit_native.update(&key, &time);
}

void trace_out_submit_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_native.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_submit_native.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_submit_native.update(&key, &time);
}

void trace_in_poll_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_native.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_poll_native.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_poll_native.update(&key, &time);
}

void trace_out_poll_native (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_native.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_poll_native.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_poll_native.update(&key, &time);
}

void trace_in_submit_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_glibc.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_submit_glibc.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_submit_glibc.update(&key, &time);
}

void trace_out_submit_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_glibc.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_submit_glibc.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_submit_glibc.update(&key, &time);
}

void trace_in_poll_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_glibc.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = in_poll_glibc.lookup(&key);
    if (tsp != 0) time += *tsp;
    in_poll_glibc.update(&key, &time);
}

void trace_out_poll_glibc (struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_VOID
    u64 key = 0; u64 *visit, *tsp;

    /* get visit-times */
    visit = est_glibc.lookup(&key);
    if (visit == 0) return;

    /* add to total cost */
    key = *visit;
    tsp = out_poll_glibc.lookup(&key);
    if (tsp != 0) time += *tsp;
    out_poll_glibc.update(&key, &time);
}


TRACEPOINT_PROBE(syscalls, sys_enter_io_uring_setup) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_ZERO
    u64 *tmp;
    u64 key = 0, val = 1;
    tmp = sysc_uring.lookup(&key);
    if (tmp != 0) { val = *tmp+1; }
    sysc_uring.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_io_uring_enter) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_ZERO
    u64 *tmp;
    u64 key = 1, val = 1;
    tmp = sysc_uring.lookup(&key);
    if (tmp != 0) { val = *tmp+1; }
    sysc_uring.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_io_uring_register) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    PID_FILTER_ZERO
    u64 *tmp;
    u64 key = 2, val = 1;
    tmp = sysc_uring.lookup(&key);
    if (tmp != 0) { val = *tmp+1; }
    sysc_uring.update(&key, &val);
    return 0;
}
