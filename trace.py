#!/usr/bin/python
from __future__ import print_function
from bcc import BPF, USDT
from time import sleep

it, pid = open('pid', 'r').readline().split(',')
iteration = int(it)
prog = open('trace.c', 'r').read()
# hook #
prog = prog.replace('PID_FILTER_VOID', 'if(tgid != %s) return  ; ' % pid)
prog = prog.replace('PID_FILTER_ZERO', 'if(tgid != %s) return 0; ' % pid)
benchmark = USDT(pid=int(pid));

benchmark.enable_probe(probe="in_io_uring", fn_name="usdt_in_uring")
benchmark.enable_probe(probe="out_io_uring", fn_name="usdt_out_uring")
benchmark.enable_probe(probe="in_cq_advance", fn_name="usdt_in_advance")
benchmark.enable_probe(probe="out_cq_advance", fn_name="usdt_out_advance")

benchmark.enable_probe(probe="in_libaio", fn_name="usdt_in_native")
benchmark.enable_probe(probe="out_libaio", fn_name="usdt_out_native")

benchmark.enable_probe(probe="in_glibc_aio", fn_name="usdt_in_glibc")
benchmark.enable_probe(probe="out_glibc_aio", fn_name="usdt_out_glibc")

bpf = BPF(text=prog, usdt_contexts=[benchmark])
bpf.attach_uprobe(name="uring", sym="io_uring_submit", fn_name="trace_in_submit_uring")
bpf.attach_uretprobe(name="uring", sym="io_uring_submit", fn_name="trace_out_submit_uring")
bpf.attach_uprobe(name="uring", sym="io_uring_peek_batch_cqe", fn_name="trace_in_peek")
bpf.attach_uretprobe(name="uring", sym="io_uring_peek_batch_cqe", fn_name="trace_out_peek")

bpf.attach_uprobe(name="aio", sym="io_submit", fn_name="trace_in_submit_native")
bpf.attach_uretprobe(name="aio", sym="io_submit", fn_name="trace_out_submit_native")
bpf.attach_uprobe(name="aio", sym="io_getevents", fn_name="trace_in_poll_native")
bpf.attach_uretprobe(name="aio", sym="io_getevents", fn_name="trace_out_poll_native")


bpf.attach_uprobe(name="rt", sym="lio_listio", fn_name="trace_in_submit_glibc")
bpf.attach_uretprobe(name="rt", sym="lio_listio", fn_name="trace_out_submit_glibc")
bpf.attach_uprobe(name="rt", sym="aio_suspend", fn_name="trace_in_poll_glibc")
bpf.attach_uretprobe(name="rt", sym="aio_suspend", fn_name="trace_out_poll_glibc")

# listen #
try:
    sleep(10000)
except KeyboardInterrupt:
    print()

# data processsing (uring, native, posix) #

def avg_val(inp, outp):
    m, n = [list() for i in range(2)]
    for k,v in inp.items():
        m.append((k.value, v.value))
    for k,v in outp.items():
        n.append((k.value, v.value))
    avg = 0
    for (i,j) in zip(sorted(m),sorted(n)):
        avg += j[1]-i[1]
    return (avg / iteration)

avg_totals, avg_submits, avg_peeks  = [list() for i in range(3)]
est_maplist, call_maplist, peek_maplist, submit_maplist = [list() for i in range(4)]
est_maplist.extend([bpf["est_uring"], bpf["est_native"], bpf["est_glibc"]])
call_maplist.extend([bpf["sysc_uring"], bpf["sysc_native"], bpf["sysc_glibc"]])

peek_maplist.append((bpf["in_peek"], bpf["out_peek"]))
peek_maplist.append((bpf["in_poll_native"], bpf["out_poll_native"]))
peek_maplist.append((bpf["in_poll_glibc"], bpf["out_poll_glibc"]))

submit_maplist.append((bpf["in_submit_uring"], bpf["out_submit_uring"]))
submit_maplist.append((bpf["in_submit_native"], bpf["out_submit_native"]))
submit_maplist.append((bpf["in_submit_glibc"], bpf["out_submit_glibc"]))

for est_map in est_maplist:
    m = []
    avg_total = 0
    for k,v in est_map.items():
        m.append((k.value, v.value))
        if (v.value != 0):
            avg_total += v.value
    avg_totals.append(avg_total / iteration)

for (in_map, out_map) in submit_maplist:
    avg = avg_val(in_map, out_map)
    avg_submits.append(avg)

avg_advance = avg_val(bpf["in_advance"], bpf["out_advance"])

for (in_map, out_map) in peek_maplist:
    avg = avg_val(in_map, out_map)
    avg_peeks.append(avg)

for i in range(3):
    if (i == 0):
        print("io_uring")
        print("%20s %20s %20s %20s" %("total cost(us)", "submit cost", "poll cost", "clear cost"))
        print("%20d %20.4f %20.4f %20.4f" % (avg_totals[i]//1000, avg_submits[i]/avg_totals[i], avg_peeks[i]/avg_totals[i], avg_advance/avg_totals[i]))
        continue
    elif (i == 1):
        print("native aio")
    else:
        print("posix aio")
    print("%20s %20s %20s" %("total cost(us)", "submit cost", "poll cost"))
    print("%20d %20.4f %20.4f" % (avg_totals[i]//1000, avg_submits[i]/avg_totals[i], avg_peeks[i]/avg_totals[i]))
