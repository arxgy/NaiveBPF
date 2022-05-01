## Report

A performance analysis experiment based on eBPF and bcc.

Output the total and partial time cost of different async I/O libs (io_uring, native aio, posix aio). 

### Intro

#### Environment configuration 

- Support USDT

```
sudo apt-get install systemtap-sdt-dev
```

- Dependencies of bcc

```
sudo apt install bpfcc-tools linux-headers-$(uname -r) 
```

- Attach liburing manually

```
git clone git@github.com:axboe/liburing.git
cd liburing && make && make all
sudo cp -r ../liburing /usr/share
sudo cp src/liburing.so.2.2 /usr/lib/x86_64-linux-gnu/liburing.so
sudo cp src/liburing.so.2.2 /usr/lib/x86_64-linux-gnu/liburing.so.2
```

​	(or select any path you like, but don't forget to update `Makefile`)

#### Run

```
make && sudo ./Benchmark & sleep 1 && sudo python3 trace.py
```

When `Benchmark Test Finished` is printed on the console, push `Ctrl+C` to kill the snoop process. The output may be like this: 

```
...
Benchmark Test Finished
^C
io_uring
      total cost(us)          submit cost            poll cost           clear cost
                8588               0.9843               0.0072               0.0014
native aio
      total cost(us)          submit cost            poll cost
               10964               0.9868               0.0081
posix aio
      total cost(us)          submit cost            poll cost
              787187               0.6713               0.3177
              
[3]   Done                    make && sudo ./Benchmark
```

### Analysis

- **io_uring** (based on `liburing`)

  - Use SQ & CQ double rings to achieve async I/O. Rings are `mmap`ed from kernel, shared between user and kernel.

    By using 2 different rings, io_uring avoid locking operation.

  - Could register file & buffer to avoid frequent atomic reference towards file descriptor & buffer map/unmap when file is `O_DIRECT` type.

  - It's possible to achieve non-blocking submit operation by setting `IORING_SETUP_SQPOLL` flags.

    (You could set `URING_POLL_EN` as `true` in `config.h` to get verification.)

    The internel machanism is realized by awakening a kernel polling thread, which may slowdown total timecost but reduce submit cost down to nearly zero.

- **native aio**
  - Use AIO ring to achieve async I/O, which is alse a `mmap` area from kernel, reducing number of syscalls.
  - Only support I/O on `O_DIRECT` file.
  - Need `copy_from_user` when submit, which maybe a high-cost point. (copy `iocb` entry into kernel)

- **posix aio** (a.k.a. glibc aio)
  - Pseudo aync I/O. Use multi-thread to achieve illusion of async on userspace level, thus induces high cost on context switch. 

You could adjust `config.h` to customize parameters. 

### Experiment Representations

We iterate 16 times for each experiment.

- Set down `IORING_SETUP_SQPOLL`

```
BATCH  SIZE                 1024
BUFFER SIZE                 1024
FILE CORCURRENCY            2048
-URING [polling]			=FALSE
-URING [register file]]		=TRUE
-URING [register buffer]	=TRUE
-POSIX aio [polling]		=TRUE

io_uring
      total cost(us)          submit cost            poll cost           clear cost
                1909               0.9752               0.0118               0.0014
native aio
      total cost(us)          submit cost            poll cost
                2215               0.9770               0.0130
posix aio
      total cost(us)          submit cost            poll cost
               29338               0.6246               0.3053
```



```
BATCH  SIZE                 1024
BUFFER SIZE                 1024
FILE CORCURRENCY            5120
-URING [polling]			=FALSE
-URING [register file]]		=TRUE
-URING [register buffer]	=TRUE
-POSIX aio [polling]		=TRUE

io_uring
      total cost(us)          submit cost            poll cost           clear cost
                8588               0.9843               0.0072               0.0014
native aio
      total cost(us)          submit cost            poll cost
               10964               0.9868               0.0081
posix aio
      total cost(us)          submit cost            poll cost
              787187               0.6713               0.3177
```

- Set up `IORING_SETUP_SQPOLL`

```
BATCH  SIZE                 1024
BUFFER SIZE                 1024
FILE CORCURRENCY           10240
-URING [polling]			=TRUE
-URING [register file]]		=TRUE
-URING [register buffer]	=TRUE
-POSIX aio [polling]		=TRUE
io_uring
      total cost(us)          submit cost            poll cost           clear cost
               10391               0.0205               0.7598               0.0198
native aio
      total cost(us)          submit cost            poll cost
               13509               0.9873               0.0084
posix aio
      total cost(us)          submit cost            poll cost
              818702               0.6752               0.3121
```

Notice that the center of io_uring's timecost is moved from submit to poll, and due to `copy_from_user`, the timecost center of native aio is on submitting.

### Further Explore

#### SPDK

#### epoll

​	Althrough epoll is a IO-multiplexing interface, it might also perform well in total time cost.

#### Dedicate Timecost Analysis

​	We are interested in `copy_from_user` cost on native aio.