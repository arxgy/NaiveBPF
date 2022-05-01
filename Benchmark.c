#include "config.h"

void init();
void preread();
void TEST_io_uring(boolean polling,boolean reg_file, boolean reg_buffer);
void TEST_libaio();
void TEST_glibc_aio(boolean polling);
void reclaim();
void callback(__sigval_t sigvalue);
static inline void exception(const char *msg) {
    perror(msg);
    exit(0);
}
int *pipes;
pthread_mutex_t mutex;
unsigned posix_aio_cnt = 0;
int main(int argc, char **argv) {
    init();
    for (int i = 0 ; i < ITERATION ; i++) {
        printf("[current iteration] %d; [target iteration] %d\n", i+1, ITERATION);
        preread();
        TEST_io_uring(false, true, false);
        TEST_libaio();
        TEST_glibc_aio(true);
    }
    reclaim();
    return 0;
}
void preread() {
    void *rbuf, *wbuf;
    rbuf = malloc(BUFFER_SIZE);
    wbuf = malloc(BUFFER_SIZE);
    memset(rbuf, 'R', BUFFER_SIZE);
    memset(wbuf, 'W', BUFFER_SIZE);
    for (int i = 0 ; i < CORCURRENCY; i++) {
        write(pipes[2*i+1], wbuf, BUFFER_SIZE);
        read(pipes[2*i], rbuf, BUFFER_SIZE);
    }
    free(rbuf);
    free(wbuf);
}
void init() {
    int ret;
    FILE *f = fopen("pid","w");
    fprintf(f, "%d, %d", ITERATION, getpid());
    fclose(f);
    ret = pthread_mutex_init(&mutex, NULL);
    if (ret) exception(strerror(ret));
    /* assign pipes, maybe failed because of 'ulimit -n'. */
    pipes = malloc(sizeof(int)*2*CORCURRENCY);
    if (!pipes) exception("malloc failed");
    for (int i = 0; i < CORCURRENCY; i++) 
        if (pipe2(pipes+2*i, O_NONBLOCK | O_DIRECT)) exception("pipe failed");
    sleep(5);
}
void reclaim() {
    for (int i = 0; i < CORCURRENCY; i++) {
        close(pipes[2*i]);
        close(pipes[2*i+1]);
    }
    free(pipes);
    pthread_mutex_destroy(&mutex);
}

void TEST_io_uring(boolean polling, boolean reg_file, boolean reg_buffer) {
    /* register need root */
    int ret, file, submit, remain, complete;
    boolean poll_flag;
    struct iovec    buffer;
    struct io_uring ring; 
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
    struct io_uring_cqe **cqes;
    
    poll_flag = polling ? IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF : 0;
    ret = io_uring_queue_init(2*CORCURRENCY, &ring, poll_flag);
    if (ret)  exception(strerror(-ret));

    buffer.iov_base = malloc(BUFFER_SIZE*2*CORCURRENCY);
    buffer.iov_len = BUFFER_SIZE*2*CORCURRENCY;
    memset(buffer.iov_base, 'T', buffer.iov_len);

    if (reg_file && io_uring_register_files(&ring, pipes, 2*CORCURRENCY)) 
        exception("register file failed");
    if (reg_buffer && io_uring_register_buffers(&ring, &buffer, 1)) 
        exception("register buffer failed");
    
    /* collecting cqe by peek_batch */
    cqes = malloc(sizeof(struct io_uring_cqe *)*BATCH_SIZE);
    for (int j = 0; j < 2*CORCURRENCY ; j++) {
        sqe = io_uring_get_sqe(&ring);
        file = reg_file ? j : pipes[j];

        if (reg_buffer) {
            if (j%2) io_uring_prep_write_fixed(sqe, file, buffer.iov_base + j*BUFFER_SIZE, BUFFER_SIZE, 0, 0);
            else io_uring_prep_read_fixed(sqe, file, buffer.iov_base + j*BUFFER_SIZE, BUFFER_SIZE, 0, 0);
        } else {
            if (j%2) io_uring_prep_write(sqe, file, buffer.iov_base + j*BUFFER_SIZE, BUFFER_SIZE, 0);
            else io_uring_prep_read(sqe, file, buffer.iov_base + j*BUFFER_SIZE, BUFFER_SIZE, 0);
        }
        if (reg_file) sqe->flags |= IOSQE_FIXED_FILE;
    }

    DTRACE_PROBE(ra, in_io_uring);
    /* submit */
    submit = 0;
    while (true) {
        submit += io_uring_submit(&ring);
        if (submit == 2*CORCURRENCY) break;
    }
    
    /* polling operation */
    remain = 2*CORCURRENCY;
    while (remain > 0) {
        complete = io_uring_peek_batch_cqe(&ring, cqes, BATCH_SIZE);
        if (!complete) continue;
        for (int k = 0 ; k< complete ; k++) {
            cqe = cqes[k];
            if (cqe->res < 0) exception(strerror(-cqe->res));
            if (cqe->res != BUFFER_SIZE) exception("buffer size not matched");
        }
        DTRACE_PROBE(ra, in_cq_advance);
        io_uring_cq_advance(&ring, complete);
        DTRACE_PROBE(ra, out_cq_advance);
        remain -= complete;
    }
    DTRACE_PROBE(ra, out_io_uring);
    free(buffer.iov_base);
    free(cqes);
    io_uring_queue_exit(&ring);
    
}

void TEST_libaio() {
    int ret, remain;
    void *buffer;
    struct io_event *events;
    struct iocb * iocb;
    struct iocb **iocbpp = malloc(2*sizeof(struct iocb *)*CORCURRENCY);
    io_context_t ctx;
    
    memset(&ctx, 0, sizeof(io_context_t));
    ret = io_setup(2*CORCURRENCY, &ctx);
    if (ret) exception(strerror(-ret));
    
    buffer = malloc(BUFFER_SIZE*2*CORCURRENCY);
    memset(buffer, 'T', BUFFER_SIZE*2*CORCURRENCY);

    for (int j = 0 ; j < CORCURRENCY; j++) {
        iocbpp[2*j] = malloc(sizeof(struct iocb));
        iocbpp[2*j+1] = malloc(sizeof(struct iocb));
        /* cannot exchange order..? */
        io_prep_pwrite(iocbpp[2*j], pipes[2*j+1], buffer + (2*j+1)*BUFFER_SIZE, BUFFER_SIZE, 0);
        io_prep_pread(iocbpp[2*j+1], pipes[2*j], buffer + (2*j)*BUFFER_SIZE, BUFFER_SIZE, 0);
    }

    /* batch submit */
    DTRACE_PROBE(ra, in_libaio);    
    remain = 2*CORCURRENCY;
    while (remain > 0) {
        ret = io_submit(ctx, 2*CORCURRENCY, iocbpp);
        remain -= ret;
        if (ret < 0) exception(strerror(-ret));
    }
    /* polling operation */
    remain = 2*CORCURRENCY;
    events = malloc(sizeof(struct io_event)*BATCH_SIZE);
    while (remain > 0) {
        ret = io_getevents(ctx, 0, BATCH_SIZE, events, NULL);
        if (ret < 0) exception(strerror(-ret));
        for (int i = 0 ; i < ret ; i++) {
            if (events[i].res != BUFFER_SIZE) 
                exception(strerror(-events[i].res));
        }
        remain -= ret;
    }
    DTRACE_PROBE(ra, out_libaio);

    free(buffer);
    free(iocbpp);
    free(events);
    ret = io_destroy(ctx);
    if (ret) exception(strerror(-ret));
}

void TEST_glibc_aio(boolean polling) {
    pthread_mutex_lock(&mutex);
    posix_aio_cnt = 0;
    pthread_mutex_unlock(&mutex);

    int ret, remain, cnt, aioerror;
    void *buffer;
    struct aiocb *iocb;
    struct aiocb *lio[2*CORCURRENCY];
    buffer = malloc(BUFFER_SIZE*2*CORCURRENCY);
    
    for (int j = 0 ; j < 2*CORCURRENCY ; j++) {
        iocb = malloc(sizeof(struct aiocb));
        memset(iocb, 0, sizeof(struct aiocb));
        iocb->aio_fildes = pipes[j];
        iocb->aio_buf    = buffer + j*BUFFER_SIZE;
        iocb->aio_nbytes = BUFFER_SIZE;
        iocb->aio_offset = 0;
        iocb->aio_sigevent.sigev_notify = SIGEV_NONE;
        iocb->aio_lio_opcode = j%2 ? IO_CMD_PWRITE : IO_CMD_PREAD;
        lio[j] = iocb;
        if (polling) continue;
        /* callback settings */
        iocb->aio_sigevent.sigev_notify = SIGEV_THREAD;
        iocb->aio_sigevent.sigev_notify_function = callback;
        iocb->aio_sigevent.sigev_notify_attributes = NULL;
        iocb->aio_sigevent.sigev_value.sival_ptr = iocb;
        
    }   
    /* submit all */
    DTRACE_PROBE(ra, in_glibc_aio);
    if (lio_listio(LIO_NOWAIT, lio, 2*CORCURRENCY, NULL)) exception(strerror(-errno));

    /* polling or callback operation */
    if (polling) {
        do {
            cnt = 0;
            if (aio_suspend(lio, 2*CORCURRENCY, NULL)) exception(strerror(-errno));
            for (int i = 0 ; i < 2*CORCURRENCY ; i++) {
                aioerror = aio_error(lio[i]);
                if (aioerror == EINPROGRESS || aioerror == ECANCELED) continue;
                else cnt++;
            }
        } while (cnt < 2*CORCURRENCY);
    } else {
        while (posix_aio_cnt != 2*CORCURRENCY) {};
    }
    DTRACE_PROBE(ra, out_glibc_aio);
}

void callback(__sigval_t sigval) {
    DTRACE_PROBE(ra, in_callback);
    if (!sigval.sival_ptr) exception("NULL on callback aiocb");
    struct aiocb *iocb = (struct aiocb *)(sigval.sival_ptr);
    if (iocb->aio_nbytes != BUFFER_SIZE) exception("buffer size not matched");
    pthread_mutex_lock(&mutex);
    posix_aio_cnt++;
    pthread_mutex_unlock(&mutex);
    DTRACE_PROBE(ra, out_callback);
}