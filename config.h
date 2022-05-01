#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sdt.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <aio.h>
#include <libaio.h>
#include <pthread.h>
#include "liburing.h"

#define BATCH_SIZE 1024
#define BUFFER_SIZE 1024
#define CORCURRENCY 5120
#define ITERATION 16
#define boolean size_t
#define true 1
#define false 0