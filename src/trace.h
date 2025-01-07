#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>

#include "mt.h"

#define MAX_TRACE_SIZE 1e9

typedef struct trace_entry {
	uint64_t blk_id;
	double timestamp;
	int type;
} trace_entry_t;

int cleanup_tracer();
int record_blk_read(uint64_t, int);
int record_blk_write(uint64_t, int);
int record_io_read(uint64_t, uint32_t);
int record_io_write(uint64_t, uint32_t);

#endif /* TRACE_H */
