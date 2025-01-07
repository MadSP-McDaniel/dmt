#ifndef COMMON_H
#define COMMON_H

#include <cstring>
#include <string>
#include <vector>

#ifdef __DEBUG
#define pdebug0(...)                                                           \
	{                                                                          \
		fprintf(stdout, "[%s:%d,%s] ", __FILE__, __LINE__, __func__);          \
		fprintf(stdout, __VA_ARGS__);                                          \
		fprintf(stdout, "\n");                                                 \
	}
#else
#define pdebug0(...)
#endif

#define perr(...) fprintf(stderr, __VA_ARGS__)

#define perr_and_abort0(...)                                                   \
	{                                                                          \
		fprintf(stderr, "Aborted [%s:%d,%s] ", __FILE__, __LINE__, __func__);  \
		fprintf(stderr, __VA_ARGS__);                                          \
		fprintf(stderr, "\n");                                                 \
		abort();                                                               \
	}

#define perr_and_abort1()                                                      \
	{                                                                          \
		fprintf(stderr, "Aborted [%s:%d,%s]\n", __FILE__, __LINE__, __func__); \
		abort();                                                               \
	}

// Common helper functions
uint64_t __do_read(int, char *, uint64_t, uint64_t);
uint64_t __do_write(int, char *, uint64_t, uint64_t);
void dump_to_file(std::string, const char *, bool);
double __get_time();
double __get_time_ns();
int setup_sigs();
int zipf(double, int, int);
std::string format_double(double, int = 3);

// Crypto settings
#define IV_SIZE 12
#define MAC_SIZE 16
#define HASH_SIZE 32
#define HASH_KEY_SIZE 32
#define CIPHER_KEY_SIZE 16
extern const uint8_t HASH_KEY[HASH_KEY_SIZE];
extern const uint8_t CIPHER_KEY[CIPHER_KEY_SIZE];

// Block device settings
#define BLK_SIZE ((long)4096)
#define DISK_SIZE __disk_size
#define NUM_BLKS (DISK_SIZE / BLK_SIZE)
#define SECURE_CACHE_SIZE __secure_cache_size
#define INSECURE_CACHE_SIZE __insecure_cache_size
extern uint64_t counter;
extern uint64_t __disk_size;
extern uint64_t __secure_cache_size;
extern uint64_t __insecure_cache_size;

// General global vars
extern uint64_t total_num_nodes;
extern int leaf_meta_fd;
extern int internal_meta_fd;
extern int root_fd;
extern int bd_fd;
extern int enable_mt;
extern int enable_enc;
extern int enable_trace;
extern int dmt_status;
extern long bg_thread_rate;
extern long MAX_QUEUE_SIZE;
extern double LOW_WATERMARK_THRESHOLD;

extern int use_chunked_io;

// This flag indicates whether to perform the actual data access on reads/writes
// or just use a single on-disk block during testing. This is only used to make
// debugging easier (particularly when examining large disks, because we do not
// need to provision actual capacity).
extern int use_static_block;

extern std::vector<uint64_t> warmup_trace;

// Various runtime statistics.
typedef struct _stats_t {
	uint64_t num_reauths;
	uint64_t num_reauths_during_splay;
	uint64_t num_splays;
	uint64_t num_verify_rets;
	uint64_t num_early_rets;
	int8_t active_io_type;
	uint64_t num_meta_disk_writes_from_blk_reads;
	uint64_t num_meta_disk_writes_from_blk_writes;
	uint64_t num_meta_root_disk_writes_from_blk_reads;
	uint64_t num_meta_root_disk_writes_from_blk_writes;
	uint64_t num_meta_root_disk_reads_from_blk_reads;
	uint64_t num_meta_root_disk_reads_from_blk_writes;
	uint64_t num_meta_disk_reads_from_blk_reads;
	uint64_t num_meta_disk_reads_from_blk_writes;
	uint64_t num_evictions_during_blk_writes;
	uint64_t num_evictions_during_blk_reads;
	uint64_t num_misses_during_blk_writes;
	uint64_t num_misses_during_blk_reads;
	uint64_t write_stride;
} stats_t;
extern stats_t stats;

extern std::vector<double> verify_mt_lats, update_mt_lats, op_read_lats,
	op_write_lats, verify_queue_times, update_queue_times, data_write_lats,
	data_read_lats, metadata_read_lats, metadata_write_lats, lats_on_splay;
extern double running_metadata_read_lat, running_metadata_write_lat;

#endif /* COMMON_H */
