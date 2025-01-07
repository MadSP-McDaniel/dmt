#include <cassert>
#include <chrono>
#include <climits>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

const uint8_t HASH_KEY[HASH_KEY_SIZE] = {
	0x1,  0x2,	0x3,  0x4,	0x5,  0x6,	0x7,  0x8,	0x9,  0xa,	0xb,
	0xc,  0xd,	0xe,  0xf,	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
const uint8_t CIPHER_KEY[CIPHER_KEY_SIZE] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6,
											 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,
											 0xd, 0xe, 0xf, 0x10};

uint64_t __disk_size = 0;
uint64_t __secure_cache_size = 0;
uint64_t __insecure_cache_size = 0;
uint64_t counter = 0;

uint64_t total_num_nodes = 0;
int leaf_meta_fd = 0;
int internal_meta_fd = 0;
int root_fd = 0;
int bd_fd = 0;
int enable_mt = 1;
int enable_enc = 1;
int enable_trace = 0;
int dmt_status = 0;
long bg_thread_rate = 0;
long MAX_QUEUE_SIZE = 1 << 20;
double LOW_WATERMARK_THRESHOLD = 0.75;
int use_chunked_io = 1;
int use_static_block = 0;
std::vector<uint64_t> warmup_trace;

stats_t stats = {0};
std::vector<double> verify_mt_lats, update_mt_lats, op_read_lats, op_write_lats,
	verify_queue_times, update_queue_times, data_write_lats, data_read_lats,
	metadata_read_lats, metadata_write_lats, lats_on_splay;
double running_metadata_read_lat, running_metadata_write_lat;

uint64_t __do_read(int fd, char *buffer, uint64_t offset, uint64_t _size) {
	ssize_t res;
	uint64_t size = _size;

	// If the fd is to data, just read the static block (block 0).
	if (use_static_block && (fd == bd_fd))
		offset = 0;

	//  Note: pread/pwrite will fail if the file is opened with O_DIRECT and the
	//  buffer is not aligned.
	while (size > 0) {
		res = pread(fd, buffer, size, offset);

		if (res < 0) {
			// retry if interrupted, fail otherwise
			perr("%s\n", strerror(errno));
			if (errno != EINTR)
				return errno;
		} else if (res == 0) {
			// EOF should never happen for us, just abort
			perr("EOF\n");
			return INT_MIN;
		}

		buffer += res;
		offset += res;
		size -= res;
	}

	return 0;
}

uint64_t __do_write(int fd, char *buffer, uint64_t offset, uint64_t _size) {
	ssize_t res;
	uint64_t size = _size;

	if (use_static_block && (fd == bd_fd))
		offset = 0;

	while (size > 0) {
		res = pwrite(fd, buffer, size, offset);

		if (res < 0) {
			// retry if interrupted, fail otherwise
			perr("%s\n", strerror(errno));
			if (errno != EINTR)
				return errno;
		} else if (res == 0) {
			// empty write, just abort
			perr("Empty write\n");
			return INT_MIN;
		}

		buffer += res;
		offset += res;
		size -= res;
	}

	return 0;
}

void dump_to_file(std::string fname, const char *data, bool append) {
	std::string fstem =
		std::string(getenv("DMT_HOME")) + std::string("/bench/o/");

	perr("Dumping data to [%s]\n", std::string(fstem + fname).c_str());

	FILE *fp = NULL;
	if (append) {
		fp = fopen(std::string(fstem + fname).c_str(), "a");
	} else {
		int r = remove(std::string(fstem + fname).c_str());
		if (r != 0 && errno != ENOENT)
			perr_and_abort0("Error deleting file: %s\n", strerror(errno));
		fp = fopen(std::string(fstem + fname).c_str(), "w");
	}

	fprintf(fp, "%s", data);
	fclose(fp);
}

double __get_time() {
	return (double)std::chrono::time_point_cast<std::chrono::microseconds>(
			   std::chrono::high_resolution_clock::now())
		.time_since_epoch()
		.count();
}

double __get_time_ns() {
	return (double)std::chrono::time_point_cast<std::chrono::nanoseconds>(
			   std::chrono::high_resolution_clock::now())
		.time_since_epoch()
		.count();
}

static void sig_handler(int signo) {
	if (signo != SIGINT && signo != SIGTERM)
		exit(0);

	// Cant really dump during signal handler so just toggle status flag.
	dmt_status = 0;
}

int setup_sigs() {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER | SA_ONSTACK;

	if (sigaction(SIGINT, &sa, NULL) < 0)
		perr_and_abort0("Error: Failed to setup SIGINT handler.\n");

	if (sigaction(SIGTERM, &sa, NULL) < 0)
		perr_and_abort0("Error: Failed to setup SIGTERM handler.\n");

	return 0;
}

int zipf(double alpha, int n, int done) {
	static int first = 1;			 // Static first time flag
	static double c = 0;			 // Normalization constant
	static double *sum_probs = NULL; // Pre-calculated sum of probabilities

	if (done) {
		if (sum_probs)
			free(sum_probs);
		return 0;
	}

	double z;			// Uniform random number (0 < z < 1)
	int zipf_value;		// Computed exponential value to be returned
	int i;				// Loop counter
	int low, high, mid; // Binary-search bounds

	// Compute normalization constant on first call only
	if (first == 1) {
		for (i = 1; i <= n; i++)
			c = c + (1.0 / pow((double)i, alpha));
		c = 1.0 / c;

		sum_probs = (double *)calloc((n + 1), sizeof(*sum_probs));
		sum_probs[0] = 0;
		for (i = 1; i <= n; i++) {
			sum_probs[i] = sum_probs[i - 1] + c / pow((double)i, alpha);
		}
		first = 0;
	}

	// Pull a uniform random number (0 < z < 1)
	do {
		z = (double)rand() / (double)RAND_MAX;
	} while ((z == 0) || (z == 1));

	// Map z to the value
	low = 1, high = n, mid = 1, zipf_value = 1;
	do {
		mid = floor((low + high) / 2);
		if (sum_probs[mid] >= z && sum_probs[mid - 1] < z) {
			zipf_value = mid;
			break;
		} else if (sum_probs[mid] >= z) {
			high = mid - 1;
		} else {
			low = mid + 1;
		}
	} while (low <= high);

	// Assert that zipf_value is between 1 and N
	assert((zipf_value >= 1) && (zipf_value <= n));

	return (zipf_value);
}

std::string format_double(double d, int precision) {
	std::string s = std::to_string(d);
	return s.substr(0, s.find(".") + precision + 1);
}
