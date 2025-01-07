/**
 * We can run the benchmarks in one of two modes: 1) by initializing the mt on,
 * and running the workload directly against, the specified block device special
 * file (by directly calling device_read/device_write), or 2) by instantiating a
 * bdus device, initializing the mt on it, then running a workload against the
 * bdus device (with pread/pwrite or with tools like fio). The code in this file
 * instantiates the bdus device so a workload can be run against it. This mode
 * is useful for holistic analysis, because we can format a file system on the
 * bdus device (or not) and then run real benchmarks/workloads against it, while
 * accounting for real block-level overheads.
 */
#include "common.h"
#define _FILE_OFFSET_BITS 64

#include <cassert>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/sysinfo.h>
#include <vector>

#include "cache.h"
#include "dmt.h"
#include "mt.h"
#include "trace.h"

static void print_usage(char *a0) {
	perr_and_abort0("Invalid number of args. Usage:\n "
					"%s -u <use_static_block>\n"
					"       -b <block_device>\n"
					"       -m <leaf_metadata_file>\n"
					"       -s <internal_metadata_file>\n"
					"       -k <use_chunked_io>\n"
					"       -a <arity>\n"
					"       -x <enable_tracer>\n"
					"       -c <secure_cache_ratio>\n"
					"       -i <insecure_cache_ratio>\n"
					"       -q <max queue size>\n"
					"       -w <low watermark threshold>\n"
					"       -t <mt_type>\n"
					"       -f <input_trace_file>\n",
					a0);
}

static void setup_devices(uint64_t block_device, char *block_device_str,
						  struct bdus_ops &ops, struct bdus_attrs &attrs,
						  double secure_cache_ratio,
						  double insecure_cache_ratio, char *leaf_metadata_file,
						  char *internal_metadata_file, uint64_t arity) {
	// Open device for data blocks.
	if (use_static_block)
		bd_fd = open("/dev/mapper/data_disk", O_RDWR | O_CREAT | O_TRUNC, 0777);
	else
		bd_fd = open(block_device_str, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (bd_fd < 0)
		perr_and_abort0("%s", strerror(errno));

	// Configure bdus device from metadata about underlying device.
	ops = device_ops;
	attrs = device_attrs;
	if (!configure_device(bd_fd, &ops, &attrs)) {
		close(bd_fd);
		perr_and_abort0("ioctl on underlying device failed. Is device a "
						"block special file?\n");
	}
	if (use_static_block)
		attrs.size = block_device;

	__disk_size = attrs.size;

	__secure_cache_size = 0;
	__insecure_cache_size = 0;

	if (arity != FIXED_ARITY)
		perr_and_abort0("Arity mismatch");

	perr("\n=====================\n");
	perr("Disk size: %lu B\n", __disk_size);
	perr("Logical block size: %lu B\n", BLK_SIZE);
	perr("Number of data blocks: %lu\n", NUM_BLKS);
	perr("Number of leaf node metadata blocks: %lu\n", NUM_LEAF_META_BLKS);
	perr("Number of internal node metadata blocks: %lu\n",
		 NUM_INTERNAL_META_BLKS2);
	perr("use_static_block: %d\n", use_static_block);
	perr("use_chunked_io: %d\n", use_chunked_io);
	perr("MAX_QUEUE_SIZE: %lu\n", MAX_QUEUE_SIZE);
	perr("LOW_WATERMARK_THRESHOLD: %f\n", LOW_WATERMARK_THRESHOLD);

	// Open device for hash/metadata blocks.
	leaf_meta_fd = open(leaf_metadata_file, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (leaf_meta_fd < 0)
		perr_and_abort0("%s", strerror(errno));

	internal_meta_fd =
		open(internal_metadata_file, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (internal_meta_fd < 0)
		perr_and_abort0("%s", strerror(errno));
}

static void setup_trace(char *input_trace_file, int64_t *&freq) {
	perr("Reading trace profile: %s\n", input_trace_file);

	freq = (int64_t *)calloc(NUM_BLKS, sizeof(int64_t));
	for (uint64_t b = 0; b < NUM_BLKS; b++)
		freq[b] = 0;

	perr("NOTE: Scaling blkids for trace replay\n");
	std::ifstream data(input_trace_file);
	std::string line;
	while (std::getline(data, line)) {
		if ((line.find("fio version 3") != std::string::npos) ||
			(line.find("add") != std::string::npos) ||
			(line.find("open") != std::string::npos) ||
			(line.find("close") != std::string::npos))
			continue;

		// Tokenize the line to get the device, operation, offset, and length.
		std::istringstream iss(line);
		std::vector<std::string> tokens;
		std::string token;
		while (std::getline(iss, token, ' '))
			tokens.push_back(token);

		if (tokens.size() < 5)
			perr_and_abort1();

		std::string timestamp = tokens[0];
		std::string device = tokens[1];
		std::string op = tokens[2];
		if (op != "read" && op != "write") {
			perr("Error: Invalid operation in trace file: %s\n", op.c_str());
			perr_and_abort1();
		}
		std::string offset = tokens[3];
		std::string length = tokens[4];

		uint64_t blkid = std::stoull(offset) / BLK_SIZE;
		if (blkid >= NUM_BLKS)
			perr_and_abort0(
				"Out of bounds blkid [blk=%lu, off=%llu] for trace replay ",
				blkid, std::stoull(offset));

		// If IO length>BLK_SIZE, we need to flatten it to multiple blocks.
		uint64_t num_records = std::stoull(length) / BLK_SIZE;
		static int log_flattening = 0;
		if (num_records > 1 && log_flattening == 0) {
			perr("Flattening IO\n");
			log_flattening = 1;
		}
		for (uint64_t i = 0; i < num_records; i++) {
			if (blkid + i < NUM_BLKS) {
				freq[blkid + i]++;
				// Sample 5% of the trace for warmup.
				if (rand() % 20 == 0)
					warmup_trace.push_back(blkid + i);
			} else {
				break;
			}
		}
	}
	data.close();
}

static void setup_hash_tree(mt_type_t mt_type, int64_t *&freq, uint64_t arity,
							char *block_device_str, char *leaf_metadata_file,
							char *internal_metadata_file,
							double secure_cache_ratio,
							double insecure_cache_ratio) {
	std::string root_file =
		std::string(getenv("DMT_HOME")) + std::string("/bench/o/root.bin");
	root_fd = open(root_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (root_fd < 0)
		perr_and_abort0("%s", strerror(errno));

	if (enable_mt) {
		if (mt_type == HUFFMAN) {
			perr("Initializing static huffman tree...\n");
			if (init_huffman_tree(bd_fd, freq, arity, false) < 0)
				perr_and_abort0("Failed initializing static huffman tree\n");
			perr("Done initializing static huffman tree\n");
		} else if (mt_type == DMT) {
			perr("Initializing dmt...\n");
			if (init_dmt(bd_fd, arity) < 0)
				perr_and_abort0("Failed initializing dmt\n");
			perr("Done initializing dmt\n");
		} else if (mt_type == VARIABLE_ARITY) {
			perr("Initializing variable arity merkle tree...\n");
			if (init_variable_arity_tree(bd_fd, mt_type, arity) < 0)
				perr_and_abort0("Failed to initialize variable arity tree.\n");
			perr("Done initializing variable arity merkle tree\n");
		} else {
			perr("Initializing generic merkle tree...\n");
			if (init_mt_generic(bd_fd, mt_type, arity) < 0)
				perr_and_abort0("Failed to initialize merkle tree.\n");
			perr("Done initializing generic merkle tree\n");
		}
	} else {
		if (mt_type == ENC_NOINT) {
			perr("Merkle tree disabled, initializing block hashes...\n");
			if (init_block_hashes(bd_fd) < 0)
				perr_and_abort0("Failed to initialize block hashes.\n");
			perr("Done initializing block hashes\n");
		} else {
			perr("Done initializing for NOENC_NOINT\n");
		}
	}

	// Now reinit caches with specified size.
	__secure_cache_size = (uint64_t)((NUM_BLKS * 2.0 - 1) * secure_cache_ratio);
	__insecure_cache_size =
		(uint64_t)((NUM_BLKS * 2.0 - 1) * insecure_cache_ratio);

	struct sysinfo info;
	sysinfo(&info);
	perr("Total RAM: %lu\n", info.totalram);
	if (__secure_cache_size > (0.7 * info.totalram / sizeof(cache_node_t))) {
		__secure_cache_size = 0.7 * info.totalram / sizeof(cache_node_t);
		perr("Secure cache size [c=%.2f] too large, reducing to 70%% of "
			 "total RAM: "
			 "%lu\n",
			 secure_cache_ratio, __secure_cache_size);
	}

	reinit_caches();
	warm_caches(freq);
	if (mt_type == HUFFMAN)
		free(freq);

	// Now close (+flush) hash files and reopen them with necessary flags.
	fsync(leaf_meta_fd);
	close(leaf_meta_fd);
	leaf_meta_fd = open(leaf_metadata_file, O_RDWR);
	if (leaf_meta_fd < 0)
		perr_and_abort0("%s", strerror(errno));

	fsync(internal_meta_fd);
	close(internal_meta_fd);
	internal_meta_fd = open(internal_metadata_file, O_RDWR);
	if (internal_meta_fd < 0)
		perr_and_abort0("%s", strerror(errno));

	fsync(bd_fd);
	close(bd_fd);
	if (use_static_block)
		bd_fd = open("/dev/mapper/data_disk", O_RDWR);
	else
		bd_fd = open(block_device_str, O_RDWR | O_DIRECT);
	if (bd_fd < 0)
		perr_and_abort0("%s", strerror(errno));
}

int main(int argc, char **argv) {
	char *block_device_str = NULL;
	uint64_t block_device = 0;
	char *leaf_metadata_file = NULL;
	char *internal_metadata_file = NULL;
	mt_type_t mt_type = NOENC_NOINT;
	uint64_t arity = 0;
	double secure_cache_ratio = 0.0;
	double insecure_cache_ratio = 0.0;
	char *input_trace_file = NULL;
	int input_trace = 0;

	if (argc < 25)
		print_usage(argv[0]);
	int ch = 0;
	while ((ch = getopt(argc, argv, "u:b:m:s:k:a:x:c:i:q:w:t:f:")) != -1) {
		switch (ch) {
		case 'u':
			// Note that the ordering of this param matters, and should be
			// specified before '-b'.
			use_static_block = atoi(optarg);
			break;
		case 'k':
			use_chunked_io = atoi(optarg);
			break;
		case 'b':
			if (use_static_block)
				block_device = std::stoull(optarg);
			else
				block_device_str = optarg;
			break;
		case 'm':
			leaf_metadata_file = optarg;
			break;
		case 's':
			internal_metadata_file = optarg;
			break;
		case 't':
			mt_type = (mt_type_t)atoi(optarg);
			if (mt_type < -2 || mt_type >= MAX_MT_TYPE)
				perr_and_abort0("Invalid mt_type: %d\n", mt_type);

			if (mt_type < 0)
				enable_mt = 0;
			else
				enable_mt = 1;

			if (mt_type == -2)
				enable_enc = 0;
			break;
		case 'a':
			arity = atoi(optarg);
			break;
		case 'x':
			enable_trace = atoi(optarg);
			break;
		case 'c':
			secure_cache_ratio = atof(optarg);
			break;
		case 'i':
			insecure_cache_ratio = atof(optarg);
			if (insecure_cache_ratio > 0)
				perr_and_abort0("Insecure cache not enabled right now\n");
			break;
		case 'q':
			MAX_QUEUE_SIZE = atol(optarg);
			break;
		case 'w':
			LOW_WATERMARK_THRESHOLD = atof(optarg);
			break;
		case 'f':
			input_trace_file = optarg;
			input_trace = 1;
			break;
		default:
			print_usage(argv[0]);
		}
	}

	if (!enable_enc && (mt_type > 0))
		perr_and_abort0(
			"Encryption must be enabled when using a merkle tree.\n");
	memset(&mt, 0x0, sizeof(merkle_tree_t));
	mt.type = mt_type;

	// General init
	dmt_status = 1;
	srand(time(NULL));
	assert(arity > 0);
	assert(!(!enable_enc && enable_mt)); // cannot enable mt without enc

	if (setup_sigs() < 0)
		perr_and_abort0("failed to setup signals.\n");

	if ((mt_type == HUFFMAN) && (input_trace == 0))
		perr_and_abort0("must provide trace file for huffman tree\n");

	// Setup bdus params and global vars
	struct bdus_ops ops = device_ops;
	struct bdus_attrs attrs = device_attrs;
	setup_devices(block_device, block_device_str, ops, attrs,
				  secure_cache_ratio, insecure_cache_ratio, leaf_metadata_file,
				  internal_metadata_file, arity);

	// Setup trace file for huffman tree
	int64_t *freq = NULL;
	if (input_trace && (mt_type == HUFFMAN))
		setup_trace(input_trace_file, freq);

	// Setup hash tree stuff
	if (init_crypto() != 0)
		perr_and_abort0("init_crypto failed\n");
	setup_hash_tree(mt_type, freq, arity, block_device_str, leaf_metadata_file,
					internal_metadata_file, secure_cache_ratio,
					insecure_cache_ratio);

	// Init locks
	if (pthread_mutex_init(&queue_lock, NULL) != 0)
		perr_and_abort1();
	if (pthread_mutex_init(&data_fd_lock, NULL) != 0)
		perr_and_abort1();
	if (pthread_mutex_init(&gcry_lock, NULL) != 0)
		perr_and_abort1();
	if (pthread_mutex_init(&tracer_lock, NULL) != 0)
		perr_and_abort1();
	if (pthread_mutex_init(&cache_lock, NULL) != 0)
		perr_and_abort1();

	// Finally, start bdus driver to expose device under /dev/bdusX
	int r = 0;
	bool success = bdus_run(&ops, &attrs, &bd_fd);
	if (!success) {
		/**
		 * If received an error code, but dmt status says still running, the
		 * error resulted from a bdus driver failure. Otherwise it was not a
		 * bdus error but a signal to exit.
		 */
		if (dmt_status) {
			r = -1;
			perr_and_abort0("bdus error\n");
		} else
			perr("User triggered exit\n");
	} else
		perr("clean exit\n");

	// On clean exit, signal to other threads that we are done
	dmt_status = 0;

	perr("\n==========\n");
	get_mt_info(NULL, NULL, NULL, NULL, NULL, NULL);

	// Cleanup and exit
	cleanup_caches();
	flush_mt();
	close(bd_fd);
	close(leaf_meta_fd);
	close(internal_meta_fd);

	// Now dump stats
	std::string out =
		std::string("update_mt_lats-" + mt_type_to_str(mt_type, arity) + ".csv")
			.c_str();
	std::string update_mt_lats_str_out = "";
	for (auto it = update_mt_lats.begin(); it != update_mt_lats.end(); it++)
		update_mt_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, update_mt_lats_str_out.c_str(), false);

	out =
		std::string("verify_mt_lats-" + mt_type_to_str(mt_type, arity) + ".csv")
			.c_str();
	std::string verify_mt_lats_str_out = "";
	for (auto it = verify_mt_lats.begin(); it != verify_mt_lats.end(); it++)
		verify_mt_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, verify_mt_lats_str_out.c_str(), false);

	out = std::string("read_lats-" + mt_type_to_str(mt_type, arity) + ".csv")
			  .c_str();
	std::string read_lats_str_out = "";
	for (auto it = op_read_lats.begin(); it != op_read_lats.end(); it++)
		read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, read_lats_str_out.c_str(), false);

	out = std::string("write_lats-" + mt_type_to_str(mt_type, arity) + ".csv")
			  .c_str();
	std::string write_lats_str_out = "";
	for (auto it = op_write_lats.begin(); it != op_write_lats.end(); it++)
		write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, write_lats_str_out.c_str(), false);

	out = std::string("verify_queue_times-" + mt_type_to_str(mt_type, arity) +
					  ".csv")
			  .c_str();
	std::string verify_queue_times_str_out = "";
	for (auto it = verify_queue_times.begin(); it != verify_queue_times.end();
		 it++)
		verify_queue_times_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, verify_queue_times_str_out.c_str(), false);

	out = std::string("update_queue_times-" + mt_type_to_str(mt_type, arity) +
					  ".csv")
			  .c_str();
	std::string update_queue_times_str_out = "";
	for (auto it = update_queue_times.begin(); it != update_queue_times.end();
		 it++)
		update_queue_times_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, update_queue_times_str_out.c_str(), false);

	out = std::string("data_write_lats-" + mt_type_to_str(mt_type, arity) +
					  ".csv")
			  .c_str();
	std::string data_write_lats_str_out = "";
	for (auto it = data_write_lats.begin(); it != data_write_lats.end(); it++)
		data_write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, data_write_lats_str_out.c_str(), false);

	out =
		std::string("data_read_lats-" + mt_type_to_str(mt_type, arity) + ".csv")
			.c_str();
	std::string data_read_lats_str_out = "";
	for (auto it = data_read_lats.begin(); it != data_read_lats.end(); it++)
		data_read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, data_read_lats_str_out.c_str(), false);

	out = std::string("metadata_write_lats-" + mt_type_to_str(mt_type, arity) +
					  ".csv")
			  .c_str();
	std::string metadata_write_lats_str_out = "";
	for (auto it = metadata_write_lats.begin(); it != metadata_write_lats.end();
		 it++)
		metadata_write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, metadata_write_lats_str_out.c_str(), false);

	out = std::string("metadata_read_lats-" + mt_type_to_str(mt_type, arity) +
					  ".csv")
			  .c_str();
	std::string metadata_read_lats_str_out = "";
	for (auto it = metadata_read_lats.begin(); it != metadata_read_lats.end();
		 it++)
		metadata_read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, metadata_read_lats_str_out.c_str(), false);

	out =
		std::string("lats_on_splay-" + mt_type_to_str(mt_type, arity) + ".csv")
			.c_str();
	std::string lats_on_splay_str_out = "";
	for (auto it = lats_on_splay.begin(); it != lats_on_splay.end(); it++)
		lats_on_splay_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, lats_on_splay_str_out.c_str(), false);

	// Log some device perf stats
	perr("\n========== Result summary ==========\n");
	perr("%s\n", log_perf_stats().c_str());

	if (enable_trace && cleanup_tracer() < 0)
		perr_and_abort0("Failed to destroy tracer.\n");

	if (r != 0)
		perr_and_abort0("bdus error: %s\n", bdus_get_error_message());

	perr("Finished driver.\n");

	// Flush all the logs
	fflush(stdout);
	fflush(stderr);

	return r;
}
