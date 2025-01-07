/**
 * See description in main.cc. This code is the other mode of operation, which
 * initializes the merkle tree and executes the workloads directly against the
 * given block device file. This mode makes testing/debugging simpler.
 */
#include <cassert>
#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/sysinfo.h>
#include <vector>

#include "cache.h"
#include "common.h"
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
					"       [-f <replay_trace_file>]\n"
					"       [-z <alpha>]\n"
					"       [-r <read_ratio>]\n",
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

	// Use 0 cache size during init (to avoid memory contention issues between
	// the minheap and cache) then reinit with actual cache size.
	__secure_cache_size = 0;
	__insecure_cache_size = 0;

	// Note: Using the FIXED_ARITY given at compile time makes serializing the
	// mt_node struct to disk easier. We need to eventually update all of the
	// code to use the FIXED_ARITY, but we do a sanity check that they always
	// match during init.
	if (arity != FIXED_ARITY)
		perr_and_abort0("Arity mismatch");

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

static void setup_trace_replay(char *replay_trace_file, int64_t *&freq,
							   mt_type_t mt_type,
							   std::vector<uint64_t> &blk_sequence,
							   std::string &trace_name) {
	perr("Setting up to replay trace: %s\n", replay_trace_file);

	if (mt_type == HUFFMAN) {
		freq = (int64_t *)calloc(NUM_BLKS, sizeof(int64_t));
		for (uint64_t b = 0; b < NUM_BLKS; b++)
			freq[b] = 0;
	}

	trace_name = std::string(replay_trace_file);
	trace_name = trace_name.substr(trace_name.find_last_of("/\\") + 1);
	trace_name = trace_name.substr(0, trace_name.find("_"));

	perr("NOTE: Scaling blkids for trace replay\n");
	std::ifstream data(replay_trace_file);
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

		// This should be consistent with scaling in the bench shell scripts.
		// Note that we need this specifically for OPT because it requires a
		// trace profile to build the OPT tree.
		uint64_t blkid = std::stoull(offset) / BLK_SIZE;
		if (blkid >= NUM_BLKS)
			perr_and_abort0(
				"Out of bounds blkid [blk=%lu, off=%llu] for trace replay ",
				blkid, std::stoull(offset));

		// If IO length>BLK_SIZE, we need to flatten it to multiple blocks.
		uint64_t num_records = std::stoull(length) / BLK_SIZE;
		for (uint64_t i = 0; i < num_records; i++) {
			blk_sequence.push_back(blkid + i);

			if (mt_type == HUFFMAN)
				freq[blkid + i]++;

			// Sample 5% of the trace for warmup.
			if (rand() % 20 == 0)
				warmup_trace.push_back(blkid + i);
		}
	}
	data.close();

	if (blk_sequence.size() == 0)
		perr_and_abort0("Error: No trace entries found\n");
	perr("Finished reading trace file: %lu entries found\n",
		 blk_sequence.size());
}

static void setup_trace_gen(char *replay_trace_file, int64_t *&freq,
							mt_type_t mt_type,
							std::vector<uint64_t> &blk_sequence, double alpha,
							std::string &trace_name, uint64_t iterations) {
	if (alpha > 0.0) {
		trace_name = "zipf" + format_double(alpha, 1);
		perr("Generating new zipf(%.1f) trace: %lu entries\n", alpha,
			 iterations);
	} else {
		trace_name = "uniform";
		perr("Generating new uniform trace: %lu entries\n", iterations);
	}

	std::string fstem =
		std::string(getenv("DMT_HOME")) + std::string("/bench/o/");
	std::string out =
		std::string(fstem + "trace-unlabeled-" + trace_name + ".csv").c_str();
	FILE *fp = fopen(out.c_str(), "w");
	if (!fp)
		perr_and_abort0("Error: Failed to open file: %s\n", strerror(errno));

	// Loop through and create a comma separated list of block ids as the trace.
	uint64_t v = 0;
	std::string end = "";
	for (uint64_t i = 0; i < iterations; i++) {
		if (alpha > 0.0)
			v = zipf(alpha, NUM_BLKS - 1, 0);
		else
			v = rand() % NUM_BLKS;

		blk_sequence.push_back(v);

		end = (i == iterations - 1) ? "\n" : ",";
		fprintf(fp, "%s", (std::string(std::to_string(v)) + end).c_str());
	}
	v = zipf(0.0, 0, 1); // cleanup zipf generator

	perr("Dumping generated unlabeled trace [%s]\n", out.c_str());
	fclose(fp);
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
				perr_and_abort0("Error: Failed to initialize merkle tree.\n");
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

static void run_workload(std::vector<uint64_t> &blk_sequence,
						 uint64_t iterations, double rratio,
						 double &init_start_time, double &end_time,
						 std::vector<double> &epoch_tps) {
	// First compute random indexes at which to log throughputs.
	std::vector<uint64_t> sample_epochs;
	double perc_sample_epochs = 0.01;
	for (uint64_t i = 0; i < iterations; i++) {
		if ((double)rand() / RAND_MAX < perc_sample_epochs)
			sample_epochs.push_back(1);
		else
			sample_epochs.push_back(0);
	}

	struct bdus_ctx ctx = {.private_data = &bd_fd};
	uint64_t epoch_start = 0;
	double op = 0.0;
	int r = 0;
	char buffer[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	uint64_t offset = 0;
	init_start_time = __get_time(), end_time = 0;
	double start_time = init_start_time;

	// Now run the test workload.
	for (uint64_t i = 0; i < iterations; i++) {
		pdebug0("Starting iteration [%lu]\n", i);
		offset = blk_sequence[i] * BLK_SIZE;

		op = (double)rand() / (double)RAND_MAX;

		if (op >= rratio) {
			pdebug0("Starting write...\n");
			r = device_write(buffer, offset, BLK_SIZE, &ctx);
			if (r != 0)
				perr_and_abort0("Error writing: %s\n", strerror(errno));
			pdebug0("Finished write.\n");
		} else {
			pdebug0("Starting read...\n");
			r = device_read(buffer, offset, BLK_SIZE, &ctx);
			if (r != 0)
				perr_and_abort0("Error reading: %s\n", strerror(errno));
			pdebug0("Finished read.\n");
		}

		if (sample_epochs.at(i)) {
			end_time = __get_time();
			epoch_tps.push_back((double)(((i - epoch_start) * BLK_SIZE) /
										 (end_time - start_time)));
			start_time = end_time;
			epoch_start = i;
		}

		if (i % (iterations / 10) == 0)
			perr("Progress: %lu%%\n", (i / (iterations / 10)) * 10);
	}
	end_time = __get_time();

	perr("\n\033[32mTest completed successfully\033[0m\n\n==========\n");
	if (enable_trace && cleanup_tracer() < 0)
		perr_and_abort0("Error: Failed to destroy tracer.\n");
}

static void dump_all_results(mt_type_t mt_type, uint64_t arity,
							 double secure_cache_ratio, double rratio,
							 double alpha, std::string trace_name,
							 uint64_t iterations, double init_start_time,
							 double end_time, std::vector<double> epoch_tps) {
	std::string out =
		std::string("tp-vs-cap-" + mt_type_to_str(mt_type, arity) + "-" +
					trace_name + ".csv")
			.c_str();
	double tp =
		(double)((iterations * BLK_SIZE) / (end_time - init_start_time));
	std::string tp_str =
		std::to_string(__disk_size) + std::string(",") +
		std::to_string(secure_cache_ratio) + std::string(",") +
		format_double(rratio) + std::string(",") + format_double(alpha, 1) +
		std::string(",") + format_double(get_secure_cache_hit_rate()) +
		std::string(",") + std::to_string(tp) + std::string("\n");
	dump_to_file(out, tp_str.c_str(), false);

	out = std::string("tp-vs-time-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string epoch_str =
		std::to_string(__disk_size) + std::string(",") +
		std::to_string(secure_cache_ratio) + std::string(",") +
		format_double(rratio) + std::string(",") + format_double(alpha, 1) +
		std::string(",") + format_double(get_secure_cache_hit_rate()) +
		std::string(",");
	std::string epoch_str_out = "";
	for (auto it = epoch_tps.begin(); it != epoch_tps.end(); it++)
		epoch_str_out += epoch_str + std::to_string(*it) + std::string("\n");
	dump_to_file(out, epoch_str_out.c_str(), false);

	// Log perf stats (including cache stats) before we call get_mt_info.
	std::string perf_stats = log_perf_stats();

	// Log mt info at end because console output may be cluttered with logs.
	int64_t min_height = 0, max_height = 0, q25_height = 0, q50_height = 0,
			q75_height = 0;
	double avg_height = 0;
	// Only log mt info again for DMT since other trees dont change
	if (mt_type == DMT) {
		perr("\n==========\n");
		get_mt_info(&min_height, &max_height, &avg_height, &q25_height,
					&q50_height, &q75_height);
	}

	cleanup_caches();
	flush_mt();

	close(bd_fd);
	close(leaf_meta_fd);
	close(internal_meta_fd);

	// Dump tree stats (min height, max height, avg height, q25_height,
	// median_height/q50, q75_height).
	out = std::string("tree-stats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string tree_stats_str_out =
		std::to_string(__disk_size) + std::string(",") +
		std::to_string(secure_cache_ratio) + std::string(",") +
		format_double(rratio) + std::string(",") + format_double(alpha, 1) +
		std::string(",") + format_double(get_secure_cache_hit_rate()) +
		std::string(",") + format_double(min_height) + std::string(",") +
		format_double(max_height) + std::string(",") +
		format_double(avg_height) + std::string(",") +
		format_double(q25_height) + std::string(",") +
		format_double(q50_height) + std::string(",") +
		format_double(q75_height) + std::string("\n");
	dump_to_file(out, tree_stats_str_out.c_str(), false);

	// Now dump all stats.
	out = std::string("update_mt_lats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string update_mt_lats_str_out = "";
	for (auto it = update_mt_lats.begin(); it != update_mt_lats.end(); it++)
		update_mt_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, update_mt_lats_str_out.c_str(), false);

	out = std::string("verify_mt_lats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string verify_mt_lats_str_out = "";
	for (auto it = verify_mt_lats.begin(); it != verify_mt_lats.end(); it++)
		verify_mt_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, verify_mt_lats_str_out.c_str(), false);

	out = std::string("op_read_lats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string read_lats_str_out = "";
	for (auto it = op_read_lats.begin(); it != op_read_lats.end(); it++)
		read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, read_lats_str_out.c_str(), false);

	out = std::string("op_write_lats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string write_lats_str_out = "";
	for (auto it = op_write_lats.begin(); it != op_write_lats.end(); it++)
		write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, write_lats_str_out.c_str(), false);

	out = std::string("verify_queue_times-" + mt_type_to_str(mt_type, arity) +
					  "-" + trace_name + ".csv")
			  .c_str();
	std::string verify_queue_times_str_out = "";
	for (auto it = verify_queue_times.begin(); it != verify_queue_times.end();
		 it++)
		verify_queue_times_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, verify_queue_times_str_out.c_str(), false);

	out = std::string("update_queue_times-" + mt_type_to_str(mt_type, arity) +
					  "-" + trace_name + ".csv")
			  .c_str();
	std::string update_queue_times_str_out = "";
	for (auto it = update_queue_times.begin(); it != update_queue_times.end();
		 it++)
		update_queue_times_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, update_queue_times_str_out.c_str(), false);

	out = std::string("data_write_lats-" + mt_type_to_str(mt_type, arity) +
					  "-" + trace_name + ".csv")
			  .c_str();
	std::string data_write_lats_str_out = "";
	for (auto it = data_write_lats.begin(); it != data_write_lats.end(); it++)
		data_write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, data_write_lats_str_out.c_str(), false);

	out = std::string("data_read_lats-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string data_read_lats_str_out = "";
	for (auto it = data_read_lats.begin(); it != data_read_lats.end(); it++)
		data_read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, data_read_lats_str_out.c_str(), false);

	out = std::string("metadata_read_lats-" + mt_type_to_str(mt_type, arity) +
					  "-" + trace_name + ".csv")
			  .c_str();
	std::string metadata_read_lats_str_out = "";
	for (auto it = metadata_read_lats.begin(); it != metadata_read_lats.end();
		 it++)
		metadata_read_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, metadata_read_lats_str_out.c_str(), false);

	out = std::string("metadata_write_lats-" + mt_type_to_str(mt_type, arity) +
					  "-" + trace_name + ".csv")
			  .c_str();
	std::string metadata_write_lats_str_out = "";
	for (auto it = metadata_write_lats.begin(); it != metadata_write_lats.end();
		 it++)
		metadata_write_lats_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, metadata_write_lats_str_out.c_str(), false);

	out = std::string("lats_on_splay-" + mt_type_to_str(mt_type, arity) + "-" +
					  trace_name + ".csv")
			  .c_str();
	std::string lats_on_splay_str_out = "";
	for (auto it = lats_on_splay.begin(); it != lats_on_splay.end(); it++)
		lats_on_splay_str_out += std::to_string(*it) + std::string("\n");
	dump_to_file(out, lats_on_splay_str_out.c_str(), false);

	perr("\n========== Result summary ==========\n");
	perr("Start time: %.3f\n", init_start_time);
	perr("End time: %.3f\n", end_time);
	perr("Total time: %.3fs\n", (end_time - init_start_time) / 1e6);
	perr("Number of test iterations: %lu\n", iterations);
	perr("Read ratio: %.2f\n", rratio);
	perr("%s", perf_stats.c_str());
	perr("Throughput: %.3f MB/s\n", tp);
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
	char *replay_trace_file = NULL;
	int replay_trace = 0;
	double alpha = 0.0;
	double rratio = 0.0;

	if (argc < 25)
		print_usage(argv[0]);
	int ch = 0;
	while ((ch = getopt(argc, argv, "u:b:m:s:k:a:x:c:i:q:w:t:f:z:r:")) !=
		   -1) {
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
			break;
		case 'q':
			MAX_QUEUE_SIZE = atol(optarg);
			break;
		case 'w':
			LOW_WATERMARK_THRESHOLD = atof(optarg);
			break;
		case 'f':
			replay_trace_file = optarg;
			replay_trace = 1;
			break;
		case 'z':
			alpha = atof(optarg);
			break;
		case 'r':
			rratio = atof(optarg);
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

	if ((mt_type == HUFFMAN) && !replay_trace)
		perr_and_abort0("Huffman tree requires a trace to replay\n");

	// Setup bdus params and global vars
	struct bdus_ops ops = device_ops;
	struct bdus_attrs attrs = device_attrs;
	setup_devices(block_device, block_device_str, ops, attrs,
				  secure_cache_ratio, insecure_cache_ratio, leaf_metadata_file,
				  internal_metadata_file, arity);

	// Setup trace to replay or generate
	uint64_t iterations = (uint64_t)100e3;
	std::string trace_name = "";
	std::vector<uint64_t> blk_sequence;
	int64_t *freq = NULL;
	if (replay_trace) {
		setup_trace_replay(replay_trace_file, freq, mt_type, blk_sequence,
						   trace_name);
		iterations = blk_sequence.size();
		perr("Replaying trace: %lu entries\n", iterations);
	} else {
		setup_trace_gen(replay_trace_file, freq, mt_type, blk_sequence, alpha,
						trace_name, iterations);
	}

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

	// Now start test workload
	double init_start_time = 0, end_time = 0;
	std::vector<double> epoch_tps;
	run_workload(blk_sequence, iterations, rratio, init_start_time, end_time,
				 epoch_tps);

	// On clean exit, signal to other threads that we are done
	dmt_status = 0;

	// Now dump results
	dump_all_results(mt_type, arity, secure_cache_ratio, rratio, alpha,
					 trace_name, iterations, init_start_time, end_time,
					 epoch_tps);

	return 0;
}
