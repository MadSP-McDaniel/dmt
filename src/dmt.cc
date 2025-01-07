/**
 * See description in main.cc. This code is invoked by either the bdus block
 * device driver, or directly by test.cc. It is the entry point to the merkle
 * tree code. It performs two main tasks: 1) on a read: decrypt block data,
 * verify the MAC is consistent with block data, and verify the MAC in the
 * merkle tree; 2) on a write: encrypt block data, generate new MAC, then
 * update the merkle tree with the new MAC.
 */
#include <cassert>
#include <fcntl.h>
#include <gcrypt.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

#include "cache.h"
#include "common.h"
#include "dmt.h"
#include "mt.h"
#include "trace.h"

mt_req *check_queue(uint64_t node_id, bool pop = false) {
	mt_req *req = NULL;

	if (pthread_mutex_lock(&queue_lock) != 0)
		perr_and_abort1();

	if (mt_queue_latest_idx.empty()) {
		if (pthread_mutex_unlock(&queue_lock) != 0)
			perr_and_abort1();
		return NULL;
	}

	// Check the queue for the updated node hash before going to cache/disk.
	// Note: We probably should not return the ptr directly because we
	// release the lock right after. Since we use coarse-grained lock in
	// device_write/device_read and the bg thread (data_fd_lock) this is
	// fine for now though.
	if (mt_queue_latest_idx.find(node_id) != mt_queue_latest_idx.end()) {
		req = &mt_queue_latest_idx[node_id];
		if (pthread_mutex_unlock(&queue_lock) != 0)
			perr_and_abort1();
		return req;
	}

	if (pthread_mutex_unlock(&queue_lock) != 0)
		perr_and_abort1();

	return NULL;
}

int device_read(char *buffer, uint64_t offset, uint32_t size,
				struct bdus_ctx *ctx) {
	// All reads should be block-aligned.
	assert((offset % BLK_SIZE) == 0);

	pdebug0(
		"starting read: [enable_mt: %d, off: %lu, start blk: %lu, size: %u]\n",
		enable_mt, offset, offset / BLK_SIZE, size);

	// Note: This allows terminating the driver with SIGINT/SIGTERM. We have
	// 'sudo bdus destroy' though and dont really need this anymore.
	if (!dmt_status) {
		perr("DMT status zero\n");
		return bdus_abort;
	}

	int data_fd = *((int *)ctx->private_data);
	uint64_t blk_id;
	uint64_t aad = 0;
	mt_node_t *node;
	uint8_t *mac_copy;
	mt_req_t args;
	bool was_queued;
	double op_start_time, op_end_time, d_start_time, d_end_time, uv_start_time,
		uv_end_time;
	char *buffer_to_read = NULL;

	if (posix_memalign((void **)&buffer_to_read, BLK_SIZE, size) != 0)
		perr_and_abort1();
	if (!buffer_to_read)
		perr_and_abort1();

	// Reset these for each read/write op. Note that these are global so the
	// driver must be single-threaded to ensure accurate results when plotting.
	running_metadata_read_lat = 0.0;
	running_metadata_write_lat = 0.0;

	op_start_time = __get_time_ns();

	if (enable_trace)
		record_io_read(offset / BLK_SIZE, size);

	pthread_mutex_lock(&data_fd_lock);

	d_start_time = __get_time_ns();
	if (__do_read(data_fd, buffer_to_read, offset, size) != 0)
		perr_and_abort1();
	d_end_time = __get_time_ns();

	data_read_lats.push_back(d_end_time - d_start_time);

	// Note: A call to device_read should only happen after MT initialization,
	// so we should just fetch the mt_node from cache/disk. Note that even if mt
	// is disabled (ie we only have leaf hashes), we still just use the mt_node
	// structure to organize the metadata on disk.
	for (uint64_t b = 0; b < size / BLK_SIZE; b++) {
		node = NULL;
		memset(&args, 0, sizeof(mt_req_t));
		was_queued = false;
		blk_id = (offset + b * BLK_SIZE) / BLK_SIZE;
		if (blk_id >= NUM_BLKS)
			perr_and_abort1();

		if (enable_trace)
			record_blk_read(blk_id, 0);
		stats.active_io_type = 0;

		if (use_static_block)
			aad = 0;
		else
			aad = blk_id;

		if (node && enable_enc)
			was_queued = true; // if using encryption + mt
		if (enable_enc) {
			if (!node)
				node = _get_mt_node(blk_id, true, true, false, NULL, true);
		}

		if (enable_mt) {
            // Decrypt the block and authenticate the read hash.
            if ((dec(buffer_to_read + b * BLK_SIZE, BLK_SIZE, &aad,
                        node->iv, node->hash) != 0))
                perr_and_abort1();

			// Synchronously verify the MAC, if it was not queued.
			if (!was_queued) {
				mac_copy = (uint8_t *)calloc(MAC_SIZE, sizeof(uint8_t));
				if (!mac_copy)
					perr_and_abort1();
				memcpy(mac_copy, node->hash, MAC_SIZE);
				uv_start_time = __get_time_ns();
				if (verify_mt(NULL, node->node_id, mac_copy, false, true) != 0)
					perr_and_abort1();
				uv_end_time = __get_time_ns();
				verify_mt_lats.push_back(uv_end_time - uv_start_time);
			}
		} else {
            // Decrypt the block and authenticate the read hash.
            if (enable_enc && (dec(buffer_to_read + b * BLK_SIZE, BLK_SIZE,
                                    &aad, node->iv, node->hash) != 0))
                perr_and_abort1();
		}

		cleanup_mt_node(node);

		// Update the read block data.
		memcpy(buffer + b * BLK_SIZE, buffer_to_read + b * BLK_SIZE, BLK_SIZE);
		stats.active_io_type = -1;
	}

	pthread_mutex_unlock(&data_fd_lock);

	op_end_time = __get_time_ns();
	op_read_lats.push_back(op_end_time - op_start_time);

	// These combined represent the total metadata I/O per
	// device_read/device_write call.
	metadata_read_lats.push_back(running_metadata_read_lat);
	metadata_write_lats.push_back(running_metadata_write_lat);

	free(buffer_to_read);

	return 0;
}

int device_write(const char *buffer, uint64_t offset, uint32_t size,
				 struct bdus_ctx *ctx) {
	// All writes should be block-aligned.
	assert((offset % BLK_SIZE) == 0);

	pdebug0(
		"starting write: [enable_mt: %d, off: %lu, start blk: %lu, size: %u]\n",
		enable_mt, offset, offset / BLK_SIZE, size);

	if (!dmt_status) {
		perr("DMT status zero\n");
		return bdus_abort;
	}

	int data_fd = *((int *)ctx->private_data);
	uint64_t blk_id;
	mt_node_t *node;
	mt_req_t args;
	uint8_t *mac_copy = NULL;
	uint8_t iv[IV_SIZE] = {0};
	uint64_t aad = 0;
	uint64_t start_splay_count = stats.num_splays;
	double op_start_time, op_end_time, d_start_time, d_end_time, uv_start_time,
		uv_end_time;
	double running_d_time = 0.0, running_uv_time = 0.0;
	char *buffer_to_write = NULL;
	if (posix_memalign((void **)&buffer_to_write, BLK_SIZE, size) != 0)
		perr_and_abort1();
	if (!buffer_to_write)
		perr_and_abort1();

	running_metadata_read_lat = 0.0;
	running_metadata_write_lat = 0.0;

	op_start_time = __get_time_ns();

	if (enable_trace)
		record_io_write(offset / BLK_SIZE, size);
	stats.write_stride++;

	pthread_mutex_lock(&data_fd_lock);

	for (uint64_t b = 0; b < size / BLK_SIZE; b++) {
		node = NULL;
		memset(&args, 0, sizeof(mt_req_t));
		blk_id = (offset + b * BLK_SIZE) / BLK_SIZE;
		if (blk_id >= NUM_BLKS)
			perr_and_abort1();

		if (enable_trace)
			record_blk_write(blk_id, 0);
		stats.active_io_type = 1;

		if (use_static_block)
			memset(&buffer_to_write[b * BLK_SIZE], 0, BLK_SIZE);
		else
			memcpy(&buffer_to_write[b * BLK_SIZE], buffer + b * BLK_SIZE,
				   BLK_SIZE);

		if (use_static_block)
			aad = 0;
		else
			aad = blk_id;

		if (!enable_enc)
			goto ready_write;

		memcpy(iv, &counter, sizeof(counter));
		counter++;

		// Encrypt block and generate new MAC.
		mac_copy = (uint8_t *)calloc(MAC_SIZE, sizeof(uint8_t));
		if (!mac_copy)
			perr_and_abort1();
		if (enc(&buffer_to_write[b * BLK_SIZE], BLK_SIZE, &aad, iv, mac_copy) !=
			0)
			perr_and_abort1();

	ready_write:
		if (enable_enc) {
			if (!node)
				node = _get_mt_node(blk_id, true, true, false, NULL, true);
		}

        // Otherwise just update the mt synchronously.
        if (enable_mt) {
            memcpy(node->iv, iv, IV_SIZE);
            put_mt_node(node);
            uv_start_time = __get_time_ns();
            if (update_mt(NULL, node->node_id, mac_copy, true) != 0)
                perr_and_abort1();
            uv_end_time = __get_time_ns();
            running_uv_time += uv_end_time - uv_start_time;
        } else if (enable_enc) {
            memcpy(node->hash, mac_copy, MAC_SIZE);
            free(mac_copy);
            memcpy(node->iv, iv, IV_SIZE);
            put_mt_node(node);
        }

		stats.active_io_type = -1;
	}

	// Now do the write-out of the new data (only hashes are updated async).
	// This helps amortize costs of calling into the lower-level driver code.
	d_start_time = __get_time_ns();
	if (__do_write(data_fd, buffer_to_write, offset, size) != 0)
		perr_and_abort1();
	d_end_time = __get_time_ns();

	data_write_lats.push_back(running_d_time + (d_end_time - d_start_time));

	pthread_mutex_unlock(&data_fd_lock);

	op_end_time = __get_time_ns();
	op_write_lats.push_back(op_end_time - op_start_time);

	if (stats.num_splays > start_splay_count)
		lats_on_splay.push_back(op_end_time - op_start_time);

	metadata_read_lats.push_back(running_metadata_read_lat);
	metadata_write_lats.push_back(running_metadata_write_lat);

	free(buffer_to_write);

	return 0;
}

static int device_flush(struct bdus_ctx *ctx) {
	int data_fd = *((int *)ctx->private_data);
	int r = 0;
	double start_time = __get_time_ns(), time_with_lock = 0.0,
		   time_to_drain = 0.0, time_to_commit_state_update = 0.0, t = 0.0,
		   t2 = 0.0;
	static double time_since_last_flush = 0.0;
	(void)time_with_lock;
	(void)time_to_drain;
	(void)time_to_commit_state_update;
	(void)time_since_last_flush;
	(void)t2;

	/*
	perr("writes since last flush: %lu\n", stats.write_stride);
	stats.write_stride = 0;

	if (time_since_last_flush == 0.0)
		time_since_last_flush = __get_time_ns();
	t2 = __get_time_ns();
	perr("time since last flush: %.3f µs\n",
		 (t2 - time_since_last_flush) / 1e3);
	time_since_last_flush = t2;
	*/

	// Need to grab lock before signaling to start drain, because otherwise
	// we might end up with a race condition where we set draining_queue==1 but
	// the bg thread was in the middle of a write and now suddenly skips the
	// block writeback because draining_queue!=0, which would mean that we would
	// complete the update but not the block write, subsequently leading to a
	// failed verification on the next read of the block.
	pthread_mutex_lock(&data_fd_lock);
	if (bg_thread_rate > 0)
		draining_queue = 1;
	pthread_mutex_unlock(&data_fd_lock);
	pdebug0("Starting device flush.\n");

	// We do block write-outs during device_write now instead of during drain,
	// so this is really a no-op.
	if (bg_thread_rate > 0) {
		ready_fsync = 0;
		while (ready_fsync == 0) {
			//
		}
		pdebug0("Ready fsync\n");
	}

	// Call fsync on data_fd to make sure data is persistent.
	r = fsync(data_fd);

	t = __get_time_ns();
	pdebug0("Done device flush.\nStarting queue drain.\n");
	time_with_lock = (t - start_time) / 1e3;
	start_time = t;

	// Wait for queue drain in background to finish.
	int n;
	(void)n;
	if (bg_thread_rate > 0) {
		n = num_to_drain;
		while (mt_queue_empty != 1) {
			if ((int)(num_to_drain * 100.0 / n) % 10 == 0) {
				pdebug0("num_to_drain: %d reqs\n", n);
			}
		}
		draining_queue = 0;
		t = __get_time_ns();
		time_to_drain = (t - start_time) / 1e3;
	}

	perr("time to fsync: %.3f µs\n", time_with_lock);
	if (bg_thread_rate > 0)
		perr("delta time to drain: %.3f µs\n", time_to_drain);

	// After we flush the data and drain the queue to get the latest root
	// (state), to ensure full rollback protection we need to commit the state
	// update. Typically this is done by binding the root to a tamper-resistant
	// counter. We simulate it by temporarily putting the main thread to sleep
	// (e.g., for 5ms).
	if (enable_mt) {
		usleep(5000);
		time_to_commit_state_update = (__get_time_ns() - t) / 1e3;
		perr("delta time to commit state update: %.3f µs\n",
			 time_to_commit_state_update);
	}

	if (r != 0)
		return errno;

	if (bg_thread_rate > 0)
		pdebug0("Done queue drain.\n\n");

	return 0;
}

static int device_ioctl(uint32_t command, void *argument,
						struct bdus_ctx *ctx) {
	int data_fd = *((int *)ctx->private_data);
	int result = 0;

	if (pthread_mutex_lock(&data_fd_lock) != 0)
		perr_and_abort1();

	result = ioctl(data_fd, (unsigned long)command, argument);

	if (pthread_mutex_unlock(&data_fd_lock) != 0)
		perr_and_abort1();

	if (result == -1)
		return errno;

	pdebug0("Done device ioctl.\n");

	return 0;
}

const struct bdus_ops device_ops = {
	.read = device_read,
	.write = device_write,
	.flush = device_flush,
	.ioctl = device_ioctl,
};

const struct bdus_attrs device_attrs = {
	// enable parallel request processing
	.max_concurrent_callbacks = 1,
};

bool configure_device(int fd, struct bdus_ops *ops, struct bdus_attrs *attrs) {
	// Mirror the size, logical block size, and physical block size of the
	// underlying device.
	if (ioctl(fd, BLKGETSIZE64, &attrs->size) != 0)
		return false;
	if (ioctl(fd, BLKSSZGET, &attrs->logical_block_size) != 0)
		return false;
	if (ioctl(fd, BLKPBSZGET, &attrs->physical_block_size) != 0)
		return false;

	return true;
}
