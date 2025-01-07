/**
 * This code is for reading and writing hashes on disk. It lays hashes out
 * linearly on disk based on the node ID and the size of the node struct. Leaf
 * nodes, internal nodes, and the root are stored on separate files/disks.
 */
#include <cassert>
#include <cstddef>
#include <fcntl.h>

#include "common.h"
#include "disk.h"
#include "trace.h"

int read_meta_from_disk(mt_node_t *node) {
	assert(leaf_meta_fd > 0);
	assert(internal_meta_fd > 0);

	if (stats.active_io_type == 0)
		stats.num_meta_disk_reads_from_blk_reads++;
	else if (stats.active_io_type == 1)
		stats.num_meta_disk_reads_from_blk_writes++;

	if (node->node_id == mt.root.node_id) {
		if (stats.active_io_type == 0)
			stats.num_meta_root_disk_reads_from_blk_reads++;
		else if (stats.active_io_type == 1)
			stats.num_meta_root_disk_reads_from_blk_writes++;
	}

	int fd = -1;
	uint64_t meta_blk_loc, abs_off, meta_blk_idx_loc;
	char meta_buffer[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	size_t hash_sz, meta_sz;
	uint64_t off = 0;
	uint64_t node_idx = 0;
	double start_time = __get_time_ns(), end_time = 0.0;

	// Note: Blocks are indexed from [0 -> NUM_BLKS-1], while internal nodes
	// are repositioned at the end of the range and are indexed from
	// [UINT64_MAX-NUM_BLKS -> UINT64_MAX]. So when we need to reach out to
	// disk, we can easily determine whether or not the node is leaf/internal
	// based on the given node_id, then select the correct fd accordingly. We
	// compute the offset for leaves by using the node_id directly, and for
	// internal nodes by subtracting the node_id from UINT64_MAX.
	if (IS_INTERNAL_NODE(node->node_id)) {
		fd = internal_meta_fd;
		node_idx = UINT64_MAX - node->node_id;
		meta_blk_loc = node_idx / (BLK_SIZE / ON_DISK_INTERNAL_NODE_SIZE);
		meta_blk_idx_loc =
			(node_idx % (BLK_SIZE / ON_DISK_INTERNAL_NODE_SIZE)) *
			ON_DISK_INTERNAL_NODE_SIZE;
		abs_off =
			(meta_blk_loc * BLK_SIZE) + (use_chunked_io ? 0 : meta_blk_idx_loc);
		if (abs_off >= NUM_INTERNAL_META_BLKS2 * BLK_SIZE)
			perr_and_abort1();
		hash_sz = HASH_SIZE;
		meta_sz = ON_DISK_INTERNAL_NODE_SIZE;
	} else {
		fd = leaf_meta_fd;
		node_idx = node->node_id;
		meta_blk_loc = node_idx / (BLK_SIZE / ON_DISK_LEAF_NODE_SIZE);
		meta_blk_idx_loc = (node_idx % (BLK_SIZE / ON_DISK_LEAF_NODE_SIZE)) *
						   ON_DISK_LEAF_NODE_SIZE;
		abs_off =
			(meta_blk_loc * BLK_SIZE) + (use_chunked_io ? 0 : meta_blk_idx_loc);
		if (abs_off >= NUM_LEAF_META_BLKS * BLK_SIZE)
			perr_and_abort1();
		hash_sz = MAC_SIZE;
		meta_sz = ON_DISK_LEAF_NODE_SIZE;
	}

	if (enable_trace)
		record_blk_read(meta_blk_loc, 1);

	if (node->node_id == mt.root.node_id) {
		if (__do_read(root_fd, meta_buffer, 0,
					  use_chunked_io ? BLK_SIZE : meta_sz) != 0)
			perr_and_abort1();
	} else {
		if (__do_read(fd, meta_buffer, abs_off,
					  use_chunked_io ? BLK_SIZE : meta_sz) != 0)
			perr_and_abort1();
	}

	off = use_chunked_io ? meta_blk_idx_loc : 0;
	if (node->is_leaf) {
		memcpy(node->iv, meta_buffer + off, IV_SIZE);
		off += IV_SIZE;
	}
	memcpy(node->hash, meta_buffer + off, hash_sz);
	off += hash_sz;
	node->arity = FIXED_ARITY;
	if (!node->is_leaf) {
		memcpy(node->children, meta_buffer + off,
			   sizeof(uint64_t) * node->arity);
		off += sizeof(uint64_t) * node->arity;
	}
	memcpy(&node->parent, meta_buffer + off, sizeof(uint64_t));
	off += sizeof(uint64_t);
	if (use_chunked_io)
		assert((off - meta_blk_idx_loc) == meta_sz);
	else
		assert(off == meta_sz);

	end_time = __get_time_ns();
	running_metadata_read_lat += (end_time - start_time);

	return 0;
}

int write_meta_to_disk(mt_node_t *node) {
	assert(leaf_meta_fd > 0);
	assert(internal_meta_fd > 0);

	// Note: For writes, we must do a read-modify-write, but for
	// the purposes of discussing write amplification, we count the number of
	// calls to this function.
	if (stats.active_io_type == 0)
		stats.num_meta_disk_writes_from_blk_reads++;
	else if (stats.active_io_type == 1)
		stats.num_meta_disk_writes_from_blk_writes++;

	if (node->node_id == mt.root.node_id) {
		if (stats.active_io_type == 0)
			stats.num_meta_root_disk_writes_from_blk_reads++;
		else if (stats.active_io_type == 1)
			stats.num_meta_root_disk_writes_from_blk_writes++;
	}

	int fd = -1;
	uint64_t meta_blk_loc, abs_off, meta_blk_idx_loc;
	char meta_buffer[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	size_t hash_sz, meta_sz;
	uint64_t off = 0;
	uint64_t node_idx = 0;
	double start_time = __get_time_ns(), end_time = 0.0;

	if (IS_INTERNAL_NODE(node->node_id)) {
		fd = internal_meta_fd;
		node_idx = UINT64_MAX - node->node_id;
		meta_blk_loc = node_idx / (BLK_SIZE / ON_DISK_INTERNAL_NODE_SIZE);
		meta_blk_idx_loc =
			(node_idx % (BLK_SIZE / ON_DISK_INTERNAL_NODE_SIZE)) *
			ON_DISK_INTERNAL_NODE_SIZE;
		abs_off =
			(meta_blk_loc * BLK_SIZE) + (use_chunked_io ? 0 : meta_blk_idx_loc);
		if (abs_off >= NUM_INTERNAL_META_BLKS2 * BLK_SIZE)
			perr_and_abort1();
		hash_sz = HASH_SIZE;
		meta_sz = ON_DISK_INTERNAL_NODE_SIZE;
	} else {
		fd = leaf_meta_fd;
		node_idx = node->node_id;
		meta_blk_loc = node_idx / (BLK_SIZE / ON_DISK_LEAF_NODE_SIZE);
		meta_blk_idx_loc = (node_idx % (BLK_SIZE / ON_DISK_LEAF_NODE_SIZE)) *
						   ON_DISK_LEAF_NODE_SIZE;
		abs_off =
			(meta_blk_loc * BLK_SIZE) + (use_chunked_io ? 0 : meta_blk_idx_loc);
		if (abs_off >= NUM_LEAF_META_BLKS * BLK_SIZE)
			perr_and_abort1();
		hash_sz = MAC_SIZE;
		meta_sz = ON_DISK_LEAF_NODE_SIZE;
	}

	if (enable_trace)
		record_blk_write(meta_blk_loc, 1);

	if (use_chunked_io) {
		if (__do_read(fd, meta_buffer, abs_off, BLK_SIZE) != 0)
			perr_and_abort1();
	}

	off = use_chunked_io ? meta_blk_idx_loc : 0;
	if (node->is_leaf) {
		memcpy(meta_buffer + off, node->iv, IV_SIZE);
		off += IV_SIZE;
	}
	memcpy(meta_buffer + off, node->hash, hash_sz);
	off += hash_sz;
	if (!node->is_leaf) {
		memcpy(meta_buffer + off, node->children,
			   sizeof(uint64_t) * node->arity);
		off += sizeof(uint64_t) * node->arity;
	}
	memcpy(meta_buffer + off, &node->parent, sizeof(uint64_t));
	off += sizeof(uint64_t);

	if (use_chunked_io)
		assert((off - meta_blk_idx_loc) == meta_sz);
	else
		assert(off == meta_sz);

	if (node->node_id == mt.root.node_id) {
		if (__do_write(root_fd, meta_buffer, 0,
					   use_chunked_io ? BLK_SIZE : meta_sz) != 0)
			perr_and_abort1();
	} else {
		if (__do_write(fd, meta_buffer, abs_off,
					   use_chunked_io ? BLK_SIZE : meta_sz) != 0)
			perr_and_abort1();
	}

	end_time = __get_time_ns();
	running_metadata_write_lat += (end_time - start_time);

	return 0;
}
