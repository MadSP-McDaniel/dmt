#ifndef MT_H
#define MT_H

#include <atomic>
#include <deque>
#include <errno.h>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "common.h"

#define INVALID_BLK_ID UINT64_MAX
#define INVALID_NODE_ID UINT64_MAX

#define IS_INTERNAL_NODE(n) (n >= NUM_BLKS)
#define IS_LEAF_NODE(n) (n < NUM_BLKS)

#define INTERNAL_NODE_ID(i) (UINT64_MAX - 1 - (i))

// Add space for iv, mac, and parent
#define ON_DISK_LEAF_NODE_SIZE (IV_SIZE + MAC_SIZE + sizeof(uint64_t))

// Add space for (SHA256) hash, parent, and children
#define ON_DISK_INTERNAL_NODE_SIZE                                             \
	(HASH_SIZE + sizeof(uint64_t) + FIXED_ARITY * sizeof(uint64_t))

// Add space for last + mt root block
#define NUM_LEAF_META_BLKS                                                     \
	((NUM_BLKS / (BLK_SIZE / ON_DISK_LEAF_NODE_SIZE)) + 1 + 1)

// This is a conservative estimate of how much space we need for metadata for
// internal nodes. We needed this before to be able to fallocate prior to MT
// initialization (otherwise we run into hole-filling issues), but we dont
// fallocate anymore because we use separate metadata disks, so this is mostly
// for some sanity checks now. We should try to calculate this at compile/init
// time at some point (depends on tree type specified).
#define NUM_INTERNAL_META_BLKS2                                                \
	(((NUM_BLKS * 2 - 1) / (BLK_SIZE / ON_DISK_INTERNAL_NODE_SIZE)) + 1)

typedef struct merkle_tree_node {
	///////////////
	// The following fields are required to be serialized to disk, the remaining
	// can be determined at runtime. Note that we fix the field sizes for now
	// for simplicity.
	uint8_t iv[IV_SIZE];
	uint8_t hash[HASH_SIZE];
	uint64_t parent, children[FIXED_ARITY];
	///////////////

	bool is_leaf;
	uint64_t arity;

	// Used for huffman tree.
	uint64_t blkid;
	int64_t freq;

	uint64_t node_id;

	// Actually used as hotness counters for DMTs.
	int64_t _height;

	// Used during cache evictions.
	uint8_t dirty;
} mt_node_t;

typedef struct mt_req {
	mt_node_t curr_node;
	double req_time;
	int type;
	int data_fd;
	uint8_t new_hash[HASH_SIZE];
	uint8_t new_iv[IV_SIZE];
	bool pending_transform;
} mt_req_t;

typedef struct mt_node_summary {
	uint64_t node_id;
	uint64_t freq;
} mt_node_summary_t;

typedef enum merkle_tree_type {
	NOENC_NOINT = -2,
	ENC_NOINT,			// enc but no mt
	PERFECT,			// perfect tree, any fixed arity
	PARTIAL_SKEW_RIGHT, // partially skewed right, 2ary
	FULL_SKEW_RIGHT,	// fully skewed right, 2ary
	HUFFMAN,			// huffman tree, any fixed arity
	DMT,				// any fixed arity
	VARIABLE_ARITY,
	MAX_MT_TYPE,
} mt_type_t;

typedef struct merkle_tree {
	mt_type_t type;
	uint32_t status;
	uint64_t n;
	uint64_t height;
	uint64_t num_nodes;
	mt_node_t root;
} merkle_tree_t;

extern merkle_tree_t mt;

struct mtn_compare {
	bool operator()(mt_node_t *l, mt_node_t *r) { return (l->freq > r->freq); }
};

struct mts_compare {
	bool operator()(mt_node_summary_t &l, mt_node_summary_t &r) {
		return (l.freq > r.freq);
	}
};

// Synchronization structures
extern pthread_mutex_t queue_lock, data_fd_lock, gcry_lock, tracer_lock,
	cache_lock;
extern std::deque<mt_req> mt_queue;
extern std::atomic<int> waiting_for_low_watermark;
extern std::atomic<int> mt_queue_empty, draining_queue, num_to_drain,
	ready_fsync;
extern std::map<uint64_t, mt_req> mt_queue_latest_idx;

// Get/put tree node to cache/disk
int put_mt_node(mt_node_t *node);
mt_node_t *_get_mt_node_low_level(uint64_t node_id, bool verify, bool is_leaf,
								  const bool expect_cached, bool *was_cached,
								  bool dont_recache);
mt_node_t *_get_mt_node(uint64_t node_id, bool verify, bool is_leaf,
						const bool expect_cached = false,
						bool *was_cached = NULL, bool dont_recache = false);
mt_node_t *get_mt_node(uint64_t node_id, bool verify = true,
					   const bool expect_cached = false,
					   bool *was_cached = NULL, bool dont_cache = false);

int transform_tree(mt_node_t *starting_node, uint64_t blk_id, bool start_left);

// Top-level crypto routines
int enc(char *buffer, uint32_t size, uint64_t *aad, uint8_t *iv, uint8_t *mac);
int dec(char *buffer, uint32_t size, uint64_t *aad, uint8_t *iv, uint8_t *mac);
int verify_mt(mt_node_t *, uint64_t blk_id, uint8_t *mac, bool transform,
			  bool allow_early_ret = true);
int update_mt(mt_node_t *, uint64_t blk_id, uint8_t *mac, bool transform);

// Lifecycle routines
int init_mt_generic(int, mt_type_t, uint64_t);
int init_variable_arity_tree(int, mt_type_t, uint64_t);
int init_block_hashes(int);
int init_huffman_tree(int, int64_t *, uint64_t, bool);
int init_dmt(int, uint64_t);
void cleanup_mt_node(mt_node_t *);
void cleanup_caches();
void reinit_caches();
void warm_caches(int64_t *);
void flush_caches();
int init_crypto();
int flush_mt(void);

// Logging
void log_meta(uint8_t *, const char *, uint8_t *, int);
void log_node_info(mt_node_t *);
void get_mt_info(int64_t * = NULL, int64_t * = NULL, double * = NULL,
				 int64_t * = NULL, int64_t * = NULL, int64_t * = NULL);
std::string mt_type_to_str(mt_type_t, uint64_t);
double get_secure_cache_hit_rate();
std::string log_perf_stats();

#endif /* MT_H */
