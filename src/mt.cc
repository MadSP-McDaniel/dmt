/**
 * This code is the core implementation of the block-level merkle hash tree. It
 * supports 4 different modes of operations: no merkle tree, balanced tree,
 * optimal tree, and dmt. For dmts, it transforms the tree dynamically based on
 * some statistics collected at runtime. It also encrypts block data with
 * AES-GCM. The main lifecycle of the code is as follows: 1) init tree; 2)
 * handle update/verify call from dmt_write/dmt_read by recursively fetching
 * nodes from cache/disk and computing hashes (+ de/encrypting the data blocks);
 * 3) flush mt and cleanup crypto.
 *
 * The merkle tree is stored on disk on two separate block devices, one for leaf
 * nodes and one for internal nodes. The data layout of the merkle tree follows
 * standard approaches, where the tree is flattened and stored in a contiguous
 * array of blocks. This allows for easy retrieval from disk and indexing while
 * in memory, because hash locations can be computed deterministically.
 */
#include <algorithm>
#include <cassert>
#include <cmath>
#include <gcrypt.h>
#include <iostream>
#include <map>
#include <queue>
#include <unistd.h>

#include "cache.h"
#include "mt.h"
#include "mt_support.h"

merkle_tree_t mt;

pthread_mutex_t queue_lock, data_fd_lock, gcry_lock, tracer_lock, cache_lock;
std::atomic<int> waiting_for_low_watermark;
std::atomic<int> mt_queue_empty, draining_queue, num_to_drain, ready_fsync;
std::map<uint64_t, mt_req> mt_queue_latest_idx;

static gcry_cipher_hd_t cipher;
static gcry_md_hd_t sha256_h;
static cache_t secure_cache, insecure_cache;

static void reset_perf_counters() {
	reset_cache_counters(&secure_cache);
	reset_cache_counters(&insecure_cache);

	memset(&stats, 0, sizeof(stats_t));
}

int put_mt_node(mt_node_t *node) {
	pthread_mutex_lock(&cache_lock);
	// Check if node_id is valid.
	if (node->node_id == INVALID_NODE_ID)
		perr_and_abort1();

	// Check if node is current root, if so then save old root to disk.
	if (node->node_id == mt.root.node_id) {
		// Always save *old* root to disk (if root node is initialized).
		// Otherwise we might run into an issue where a new node is set as root,
		// but the old root hash was never updated on disk before the change.
		if (enable_mt && (mt.status == 1) && (bg_thread_rate == 0) &&
			(write_meta_to_disk(&mt.root) != 0))
			perr_and_abort1();
	}

	// Now check if node is the new root, if so then update in mem and remove
	// the node from cache if possible. Note that we identify the *new* root
	// node by its parent (and the *old* root node by its node_id) instead since
	// the node_id might change from rotations.
	if (node->parent == INVALID_NODE_ID) {
		mt.root = *node;
		if (pop_node(&secure_cache, node->node_id, false) != 0)
			perr_and_abort1();
		pthread_mutex_unlock(&cache_lock);

		return 0;
	}

	log_node_info(node);

	// Otherwise just put the node into cache. We assume that put is called
	// whenever a node is updated somehow, and therefore we should mark it as
	// dirty. Note that caller owns the ptr and should ensure it is cleaned up.
	node->dirty = 1;
	if (put_cache(&secure_cache, node) != 0)
		perr_and_abort1();

	pthread_mutex_unlock(&cache_lock);

	return 0;
}

mt_node_t *_get_mt_node_low_level(uint64_t node_id, bool verify, bool is_leaf,
								  const bool expect_cached, bool *was_cached,
								  bool dont_recache) {
	mt_node_t *node = NULL;

	pthread_mutex_lock(&cache_lock);

	// Try to fetch node from the cache. If not present, return NULL.
	node =
		get_cache_low_level(&secure_cache, node_id, dont_recache, was_cached);

	pthread_mutex_unlock(&cache_lock);

	return node;
}

mt_node_t *_get_mt_node(uint64_t node_id, bool verify, bool is_leaf,
						const bool expect_cached, bool *was_cached,
						bool dont_recache) {
	mt_node_t *node = NULL;

	pthread_mutex_lock(&cache_lock);

	// Not supporting expect_cached==true for now, because we dont use it. Need
	// to remove this arg.
	if (expect_cached)
		perr_and_abort1();

	// Always try to signal callers whether the node was cached or not (if it is
	// not, then it will be reflected below).
	if (was_cached)
		*was_cached = false;

	// Fetch node from the storage hierarchy.
	node = get_cache(&secure_cache, node_id, dont_recache, was_cached);
	if (!node)
		perr_and_abort1();

	pthread_mutex_unlock(&cache_lock);

	return node;
}

mt_node_t *get_mt_node(uint64_t node_id, bool verify, const bool expect_cached,
					   bool *was_cached_out, bool dont_recache) {
	mt_node_t *node_copy = NULL;
	bool was_cached_tmp;

	if (expect_cached)
		perr_and_abort1();

	// Check if node_id is valid.
	if (node_id == INVALID_NODE_ID)
		perr_and_abort1();

	// If the specified node_id is root, just return a copy directly because we
	// dont cache root in the regular caches (i.e., it is stored statically in
	// secure memory).
	if (node_id == mt.root.node_id) {
		node_copy = copy_mt_node(&mt.root);

		if (was_cached_out)
			*was_cached_out = true;

		log_node_info(node_copy);

		return node_copy;
	}

	// Otherwise node_id is not root, try to fetch from cache/disk.
	was_cached_tmp = false;
	if (IS_INTERNAL_NODE(node_id))
		node_copy = _get_mt_node(node_id, verify, false, expect_cached,
								 &was_cached_tmp, dont_recache);
	else
		node_copy = _get_mt_node(node_id, verify, true, expect_cached,
								 &was_cached_tmp, dont_recache);
	if (was_cached_out)
		*was_cached_out = was_cached_tmp;

	// Expected node to be cached but it wasnt. Note: Sanity check, but we dont
	// expect cached ATM, so remove this at some point.
	if (expect_cached && !*was_cached_out)
		perr_and_abort1();

	// Reauthenticate the node before we put it in the secure cache if: 1) MT is
	// initialized, 2) the caller requests to verify the get, and 3) the node
	// was not cached.
	if (enable_mt && (mt.status == 1) && verify && !was_cached_tmp) {
		stats.num_reauths++;
		if (IS_INTERNAL_NODE(node_id)) {
			if (verify_mt(node_copy, UINT64_MAX, NULL, false, true) != 0)
				perr_and_abort1();
		} else {
			uint8_t *mac_copy = (uint8_t *)calloc(MAC_SIZE, sizeof(uint8_t));
			if (!mac_copy)
				perr_and_abort1();

			memcpy(mac_copy, node_copy->hash, MAC_SIZE);
			if (verify_mt(NULL, node_copy->blkid, mac_copy, false, true) != 0)
				perr_and_abort1();
		}
	}

	// This should never fail for our experiment purposes. If so, just abort and
	// debug it.
	if (!node_copy)
		perr_and_abort1();

	log_node_info(node_copy);

	return node_copy;
}

int enc(char *buffer, uint32_t size, uint64_t *aad, uint8_t *iv, uint8_t *mac) {
	gcry_error_t err;

	pthread_mutex_lock(&gcry_lock);

	err = gcry_cipher_reset(cipher);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_setiv(cipher, iv, IV_SIZE);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_authenticate(cipher, aad, sizeof(uint64_t));
	if (err)
		perr_and_abort1();

	err = gcry_cipher_encrypt(cipher, buffer, size, NULL, 0);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_gettag(cipher, mac, MAC_SIZE);
	if (err)
		perr_and_abort1();

	pthread_mutex_unlock(&gcry_lock);

	return 0;
}

int dec(char *buffer, uint32_t size, uint64_t *aad, uint8_t *iv, uint8_t *mac) {
	gcry_error_t err;

	pthread_mutex_lock(&gcry_lock);

	err = gcry_cipher_reset(cipher);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_setiv(cipher, iv, IV_SIZE);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_authenticate(cipher, aad, sizeof(uint64_t));
	if (err)
		perr_and_abort1();

	err = gcry_cipher_decrypt(cipher, buffer, size, NULL, 0);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_checktag(cipher, mac, MAC_SIZE);
	if (err)
		perr_and_abort1();

	pthread_mutex_unlock(&gcry_lock);

	return 0;
}

static int __sha256(const uint8_t *key, uint64_t keylen, const uint8_t *data,
					uint64_t datalen, uint8_t *sha256_digest) {
	unsigned char *tmp;
	size_t dlen;

	pthread_mutex_lock(&gcry_lock);

	if (!sha256_digest)
		perr_and_abort1();

	gcry_md_reset(sha256_h);
	gcry_md_write(sha256_h, data, datalen);
	tmp = gcry_md_read(sha256_h, GCRY_MD_SHA256);
	if (!tmp)
		perr_and_abort1();
	dlen = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	memcpy(sha256_digest, tmp, dlen);

	pthread_mutex_unlock(&gcry_lock);

	return 0;
}

static int _sha256(mt_node_t *curr_node, const bool expect_cached = false,
				   bool *was_cached = NULL, bool verify = true) {
	int r;
	uint64_t off = 0, total_hash_sz = 0;
	mt_node_t *children[FIXED_ARITY] = {0};

	// Fetch child hashes, concatenate them, then compute sha256 hash.
	for (uint64_t i = 0; i < curr_node->arity; i++) {
		children[i] = get_mt_node(curr_node->children[i], verify, expect_cached,
								  was_cached);
		if (children[i]->is_leaf)
			total_hash_sz += MAC_SIZE;
		else
			total_hash_sz += HASH_SIZE;
	}

	uint8_t data[HASH_SIZE * FIXED_ARITY] = {0};
	for (uint64_t i = 0; i < curr_node->arity; i++) {
		if (children[i]->is_leaf) {
			memcpy(data + off, children[i]->hash, MAC_SIZE);
			off += MAC_SIZE;
		} else {
			memcpy(data + off, children[i]->hash, HASH_SIZE);
			off += HASH_SIZE;
		}
	}

	r = __sha256((uint8_t *)HASH_KEY, HASH_KEY_SIZE, data, total_hash_sz,
				 curr_node->hash);
	if (r)
		perr_and_abort1();

	for (uint64_t i = 0; i < curr_node->arity; i++)
		cleanup_mt_node(children[i]);

	return 0;
}

static int _sha2562(mt_node_t *curr_node,
					mt_node_t *new_children[FIXED_ARITY]) {
	int r;
	uint64_t off = 0, total_hash_sz = 0;

	// Child hashes are explicitly provided already, so just concatenate them
	// and compute sha256 hash.
	for (uint64_t i = 0; i < curr_node->arity; i++) {
		if (new_children[i]->is_leaf)
			total_hash_sz += MAC_SIZE;
		else
			total_hash_sz += HASH_SIZE;
	}

	uint8_t data[HASH_SIZE * FIXED_ARITY] = {0};
	for (uint64_t i = 0; i < curr_node->arity; i++) {
		if (new_children[i]->is_leaf) {
			memcpy(data + off, new_children[i]->hash, MAC_SIZE);
			off += MAC_SIZE;
		} else {
			memcpy(data + off, new_children[i]->hash, HASH_SIZE);
			off += HASH_SIZE;
		}
	}

	r = __sha256((uint8_t *)HASH_KEY, HASH_KEY_SIZE, data, total_hash_sz,
				 curr_node->hash);
	if (r)
		perr_and_abort1();

	return 0;
}

static int hash_node(mt_node_t *curr_node, const bool expect_cached = false,
					 bool *was_cached = NULL, bool verify = true) {
	// Only compute sha256 hash on internal nodes, leaf hashes fetched from
	// disk.
	if (curr_node->is_leaf)
		perr_and_abort1();
	if (!curr_node->hash)
		perr_and_abort1();
	if (!curr_node->children)
		perr_and_abort1();

	return _sha256(curr_node, expect_cached, was_cached, verify);
}

static int hash_node2(mt_node_t *curr_node,
					  mt_node_t *new_children[FIXED_ARITY]) {
	// Only compute sha256 hash on internal nodes, leaf hashes fetched from
	// disk.
	if (curr_node->is_leaf)
		perr_and_abort1();
	if (!curr_node->hash)
		perr_and_abort1();
	if (!curr_node->children)
		perr_and_abort1();

	return _sha2562(curr_node, new_children);
}

static void left_rotate(mt_node_t *x, bool swap_gchildren) {
	mt_node_t *y = NULL, *yc0 = NULL, *xpar = NULL, *yc1 = NULL, *xc0 = NULL,
			  *xsib = NULL, *tmp = NULL;
	u_int64_t tmp_node_id;
	uint8_t *new_xpar_hash = NULL;
	uint8_t old_xpar_hash[HASH_SIZE] = {0};
	mt_node_t *new_children[2] = {NULL, NULL};

	// Rotate should only be called on a node with a (at least one) child, so we
	// expect y to exist.
	y = get_mt_node(x->children[1], true, false, NULL);
	if (!y)
		perr_and_abort1();

	// Update subtree heights. Note: x's height will simply decrease by 1 and
	// y's height will increase by 1.
	x->_height -= 1;
	y->_height += 1;

	// Rotate is only called on a node with at least one grandchild (because
	// splay is called on parent and rotate is called on that node's
	// parent), so this case should never happen, and moreover it
	// complicates the way we update the hash below.
	if (!y->children || (y->children[0] == INVALID_NODE_ID) ||
		(y->children[1] == INVALID_NODE_ID))
		perr_and_abort1();

	yc0 = get_mt_node(y->children[0], true, false, NULL);
	yc1 = get_mt_node(y->children[1], true, false, NULL);

	if (swap_gchildren) {
		tmp_node_id = yc0->node_id;
		tmp = yc0;

		y->children[0] = y->children[1];
		yc0 = yc1;

		y->children[1] = tmp_node_id;
		yc1 = tmp;
	}
	// update heuristic counters
	yc1->_height += 1;

	x->children[1] = y->children[0];
	yc0->parent = x->node_id;
	y->parent = x->parent;

	// update the sibling under x
	if (x->children[0] != INVALID_NODE_ID) {
		xc0 = get_mt_node(x->children[0], true, false, NULL);
		xc0->_height -= 1;
	}

	if (x->parent != INVALID_NODE_ID) {
		xpar = get_mt_node(x->parent, true, false, NULL);
		if (x->node_id == xpar->children[0]) {
			xpar->children[0] = y->node_id;
			xsib = get_mt_node(xpar->children[1], true, false, NULL);
		} else {
			xpar->children[1] = y->node_id;
			xsib = get_mt_node(xpar->children[0], true, false, NULL);
		}
	}

	if (y->children)
		y->children[0] = x->node_id;
	x->parent = y->node_id;

	// Update the hashes of the nodes involved in the rotation directly, then
	// proceed below with the update_mt from the (new) root of our rotation
	// subtree (ie y). The effect will be basically that update_mt handles
	// updates initiated from both device_write and *_rotate calls in the same
	// way. This is the easiest way to handle rotations.

	// directly update x first
	new_children[0] = xc0;
	new_children[1] = yc0;
	if (hash_node2(x, new_children) != 0)
		perr_and_abort1();

	// Only persist the updates (by calling put) after all calls to get_mt_node
	// (but before update_mt) to persist everything above the rotated subtree.
	if (xc0) {
		put_mt_node(xc0);
		cleanup_mt_node(xc0);
		xc0 = NULL;
	}

	if (yc0) {
		put_mt_node(yc0);
		cleanup_mt_node(yc0);
		yc0 = NULL;
	}

	// now update y (x's new parent)
	new_children[0] = x;
	new_children[1] = yc1;
	if (hash_node2(y, new_children) != 0)
		perr_and_abort1();

	put_mt_node(x);

	if (yc1) {
		put_mt_node(yc1);
		cleanup_mt_node(yc1);
		yc1 = NULL;
	}

	// We dont need to update mt any further if y is the new root.
	if (y->parent == INVALID_NODE_ID) {
		put_mt_node(y);
		cleanup_mt_node(y);
		y = NULL;
		goto cleanup;
	}

	// Otherwise we know that y is not the new root, so we need to update xpar.
	memcpy(old_xpar_hash, xpar->hash, HASH_SIZE);
	if (xpar->children[0] == y->node_id) {
		new_children[0] = y;
		new_children[1] = xsib;
	} else {
		new_children[0] = xsib;
		new_children[1] = y;
	}
	if (hash_node2(xpar, new_children) != 0)
		perr_and_abort1();

	put_mt_node(y);
	cleanup_mt_node(y);
	y = NULL;

	put_mt_node(xsib);
	cleanup_mt_node(xsib);
	xsib = NULL;

	// We dont need to update mt any further if xpar is the root.
	if (!xpar) // sanity check
		perr_and_abort1();
	if (xpar->parent == INVALID_NODE_ID)
		goto cleanup;

	new_xpar_hash = (uint8_t *)calloc(HASH_SIZE, sizeof(uint8_t));
	if (!new_xpar_hash)
		perr_and_abort1();
	memcpy(new_xpar_hash, xpar->hash, HASH_SIZE);
	memcpy(xpar->hash, old_xpar_hash, HASH_SIZE);
	if (update_mt(xpar, UINT64_MAX, new_xpar_hash, false) != 0)
		perr_and_abort1();

cleanup:
	if (xpar) {
		// redundant - mac is swapped in update_mt and xpar is put; remove this
		// at some point
		put_mt_node(xpar);
		cleanup_mt_node(xpar);
		xpar = NULL;
	}
}

static void right_rotate(mt_node_t *x, bool swap_gchildren) {
	mt_node_t *y = NULL, *yc1 = NULL, *xpar = NULL, *yc0 = NULL, *xc1 = NULL,
			  *xsib = NULL, *tmp = NULL;
	u_int64_t tmp_node_id;
	uint8_t *new_xpar_hash = NULL;
	uint8_t old_xpar_hash[HASH_SIZE] = {0};
	mt_node_t *new_children[2] = {NULL, NULL};

	y = get_mt_node(x->children[0], true, false, NULL);
	if (!y)
		perr_and_abort1();

	x->_height -= 1;
	y->_height += 1;

	if (!y->children || (y->children[0] == INVALID_NODE_ID) ||
		(y->children[1] == INVALID_NODE_ID))
		perr_and_abort1();

	yc1 = get_mt_node(y->children[1], true, false, NULL);
	yc0 = get_mt_node(y->children[0], true, false, NULL);

	if (swap_gchildren) {
		tmp_node_id = yc0->node_id;
		tmp = yc0;

		y->children[0] = y->children[1];
		yc0 = yc1;

		y->children[1] = tmp_node_id;
		yc1 = tmp;
	}
	// update heuristic counters
	yc0->_height += 1;

	x->children[0] = y->children[1];
	yc1->parent = x->node_id;
	y->parent = x->parent;

	// update the sibling under x
	if (x->children[1] != INVALID_NODE_ID) {
		xc1 = get_mt_node(x->children[1], true, false, NULL);
		xc1->_height -= 1;
	}

	if (x->parent != INVALID_NODE_ID) {
		xpar = get_mt_node(x->parent, true, false, NULL);
		if (x->node_id == xpar->children[0]) {
			xpar->children[0] = y->node_id;
			xsib = get_mt_node(xpar->children[1], true, false, NULL);
		} else {
			xpar->children[1] = y->node_id;
			xsib = get_mt_node(xpar->children[0], true, false, NULL);
		}
	}

	if (y->children)
		y->children[1] = x->node_id;
	x->parent = y->node_id;

	// directly update x first
	new_children[0] = yc1;
	new_children[1] = xc1;
	if (hash_node2(x, new_children) != 0)
		perr_and_abort1();

	if (yc1) {
		put_mt_node(yc1);
		cleanup_mt_node(yc1);
		yc1 = NULL;
	}

	if (xc1) {
		put_mt_node(xc1);
		cleanup_mt_node(xc1);
		xc1 = NULL;
	}

	// now update y (x's new parent)
	new_children[0] = yc0;
	new_children[1] = x;
	if (hash_node2(y, new_children) != 0)
		perr_and_abort1();

	if (yc0) {
		put_mt_node(yc0);
		cleanup_mt_node(yc0);
		yc0 = NULL;
	}

	put_mt_node(x);

	// We dont need to update mt any further if y is the new root.
	if (y->parent == INVALID_NODE_ID) {
		put_mt_node(y);
		cleanup_mt_node(y);
		y = NULL;
		goto cleanup;
	}

	// Otherwise we know that y is not the new root, so we need to update xpar.
	memcpy(old_xpar_hash, xpar->hash, HASH_SIZE);
	if (xpar->children[0] == y->node_id) {
		new_children[0] = y;
		new_children[1] = xsib;
	} else {
		new_children[0] = xsib;
		new_children[1] = y;
	}
	if (hash_node2(xpar, new_children) != 0)
		perr_and_abort1();

	put_mt_node(y);
	cleanup_mt_node(y);
	y = NULL;

	put_mt_node(xsib);
	cleanup_mt_node(xsib);
	xsib = NULL;

	// We dont need to update mt any further if xpar is the root.
	if (!xpar) // sanity check
		perr_and_abort1();
	if (xpar->parent == INVALID_NODE_ID)
		goto cleanup;

	new_xpar_hash = (uint8_t *)calloc(HASH_SIZE, sizeof(uint8_t));
	if (!new_xpar_hash)
		perr_and_abort1();
	memcpy(new_xpar_hash, xpar->hash, HASH_SIZE);
	memcpy(xpar->hash, old_xpar_hash, HASH_SIZE);
	if (update_mt(xpar, UINT64_MAX, new_xpar_hash, false) != 0)
		perr_and_abort1();

cleanup:
	if (xpar) {
		// redundant - mac is swapped in update_mt and xpar is put; remove this
		// at some point
		put_mt_node(xpar);
		cleanup_mt_node(xpar);
		xpar = NULL;
	}
}

static void splay(mt_node_t *x, uint64_t blk_id, bool start_left) {
	(void)blk_id;
	const double cold_multiplier = -0.5, hot_multiplier = 1e4;
	uint64_t x_node_id = x->node_id;

	// Flag indicating whether to do a full or semi-splay approach
	bool semi_splay = false;

	// Threshold number of accesses before we stop splaying (conditional
	// splaying); set high to always splay.
	static uint64_t splay_iterations = (uint64_t)UINT64_MAX;

	// Threshold number of operations to wait before considering to splay.
	// static uint64_t splay_wait = (uint64_t)0;
	// if (splay_wait > 0) {
	// 	splay_wait--;
	// 	return;
	// }

	uint64_t num_reauths_during_splays_start = stats.num_reauths;

	uint64_t splay_distance = 0;
	if (splay_iterations > 0) {
		splay_iterations--;

		if (((double)rand() / (double)RAND_MAX) < 0.01) {
			if (x->_height < 0)
				splay_distance =
					(uint64_t)std::max(x->_height * cold_multiplier, 1.0);
			else
				splay_distance =
					(uint64_t)std::max(x->_height * hot_multiplier, 1.0);
		}
	} else
		splay_distance = 0;

	if (splay_distance == 0) {
		cleanup_mt_node(x);
		return;
	}

	if ((splay_distance > 0) && (x->parent != INVALID_NODE_ID))
		stats.num_splays++;

	mt_node_t *p, *g, *pc0, *pc1, *xc0, *xc1, *xg0, *xg1;
	p = g = pc0 = pc1 = xc0 = xc1 = xg0 = xg1 = NULL;

	while ((splay_distance > 0) && (x->parent != INVALID_NODE_ID)) {
		splay_distance--;

		// Note: If we _zig_ from left, but start_left==false, then we should
		// swap x's children before rotating. Vice versa if we zig from right.
		// If we _zig-zig_ from left, but start_left==false (the accessed leaf
		// was originally a right child), then we should swap x's children
		// before rotating to ensure that the accessed leaf is promoted two
		// levels. Vice versa if we zig-zig from right. If we _zig-zag_ from
		// either side, all children are promoted/demoted to same level anyway,
		// so doesnt matter.

		cleanup_mt_node(p);
		p = get_mt_node(x->parent, true, false, NULL);

		if (p->parent == INVALID_NODE_ID) {
			if (p->children[0] == x->node_id) {
				// x is left child (zig from left)
				if (!start_left)
					right_rotate(p, true);
				else
					right_rotate(p, false);
			} else {
				// x is right child (zig from right)
				if (start_left)
					left_rotate(p, true);
				else
					left_rotate(p, false);
			}

			goto done_update;
		}

		cleanup_mt_node(g);
		g = get_mt_node(p->parent, true, false, NULL);

		if (p->children[0] == x->node_id && g->children[0] == p->node_id) {
			// x is left child and parent is left child (zig-zig from left)
			right_rotate(g, false);

			cleanup_mt_node(x);
			cleanup_mt_node(p);
			x = get_mt_node(x_node_id, true, false, NULL);
			p = get_mt_node(x->parent, true, false, NULL);

			if (!semi_splay) {
				if (!start_left)
					right_rotate(p, true);
				else
					right_rotate(p, false);
			}
		} else if (p->children[1] == x->node_id &&
				   g->children[1] == p->node_id) {
			// x is right child and parent is right child (zig-zig from right)
			left_rotate(g, false);

			cleanup_mt_node(x);
			cleanup_mt_node(p);
			x = get_mt_node(x_node_id, true, false, NULL);
			p = get_mt_node(x->parent, true, false, NULL);

			if (!semi_splay) {
				if (start_left)
					left_rotate(p, true);
				else
					left_rotate(p, false);
			}
		} else if (p->children[0] == x->node_id &&
				   g->children[1] == p->node_id) {
			// x is left child and parent is right child (zig-zag from left)
			right_rotate(p, false);

			cleanup_mt_node(x);
			cleanup_mt_node(p);
			x = get_mt_node(x_node_id, true, false, NULL);
			p = get_mt_node(x->parent, true, false, NULL);

			left_rotate(p, false);
		} else {
			// x is right child and parent is left child (zig-zag from right)
			left_rotate(p, false);

			cleanup_mt_node(x);
			cleanup_mt_node(p);
			x = get_mt_node(x_node_id, true, false, NULL);
			p = get_mt_node(x->parent, true, false, NULL);

			right_rotate(p, false);
		}

		cleanup_mt_node(g);
		g = NULL;

	done_update:
		cleanup_mt_node(p);
		p = NULL;

		cleanup_mt_node(x);
		x = get_mt_node(x_node_id, true, false, NULL);
	}

	cleanup_mt_node(x);

	stats.num_reauths_during_splay +=
		(stats.num_reauths - num_reauths_during_splays_start);
}

static int transform_tree__dmt(mt_node_t *starting_node,
							   uint64_t associated_blkid, bool start_left) {
	assert(mt.root.parent == INVALID_NODE_ID);

	if (starting_node->node_id == mt.root.node_id)
		return 0;

	if (starting_node->node_id == INVALID_NODE_ID)
		perr_and_abort1();

	// Note that we splay starting at the parent of the accessed leaf
	// node, not the leaf, to maintain a valid hash tree structure. However,
	// regardless of what kind of splay step we do (zig, zig-zig, or zig-zag),
	// we will always promote the actual accessed leaf to some extent.
	splay(starting_node, associated_blkid, start_left);

	return 0;
}

int transform_tree(mt_node_t *starting_node, uint64_t blk_id, bool start_left) {
	switch (mt.type) {
	case DMT:
		return transform_tree__dmt(starting_node, blk_id, start_left);
	case PERFECT:
	case HUFFMAN:
		cleanup_mt_node(starting_node);
		return 0;
	case PARTIAL_SKEW_RIGHT:
	case FULL_SKEW_RIGHT:
	case VARIABLE_ARITY:
	default:
		cleanup_mt_node(starting_node);
		perr_and_abort0("transform not supported");
	}
}

int verify_mt(mt_node_t *_curr_node, uint64_t blk_id, uint8_t *mac,
			  bool pending_transform, bool allow_early_ret) {
	/*
	 * The basic idea with verify_mt is that we do not verify fetched nodes,
	 * instead just accepting them as-is, and proceeding to fetch parent nodes
	 * and computing parent hashes until we reach an authenticated parent or the
	 * root. We will cache all accessed nodes along the way. This avoids having
	 * to recursively re-auth any fetched node during the process of verifying
	 * the original starting node, because as long as the authenticated par/root
	 * checks out, we are good. In a real system, we should have a secure way to
	 * _undo_ the caching of certain nodes if a violation is detected.
	 */

	uint8_t new_par_hash[HASH_SIZE] = {0};
	mt_node_t *curr_node = NULL, *tmp = NULL, *starting_node = NULL;
	uint64_t splay_assoc_blkid = 0;
	bool skip_done = true;
	bool start_left = false;
	bool find_start_done = false;
	bool was_cached = false;

	// Either verify_mt is called when a leaf node is accessed (mac!=NULL,
	// ptr==NULL), or when an internal node is accessed (mac==NULL, ptr!=NULL).
	// Note: If called directly from device_read, then pending_transform==true,
	// otherwise if called recursively from a call to get_mt_node, then
	// pending_transform==false.
	assert((_curr_node && !mac) || (!_curr_node && mac));

	// Check what case we are dealing with to prepare for the main loop.
	if (!_curr_node && mac) {
		curr_node = get_mt_node(blk_id, false);
		curr_node->_height++;
	} else {
		curr_node = _curr_node;
		skip_done = false;
	}

	// Sanity checks
	if (!curr_node)
		perr_and_abort1();
	if (!curr_node->hash)
		perr_and_abort1();

	// Save this for transforming the tree later.
	if (pending_transform)
		splay_assoc_blkid = curr_node->blkid;

	if (!_curr_node && mac) {
		// Fetch parent before swapping in the new (child) mac. Edit: not
		// sure if we really need to fetch parent before swapping mac (that may
		// only be the case if verify==true).
		was_cached = false;
		tmp = get_mt_node(curr_node->parent, false, false, &was_cached);

		memcpy(curr_node->hash, mac, curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);
		free(mac);
		put_mt_node(curr_node);
		cleanup_mt_node(curr_node);

		curr_node = tmp;
	}

	while (1) {
		if (!curr_node->hash)
			perr_and_abort1();

		// Save the stored parent hash.
		memcpy(new_par_hash, curr_node->hash, HASH_SIZE);

		// Compute the test parent hash now that the child hash has changed.
		if (hash_node(curr_node, false, NULL, false) != 0)
			perr_and_abort1();

		log_node_info(curr_node);

		// Verify that test parent hash matches stored hash.
		if (memcmp(curr_node->hash, new_par_hash, HASH_SIZE) != 0)
			perr_and_abort1();

		// If memcmp checks out, put the node into the cache so we keep a
		// running test hash until we reach an authenticated hash or the root.
		put_mt_node(curr_node);

		// Save a copy of the starting (par) node with the updated hash so we
		// dont need to fetch it again during transform.
		if (pending_transform && !starting_node)
			starting_node = copy_mt_node(curr_node);

		if (curr_node->node_id == mt.root.node_id)
			assert(was_cached);
		if (was_cached) {
			if (curr_node->node_id == mt.root.node_id) {
				// Skip cleanup if we do not own the ptr.
				if (skip_done)
					cleanup_mt_node(curr_node);
				// TODO: increment num_early_rets here because for DMT we should
				// still consider an early ret valid if the leaf's par is root.
				break;
			}

			// Skip cleanup if we do not own the ptr.
			if (skip_done)
				cleanup_mt_node(curr_node);

			if (allow_early_ret) {
				stats.num_early_rets++;
				break;
			}
		}

		// We dont expect the parent node to be cached, but we want to know if
		// it is so we can determine if we can do an early return in the next
		// loop iteration.
		was_cached = false;
		tmp = get_mt_node(curr_node->parent, false, false, &was_cached);
		if (!tmp)
			perr_and_abort1();

		// Check if the starting node is a left or right child. Note: tmp is the
		// gparent of the original node verify was called on.
		if (starting_node && !find_start_done) {
			find_start_done = true;
			if (tmp->children[0] == starting_node->node_id)
				start_left = true;
			else
				start_left = false;
		}

		// Skip cleanup on first node if we do not own the ptr.
		if (!skip_done)
			skip_done = true;
		else
			cleanup_mt_node(curr_node);

		curr_node = tmp;
	}

	stats.num_verify_rets++;

	if (pending_transform &&
		(transform_tree(starting_node, splay_assoc_blkid, start_left) != 0))
		perr_and_abort1();

	return 0;
}

int update_mt(mt_node_t *_curr_node, uint64_t blk_id, uint8_t *mac,
			  bool pending_transform) {
	/*
	 * The basic idea with update_mt is that we loop all the way from beginning
	 * node to the root, updating all parent hashes along the way. Unlike
	 * verify_mt, all fetched nodes here must be authenticated in order to have
	 * an authenticated update.
	 */

	mt_node_t *curr_node = NULL, *tmp = NULL, *starting_node = NULL;
	mt_node_t *sibling = NULL;
	uint64_t splay_assoc_blkid = 0;
	mt_node_t *new_children[FIXED_ARITY] = {NULL, NULL};
	bool skip_done = true;
	bool start_left = false;
	bool find_start_done = false;

	// Whether update_mt is called in the context of a leaf node, internal node,
	// from device_write, or from rotate, a mac should always be provided.
	assert(mac);

	// Check what case we are dealing with to prepare for the main loop.
	if (!_curr_node) {
		curr_node = get_mt_node(blk_id, true);
		curr_node->_height++;
	} else {
		curr_node = _curr_node;
		skip_done = false;
	}

	// Sanity checks
	if (!curr_node)
		perr_and_abort1();
	if (!curr_node->hash)
		perr_and_abort1();

	// Save this for transforming the tree later.
	if (pending_transform)
		splay_assoc_blkid = curr_node->blkid;

	// Note that we have to fetch the parent first before swapping the
	// hashes, otherwise the verification of the parent would fail.
	mt_node_t *par = get_mt_node(curr_node->parent, true);

	uint8_t old_hash[HASH_SIZE] = {0};
	memcpy(old_hash, curr_node->hash,
		   curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);

	uint8_t old_par_hash[HASH_SIZE] = {0};
	memcpy(old_par_hash, par->hash, HASH_SIZE);

	uint8_t new_hash[HASH_SIZE] = {0};

	memcpy(curr_node->hash, mac, curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);
	free(mac);
	put_mt_node(curr_node);
	memcpy(new_hash, curr_node->hash,
		   curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);

	while (1) {
		if (!curr_node || !par || !curr_node->hash || !par->hash)
			perr_and_abort1();

		// Save the test hashes and move the old contents into the buffers so we
		// can authenticate first.
		memcpy(new_hash, curr_node->hash,
			   curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);
		memcpy(curr_node->hash, old_hash,
			   curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);
		put_mt_node(curr_node);
		memcpy(par->hash, old_par_hash, HASH_SIZE);
		put_mt_node(par);

		/*
		 * Note that update is tricky because the only way we can guarantee an
		 * authenticated update is if the auxiliary (i.e., sibling) hashes are
		 * authenticated too. We could do something like 'expect' hashes to be
		 * cached, but that would make it difficult when cache size is small or
		 * there is no cache (only disk). So instead we proceed with update by:
		 * 1) ensuring that we localize all the side effects during rotate by
		 * updating the hashes directly, and 2) beginning the update_mt at the
		 * root of the updated subtree. So therefore here we proceed in the same
		 * way as we would when updating a leaf hash from device_write -- by
		 * swapping in the old hashes above, then we fetch/verify the sibling,
		 * then we compute the new parent hash directly using the curr_node and
		 * authenticated sibling.
		 */
		for (uint64_t i = 0; i < FIXED_ARITY; i++) {
			if (par->children[i] == curr_node->node_id)
				new_children[i] = curr_node;
			else {
				sibling = get_mt_node(par->children[i], true);
				new_children[i] = sibling;
			}
		}

		// Move the test contents back over and compute the new hashes.
		memcpy(curr_node->hash, new_hash,
			   curr_node->is_leaf ? MAC_SIZE : HASH_SIZE);
		put_mt_node(curr_node);

		if (hash_node2(par, new_children) != 0)
			perr_and_abort1();

		// Save a copy of the starting (par) node with the updated hash so we
		// dont need to fetch it again during transform.
		if (pending_transform && !starting_node)
			starting_node = copy_mt_node(par);

		for (uint64_t i = 0; i < FIXED_ARITY; i++) {
			// Cleanup everything but curr_node because we need it below. Also
			// prevents cleanup when we do not own the ptr (_curr_node was
			// passed in).
			if (par->children[i] != curr_node->node_id)
				cleanup_mt_node(new_children[i]);
		}

		// Try to fetch the grandparent before we save the new parent hash. Note
		// that we proceed towards the root, so even though we just updated
		// curr_node, it wont affect the verification of par->parent.
		if (par->node_id != mt.root.node_id) {
			tmp = get_mt_node(par->parent, true);

			if (starting_node && !find_start_done) {
				find_start_done = true;
				if (tmp->children[0] == starting_node->node_id)
					start_left = true;
				else
					start_left = false;
			}
		}

		// Now save the updated parent hash.
		put_mt_node(par);

		// Skip cleanup on first node if we do not own the ptr.
		if (!skip_done)
			skip_done = true;
		else
			cleanup_mt_node(curr_node);

		// Stop if at root.
		if (par->node_id == mt.root.node_id) {
			cleanup_mt_node(par);
			break;
		}

		// Copy over the staging hashes so we can proceed to next parent.
		memcpy(old_hash, old_par_hash, HASH_SIZE);
		memcpy(old_par_hash, tmp->hash, HASH_SIZE);

		curr_node = par;
		par = tmp;
	}

	if (pending_transform &&
		(transform_tree(starting_node, splay_assoc_blkid, start_left) != 0))
		perr_and_abort1();

	return 0;
}

int init_mt_generic(int data_fd, mt_type_t mt_type, uint64_t arity) {
	// Sanity check
	if ((mt_type != PERFECT) && (mt_type != DMT))
		perr_and_abort1();

	mt.type = mt_type;

	// We know that the initial root node id will be INVALID_NODE_ID-1, so just
	// set this initially so puts/fetches are OK.
	mt.root.node_id = INVALID_NODE_ID - 1;

	// Should only init once.
	if (mt.status != 0)
		perr_and_abort1();

	mt.n = NUM_BLKS;

	switch (mt.type) {
	case PERFECT:
	case DMT:
		mt.height = (uint64_t)(log2(mt.n) / log2(arity));
		mt.num_nodes = (arity * mt.n - 1) / (arity - 1);
		total_num_nodes = mt.num_nodes;
		break;
	case PARTIAL_SKEW_RIGHT:
		// not supported yet
	case FULL_SKEW_RIGHT:
		// not supported yet
	default:
		perr_and_abort1();
	}

	// Only binary trees are supported for now for DMT/PERFECT
	// Edit: n-ary trees are not supported for PERFECT only
	if ((mt.type == DMT) && (arity != 2))
		perr_and_abort1();

	cache_init(&insecure_cache, INSECURE_CACHE_SIZE, NULL);
	cache_init(&secure_cache, SECURE_CACHE_SIZE,
			   INSECURE_CACHE_SIZE > 0 ? &insecure_cache : NULL);

	uint64_t blk_id = 0, aad;
	uint64_t i = mt.num_nodes - 1;
	mt_node_t node_i, *node_c;
	char blk[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	for (;; i--) {
		memset(&node_i, 0x0, sizeof(mt_node_t));
		node_c = NULL;

		if (check_idx_is_leaf(i, arity))
			node_i.is_leaf = true;
		else
			node_i.is_leaf = false;

		node_i.arity = arity;

		if (!node_i.hash)
			perr_and_abort1();

		if (node_i.is_leaf) {
			blk_id = get_blk_id_from_idx(i, arity);
			node_i.blkid = blk_id;
			node_i.node_id = blk_id;
			node_i._height = 0;
		} else {
			node_i.node_id = INTERNAL_NODE_ID(i);

			// Build links from bottom up like huffman algorithm.
			uint64_t c = 0;
			for (uint64_t j = 0; j < arity; j++) {
				c = get_blk_id_from_idx(get_child_idx(i, j, arity), arity);
				if (c > mt.n - 1)
					c = INTERNAL_NODE_ID(get_child_idx(i, j, arity));
				node_c = get_mt_node(c, false);

				node_i.children[j] = node_c->node_id;
				node_c->parent = node_i.node_id;
				put_mt_node(node_c);
				cleanup_mt_node(node_c);
			}
		}

		if (node_i.is_leaf) {
			// Init everything with 0 block and IV
			memset(blk, 0x0, BLK_SIZE);
			memset(node_i.iv, 0x0, IV_SIZE);

			// encrypt + write data to disk
			aad = use_static_block ? 0 : blk_id;
			if ((enc(blk, BLK_SIZE, &aad, node_i.iv, node_i.hash) != 0))
				perr_and_abort1();

			if (__do_write(data_fd, blk, blk_id * BLK_SIZE, BLK_SIZE) != 0)
				perr_and_abort1();

			// save metadata through cache later
		} else {
			if (hash_node(&node_i) != 0)
				perr_and_abort1();
		}

		if ((mt.num_nodes - i) % (mt.num_nodes / 10) == 0)
			perr("\rProgress: %lu%%",
				 ((mt.num_nodes - i) / (mt.num_nodes / 10)) * 10);

		// Mark root node (i==0) parent accordingly.
		if (i == 0)
			node_i.parent = INVALID_NODE_ID;

		put_mt_node(&node_i);

		if (i == 0)
			break;
	}

	// Sanity check
	assert(mt.root.node_id != INVALID_NODE_ID);

	perr("\rProgress: %lu/%lu\n", mt.num_nodes, mt.num_nodes);

	// Log init info and reset cache/counters
	get_mt_info();
	flush_caches();
	reset_perf_counters();

	mt.status = 1;

	return 0;
}

int init_variable_arity_tree(int data_fd, mt_type_t mt_type, uint64_t arity) {
	// Note: This function is WIP.
	perr_and_abort1();

	// Sanity check
	if ((mt_type != PERFECT) && (mt_type != DMT))
		perr_and_abort1();

	mt.type = mt_type;

	// We know that the initial root node id will be INVALID_NODE_ID-1, so just
	// set this initially so puts/fetches are OK.
	mt.root.node_id = INVALID_NODE_ID - 1;

	// Should only init once.
	if (mt.status != 0)
		perr_and_abort1();

	mt.n = NUM_BLKS;

	uint64_t nth, num_nodes_at_curr_level, num_nodes, attempts;
	switch (mt.type) {
	case VARIABLE_ARITY:
		// Brute force search for the height based on the given number of
		// nodes and the fact that the number of nodes at each level (and
		// thus the exponent) exhibits a triangular pattern
		// Note that arity is the starting arity (root node)
		pdebug0("Computing height for variable arity MT based on given "
				"number of blocks\n");
		nth = 1, num_nodes_at_curr_level = 0, num_nodes = 0;
		attempts = 0;
		while (1) {
			num_nodes_at_curr_level = (uint64_t)pow(arity, nth * (nth - 1) / 2);
			num_nodes += num_nodes_at_curr_level;
			if (num_nodes_at_curr_level == mt.n)
				break;
			nth++;
			pdebug0("mt.n: %lu, nth: %lu, num_nodes_at_curr_level: %lu, "
					"num_nodes: %lu\n",
					mt.n, nth, num_nodes_at_curr_level, num_nodes);
			attempts++;
			if (attempts > 1e6)
				perr("\rMight be stuck%s", attempts % 2 == 0 ? ".. " : "...");
		}
		pdebug0("mt.n: %lu, nth: %lu, num_nodes_at_curr_level: %lu, "
				"num_nodes: %lu\n",
				mt.n, nth, num_nodes_at_curr_level, num_nodes);
		mt.height = nth - 1; // the level (height) is the nth term - 1
		mt.num_nodes = num_nodes;
		total_num_nodes = mt.num_nodes;
		break;
	default:
		perr_and_abort1();
	}

	cache_init(&insecure_cache, INSECURE_CACHE_SIZE, NULL);
	cache_init(&secure_cache, SECURE_CACHE_SIZE,
			   INSECURE_CACHE_SIZE > 0 ? &insecure_cache : NULL);

	uint64_t curr_blk_id = NUM_BLKS - 1;
	uint64_t i = mt.num_nodes - 1;
	mt_node_t node_i, *node_c;
	uint64_t aad;
	char blk[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	for (;; i--) {
		memset(&node_i, 0x0, sizeof(mt_node_t));
		node_c = NULL;

		if (check_idx_is_leaf(i, arity))
			node_i.is_leaf = true;
		else
			node_i.is_leaf = false;

		node_i.arity = get_arity_from_idx(i, arity);

		if (!node_i.hash)
			perr_and_abort1();

		if (node_i.is_leaf) {
			node_i.blkid = curr_blk_id;
			node_i.node_id = curr_blk_id;
			node_i._height = 0;
		} else {
			node_i.node_id = INTERNAL_NODE_ID(i);

			// Build links from bottom up like huffman algorithm.
			uint64_t c = 0;
			for (uint64_t j = 0; j < arity; j++) {
				c = get_blk_id_from_idx(get_child_idx(i, j, arity), arity);
				if (c > mt.n - 1)
					c = INTERNAL_NODE_ID(get_child_idx(i, j, arity));
				node_c = get_mt_node(c, false);

				node_i.children[j] = node_c->node_id;
				node_c->parent = node_i.node_id;
				put_mt_node(node_c);
				cleanup_mt_node(node_c);
			}
		}

		if (node_i.is_leaf) {
			// Init everything with 0 block and IV
			memset(blk, 0x0, BLK_SIZE);
			memset(node_i.iv, 0x0, IV_SIZE);

			// encrypt + write data to disk
			aad = use_static_block ? 0 : curr_blk_id;
			if ((enc(blk, BLK_SIZE, &aad, node_i.iv, node_i.hash) != 0))
				perr_and_abort1();

			if (__do_write(data_fd, blk, curr_blk_id * BLK_SIZE, BLK_SIZE) != 0)
				perr_and_abort1();

			// save metadata through cache later

			curr_blk_id--;
		} else {
			if (hash_node(&node_i) != 0)
				perr_and_abort1();
		}

		if ((mt.num_nodes - i) % (mt.num_nodes / 10) == 0)
			perr("\rProgress: %lu%%",
				 ((mt.num_nodes - i) / (mt.num_nodes / 10)) * 10);

		// Mark root node (i==0) parent accordingly.
		if (i == 0)
			node_i.parent = INVALID_NODE_ID;

		put_mt_node(&node_i);

		if (i == 0)
			break;
	}

	// Sanity check
	assert(mt.root.node_id != INVALID_NODE_ID);

	perr("\rProgress: %lu/%lu\n", mt.num_nodes, mt.num_nodes);

	// Log init info and reset cache/counters
	get_mt_info();
	flush_caches();
	reset_perf_counters();

	mt.status = 1;

	return 0;
}

int init_block_hashes(int data_fd) {
	mt.type = ENC_NOINT;

	mt.root.node_id = INVALID_NODE_ID - 1;

	cache_init(&insecure_cache, INSECURE_CACHE_SIZE, NULL);
	cache_init(&secure_cache, SECURE_CACHE_SIZE,
			   INSECURE_CACHE_SIZE > 0 ? &insecure_cache : NULL);

	mt_node_t node_i;
	uint64_t aad;
	char blk[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	for (uint64_t b = 0; b < NUM_BLKS; b++) {
		memset(&node_i, 0x0, sizeof(mt_node_t));
		node_i.is_leaf = true; // if mt disabled then we only need leaves

		// Init everything with 0 block and IV
		memset(blk, 0x0, BLK_SIZE);
		memset(node_i.iv, 0x0, IV_SIZE);

		node_i.arity = FIXED_ARITY;
		node_i.blkid = b;
		node_i.node_id = b;

		// encrypt + write data to disk
		aad = use_static_block ? 0 : b;
		if ((enc(blk, BLK_SIZE, &aad, node_i.iv, node_i.hash) != 0))
			perr_and_abort1();

		if (__do_write(data_fd, blk, b * BLK_SIZE, BLK_SIZE) != 0)
			perr_and_abort1();

		if (b % (NUM_BLKS / 10) == 0)
			perr("\rProgress: %lu%%", (b / (NUM_BLKS / 10)) * 10);

		// save metadata through cache
		put_mt_node(&node_i);
	}

	perr("\rProgress: %lu/%lu\n", NUM_BLKS, NUM_BLKS);

	flush_caches();
	reset_perf_counters();

	mt.status = 1;

	return 0;
}

int init_huffman_tree(int data_fd, int64_t *freq, uint64_t arity,
					  bool adaptive) {
	mt.type = HUFFMAN;

	// For HUFFMAN, we assign node iterating forwards (via the num_nodes
	// counter), so the initial root node id is not INVALID_NODE_ID-1 but
	// instead the internal node id furthest inwards.
	mt.root.node_id = INTERNAL_NODE_ID(NUM_BLKS * 2 - 1);

	// Should only init once.
	if (mt.status != 0)
		perr_and_abort1();

	cache_init(&insecure_cache, INSECURE_CACHE_SIZE, NULL);
	cache_init(&secure_cache, SECURE_CACHE_SIZE,
			   INSECURE_CACHE_SIZE > 0 ? &insecure_cache : NULL);

	// add the leaves + compute hashes and save to disk
	mt_node_t t;
	uint64_t aad;
	mt_node_summary_t s;
	uint64_t num_nodes = 0;
	char blk[BLK_SIZE] __attribute__((aligned(BLK_SIZE))) = {0};
	std::priority_queue<mt_node_summary_t, std::vector<mt_node_summary_t>,
						mts_compare>
		minheap;
	for (uint64_t b = 0; b < NUM_BLKS; b++) {
		memset(&t, 0x0, sizeof(mt_node_t));
		memset(&s, 0x0, sizeof(mt_node_summary_t));

		// Sanity check
		if (num_nodes >= (NUM_BLKS * 2.0 - 1))
			perr_and_abort1();

		t.is_leaf = true;
		t.arity = 0;
		t.blkid = b;
		t.freq = freq[b];
		t.node_id = b;

		// Init everything with 0 block and IV
		memset(blk, 0x0, BLK_SIZE);
		memset(t.iv, 0x0, IV_SIZE);

		// encrypt + write data to disk
		aad = use_static_block ? 0 : b;
		if ((enc(blk, BLK_SIZE, &aad, t.iv, t.hash) != 0))
			perr_and_abort1();

		if (__do_write(data_fd, blk, b * BLK_SIZE, BLK_SIZE) != 0)
			perr_and_abort1();

		s.node_id = b;
		s.freq = t.freq;

		minheap.push(s);

		// save metadata through cache
		put_mt_node(&t);

		num_nodes++;

		if (num_nodes % ((NUM_BLKS * 2 - 1) / 10) == 0)
			perr("\rProgress: %lu%%",
				 (num_nodes / ((NUM_BLKS * 2 - 1) / 10)) * 10);
	}

	// add the internal nodes + compute hashes
	mt_node_t top;
	mt_node_t **children = (mt_node_t **)calloc(arity, sizeof(mt_node_t *));
	while (minheap.size() != 1) {
		memset(&top, 0x0, sizeof(mt_node_t));
		memset(&s, 0x0, sizeof(mt_node_summary_t));
		memset(children, 0x0, arity * sizeof(mt_node_t *));

		for (uint64_t j = 0; j < arity; j++) {
			if (minheap.empty()) {
				// Note: for our experiments, we only considered power-of-2
				// sized disks/trees; just abort so we dont have to handle this
				// case (and we abort in get/put if the node_id invalid anyway).
				perr_and_abort1();

				// These are basically dummy blocks that are unmappable by the
				// lookup table but nonetheless need to be hashed to compute the
				// parent (and thus root) hashes. We need this in the case where
				// we have a number of blocks that is not a power of the
				// specified arity.
				children[j] = (mt_node_t *)calloc(1, sizeof(mt_node_t));
				if (!children[j])
					perr_and_abort1();

				children[j]->is_leaf = true;
				children[j]->arity = arity;
				children[j]->blkid = INVALID_BLK_ID;
				children[j]->node_id = INVALID_NODE_ID;

				num_nodes++;
			} else {
				// Otherwise just get the top node from the minheap.
				s = minheap.top();
				children[j] = get_mt_node(s.node_id, false);
				children[j]->freq = s.freq;
				minheap.pop();
			}
		}

		// Sanity check
		if (num_nodes >= (NUM_BLKS * 2.0 - 1))
			perr_and_abort1();

		num_nodes++;

		top.is_leaf = false;
		top.arity = arity;
		top.blkid = INVALID_BLK_ID;
		top.freq = 0;
		for (uint64_t j = 0; j < arity; j++)
			top.freq += children[j]->freq;
		top.node_id = INTERNAL_NODE_ID(num_nodes);

		if (minheap.size() == 0)
			top.parent = INVALID_NODE_ID;
		else
			top.parent = 0;

		// Link the parent to children and vice versa
		for (uint64_t j = 0; j < arity; j++) {
			top.children[j] = children[j]->node_id;
			children[j]->parent = top.node_id;

			// save the updated child node to cache
			put_mt_node(children[j]);
			cleanup_mt_node(children[j]);
		}

		if (hash_node(&top) != 0)
			perr_and_abort1();

		put_mt_node(&top);

		s.node_id = top.node_id;
		s.freq = top.freq;
		minheap.push(s);

		if (num_nodes % ((NUM_BLKS * 2 - 1) / 10) == 0)
			perr("\rProgress: %lu%%",
				 (num_nodes / ((NUM_BLKS * 2 - 1) / 10)) * 10);
	}

	perr("\rProgress: %lu/%lu\n", num_nodes, num_nodes);

	// Sanity checks. Root should be the last element left.
	if (minheap.empty())
		perr_and_abort1();
	assert(mt.root.node_id != INVALID_NODE_ID);

	assert(minheap.top().node_id == INTERNAL_NODE_ID(num_nodes));
	minheap.pop(); // pop the root

	mt.num_nodes = num_nodes;
	total_num_nodes = mt.num_nodes;

	free(children);

	get_mt_info();
	flush_caches();
	reset_perf_counters();

	mt.status = 1;

	return 0;
}

int init_dmt(int data_fd, uint64_t arity) {
	// For DMT, we start with a full balanced tree.
	return init_mt_generic(data_fd, DMT, arity);
}

void log_meta(uint8_t *iv, const char *hash_name, uint8_t *hash, int hash_len) {
	if (iv) {
		pdebug0("\niv: ");
		for (int i = 0; i < IV_SIZE; i++)
			pdebug0("%02x", iv[i]);
		pdebug0(", ");
	}

	if (hash) {
		pdebug0("\n%s: ", hash_name);
		for (int i = 0; i < hash_len; i++)
			pdebug0("%02x", hash[i]);
		pdebug0("\n");
	}
}

void log_node_info(mt_node_t *node) {
	pdebug0("node->node_id: %lu (leaf: %s)\n", node->node_id,
			node->is_leaf ? "true" : "false");
	log_meta(NULL, "node->hash", node->hash,
			 node->is_leaf ? MAC_SIZE : HASH_SIZE);
}

void get_mt_info(int64_t *__min_height, int64_t *__max_height,
				 double *__avg_height, int64_t *__q25_height,
				 int64_t *__q50_height, int64_t *__q75_height) {
	perr("mt info:\n");
	perr("\tmt.type: %s\n",
		 mt_type_to_str(mt.type, (uint64_t)FIXED_ARITY).c_str());
	perr("\tarity: %lu\n", (uint64_t)FIXED_ARITY);
	perr("\tstatus: %d\n", mt.status);
	perr("\tsecure_cache_size: %lu\n", SECURE_CACHE_SIZE);
	perr("\tinsecure_cache_size: %lu\n", INSECURE_CACHE_SIZE);
	perr("\tn: %lu\n", mt.n);
	perr("\ttree height: %lu\n", mt.height);
	perr("\tnum_nodes: %lu\n", mt.num_nodes);
	perr("\tmt.root: %p\n", &mt.root);

	return;

	// compute the min, max, avg, and median height of the tree
	int64_t min_height = INT64_MAX;
	int64_t max_height = 0;
	double avg_height = 0;
	int64_t total_height = 0;
	int64_t q25_height = 0, q50_height = 0, q75_height = 0;
	mt_node_t *curr_node = NULL, *tmp = NULL;
	int64_t curr_height;
	std::vector<int64_t> *heights = new std::vector<int64_t>();
	for (uint64_t b = 0; b < NUM_BLKS; b++) {
		curr_height = 0;
		curr_node = get_mt_node(b, false, false, NULL, true);

		if (mt.type != HUFFMAN) {
			while (curr_node->parent != INVALID_NODE_ID) {
				curr_height++;
				tmp = get_mt_node(curr_node->parent, false, false, NULL, true);
				cleanup_mt_node(curr_node);
				curr_node = tmp;
			}
		}
		cleanup_mt_node(curr_node);

		heights->push_back(curr_height);

		if (curr_height < min_height)
			min_height = curr_height;
		if (curr_height > max_height)
			max_height = curr_height;
		total_height += curr_height;

		// print progress every 10% of the way
		if (b % (NUM_BLKS / 10) == 0)
			perr("\r\t> Compute heights progress: %lu/%lu", b, NUM_BLKS);
	}
	perr("\r\t> Compute heights progress: %lu/%lu\n", NUM_BLKS, NUM_BLKS);
	std::sort(heights->begin(), heights->end());
	q25_height = heights->at(heights->size() / 4);
	q50_height = heights->at(heights->size() / 2);
	q75_height = heights->at((3 * heights->size()) / 4);
	avg_height = (double)total_height / NUM_BLKS;
	delete heights;

	// perr("\thottest: %ld\n", hottest);
	// perr("\tcoldest: %ld\n", coldest);
	perr("\tmin_height: %ld\n", min_height);
	perr("\tmax_height: %ld\n", max_height);
	perr("\tavg_height: %.2f\n", avg_height);
	perr("\tq25_height: %ld\n", q25_height);
	perr("\tq50_height: %ld\n", q50_height);
	perr("\tq75_height: %ld\n", q75_height);

	if (__min_height)
		*__min_height = min_height;
	if (__max_height)
		*__max_height = max_height;
	if (__avg_height)
		*__avg_height = avg_height;
	if (__q25_height)
		*__q25_height = q25_height;
	if (__q50_height)
		*__q50_height = q50_height;
	if (__q75_height)
		*__q75_height = q75_height;
}

double get_secure_cache_hit_rate() { return get_cache_hit_rate(&secure_cache); }

static std::string log_cache_hit_rate(cache_t *c) {
	if (c->accesses == 0)
		return "0.0";

	std::string r = std::to_string(get_cache_hit_rate(c));
	r += " (" + std::to_string(c->hits) + "/" + std::to_string(c->accesses) +
		 ")";

	return r;
}

std::string log_perf_stats() {
	std::string out;
	out += "Secure cache hit rate: " + log_cache_hit_rate(&secure_cache) + "\n";
	out += "Insecure cache hit rate: " + log_cache_hit_rate(&insecure_cache) +
		   "\n";
	out += "Number of splays: " + std::to_string(stats.num_splays) + "\n";
	out += "Number of reauthentications: " + std::to_string(stats.num_reauths) +
		   "\n";
	out += "Number of reauths during splay: " +
		   std::to_string(stats.num_reauths_during_splay) + "\n";
	out += "Early ret rate: " +
		   std::to_string((double)stats.num_early_rets /
						  (double)stats.num_verify_rets) +
		   "\n";

	out += "Number of meta disk writes from blk reads: " +
		   std::to_string(stats.num_meta_disk_writes_from_blk_reads) + "\n";
	out += "Number of meta disk writes from blk writes: " +
		   std::to_string(stats.num_meta_disk_writes_from_blk_writes) + "\n";
	out += "Number of meta root disk writes from blk reads: " +
		   std::to_string(stats.num_meta_root_disk_writes_from_blk_reads) +
		   "\n";
	out += "Number of meta root disk writes from blk writes: " +
		   std::to_string(stats.num_meta_root_disk_writes_from_blk_writes) +
		   "\n";
	out += "Number of meta root disk reads from blk reads: " +
		   std::to_string(stats.num_meta_root_disk_reads_from_blk_reads) + "\n";
	out += "Number of meta root disk reads from blk writes: " +
		   std::to_string(stats.num_meta_root_disk_reads_from_blk_writes) +
		   "\n";
	out += "Number of total meta disk writes: " +
		   std::to_string(stats.num_meta_disk_writes_from_blk_reads +
						  stats.num_meta_disk_writes_from_blk_writes) +
		   "\n";
	out += "Number of meta disk reads from blk reads: " +
		   std::to_string(stats.num_meta_disk_reads_from_blk_reads) + "\n";
	out += "Number of meta disk reads from blk writes: " +
		   std::to_string(stats.num_meta_disk_reads_from_blk_writes) + "\n";
	out += "Number of total meta disk reads: " +
		   std::to_string(stats.num_meta_disk_reads_from_blk_reads +
						  stats.num_meta_disk_reads_from_blk_writes) +
		   "\n";
	// ratio of total writes to total reads
	out += "Ratio of total writes to total reads: " +
		   std::to_string((double)(stats.num_meta_disk_writes_from_blk_reads +
								   stats.num_meta_disk_writes_from_blk_writes) /
						  (double)(stats.num_meta_disk_reads_from_blk_reads +
								   stats.num_meta_disk_reads_from_blk_writes)) +
		   "\n";

	out += "Number of (dirty) evictions during blk writes: " +
		   std::to_string(stats.num_evictions_during_blk_writes) + "\n";
	out += "Number of (dirty) evictions during blk reads: " +
		   std::to_string(stats.num_evictions_during_blk_reads) + "\n";

	out += "Number of misses during blk writes: " +
		   std::to_string(stats.num_misses_during_blk_writes) + "\n";
	out += "Number of misses during blk reads: " +
		   std::to_string(stats.num_misses_during_blk_reads) + "\n";

	return out;
}

std::string mt_type_to_str(mt_type_t type, uint64_t arity) {
	switch (type) {
	case PERFECT:
		return "PERFECT" + std::to_string(arity);
	case PARTIAL_SKEW_RIGHT:
		return "PARTIAL_SKEW_RIGHT";
	case FULL_SKEW_RIGHT:
		return "FULL_SKEW_RIGHT";
	case HUFFMAN:
		return "HUFFMAN";
	case DMT:
		return "DMT";
	case VARIABLE_ARITY:
		return "VARIABLE_ARITY";
	case ENC_NOINT:
		return "ENC_NOINT";
	case NOENC_NOINT:
		return "NOENC_NOINT";
	default:
		return "UNKNOWN";
	}
}

void cleanup_mt_node(mt_node_t *node) {
	if (node)
		free(node);
}

void cleanup_caches() {
	cleanup_cache(&secure_cache);
	cleanup_cache(&insecure_cache);
}

void reinit_caches() {
	// We reinit caches primarily because, during initialization of the huffman
	// tree, there is heavy memory contention between the cache and minheap,
	// often leading to OOM issues, so we just dont cache stuff during init for
	// right now, so that the minheap can complete successfully.
	cleanup_cache(&secure_cache);
	cleanup_cache(&insecure_cache);
	cache_init(&insecure_cache, INSECURE_CACHE_SIZE, NULL);
	cache_init(&secure_cache, SECURE_CACHE_SIZE,
			   INSECURE_CACHE_SIZE > 0 ? &insecure_cache : NULL);

	perr("Done reinitializing caches\n");
}

void warm_caches(int64_t *freq) {
	// Warm up the cache by replaying some of the given trace. This is to
	// prevent fio hangs, particularly for OPT, because cold misses might fail
	// with ETIMEDOUT. Note: This function should be called before we spawn the
	// bg verifier thread and/or start BDUS driver/test workload. Otherwise
	// there may be risk of inconsistency between the mt_queue/cache.
	perr("Warming up caches\n");

	uint64_t i = 0;
	for (auto &blk : warmup_trace) {
		mt_node_t *node = get_mt_node(blk, true);
		cleanup_mt_node(node);
		if (i % (warmup_trace.size() / 10) == 0)
			perr("\t> Warm up progress: %lu/%lu\n", i, warmup_trace.size());
		i++;
	}

	perr("Warmup done\n");
}

void flush_caches() {
	flush_cache(&secure_cache);
	flush_cache(&insecure_cache);
	perr("Done flushing caches\n");
}

int init_crypto() {
	gcry_error_t err;

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n",
				GCRYPT_VERSION, gcry_check_version(NULL));
		abort();
	}

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	memset(&cipher, 0x0, sizeof(gcry_cipher_hd_t));
	memset(&sha256_h, 0x0, sizeof(gcry_md_hd_t));

	err = gcry_md_open(&sha256_h, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (err)
		perr_and_abort1();

	err =
		gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
	if (err)
		perr_and_abort1();

	err = gcry_cipher_setkey(cipher, CIPHER_KEY, CIPHER_KEY_SIZE);
	if (err)
		perr_and_abort1();

	return 0;
}

static void destroy_crypto() {
	gcry_cipher_close(cipher);
	gcry_md_close(sha256_h);
}

int flush_mt(void) {
	// TODO: flush mt to disk
	destroy_crypto();
	return 0;
}
