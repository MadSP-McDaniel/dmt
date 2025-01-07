/**
 * This code implements a simple LRU cache for the Merkle tree nodes, using a
 * doubly linked list and hash table. We pre-alloc a buffer pool for cache nodes
 * to avoid memory fragmentation issues, and track free/available cache nodes
 * to use when inserting new mt_nodes. The cache subsystem is arranged in an
 * (exclusive) hierarchy, where a cache struct points to a next level
 * cache in the hierarchy. We focus on 2 levels for now: secure in-memory cache
 * -> then disk.
 */
#include <cassert>

#include "cache.h"
#include "common.h"
#include "mt.h"

void cache_init(cache_t *c, uint64_t capacity, cache_t *next_level_cache) {
	c->head = NULL;
	c->tail = NULL;
	c->next_level_cache = next_level_cache;
	c->capacity = capacity;
	c->size = 0;
	c->accesses = 0;
	c->hits = 0;

	if (c->capacity == 0)
		return;

	c->raw_nodes = (cache_node_t *)calloc(c->capacity, sizeof(cache_node_t));
	if (!c->raw_nodes)
		perr_and_abort1();

	for (uint64_t i = 0; i < c->capacity; i++)
		c->free_nodes.push_back(&c->raw_nodes[i]);
}

void flush_cache(cache_t *c) {
	if (c->capacity == 0 || c->size == 0)
		return;

	// loop through each node in the cache and write it to disk
	while (c->size > 0) {
		auto it = c->nodes.begin();
		if (!it->second)
			perr_and_abort1();
		if (write_meta_to_disk(&it->second->mt_node) != 0)
			perr_and_abort1();
		if (pop_node(c, it->second->mt_node.node_id, true) != 0)
			perr_and_abort1();
	}
}

void cleanup_cache(cache_t *c) {
	if (c->capacity == 0)
		return;

	flush_cache(c);

	c->free_nodes.clear();

	if (c->raw_nodes)
		free(c->raw_nodes);
}

int pop_node(cache_t *c, uint64_t node_id, bool abort_if_not_found) {
	if (c->capacity == 0) {
		if (abort_if_not_found)
			perr_and_abort1();
		return 0;
	}

	if (c->nodes.find(node_id) == c->nodes.end()) {
		if (abort_if_not_found)
			perr_and_abort1();
		return 0;
	}

	pdebug0("[c=%p] popping node [%lu] from cache\n", c, node_id);

	cache_node_t *cached_node = c->nodes.at(node_id);
	if (!cached_node)
		perr_and_abort1();

	// Remove the node from the LRU linked list.
	if (cached_node->prev != NULL)
		cached_node->prev->next = cached_node->next;
	if (cached_node->next != NULL)
		cached_node->next->prev = cached_node->prev;

	// Update the head and tail.
	if (cached_node == c->tail)
		c->tail = cached_node->prev;
	if (cached_node == c->head)
		c->head = cached_node->next;

	// remove the node from the cache map
	c->nodes.erase(node_id);

	// now mark the node as free
	c->free_nodes.push_back(cached_node);

	c->size--;

	return 0;
}

mt_node_t *get_cache_low_level(cache_t *c, uint64_t node_id, bool dont_recache,
							   bool *was_cached) {

	(void)dont_recache;

	c->accesses++;

	if (c->capacity == 0)
		return NULL;
	if (c->nodes.find(node_id) == c->nodes.end())
		return NULL;

	c->hits++;

	if (was_cached)
		*was_cached = true;

	mt_node_t mt_copy = c->nodes.at(node_id)->mt_node;
	if (put_cache(c, &mt_copy) != 0)
		perr_and_abort1();

	return copy_mt_node(&c->nodes.at(node_id)->mt_node);
}

mt_node_t *get_cache(cache_t *c, uint64_t node_id, bool dont_recache,
					 bool *was_cached) {
	mt_node_t *ret = NULL;

	if (c->capacity == 0) {
		// If c is zero capacity, try to fetch from next level cache or disk. In
		// either case, ret will be a new ptr so just return it directly. Note
		// that c is zero capacity so we do not try to cache it after fetching.
		if (c->next_level_cache)
			ret = get_cache(c->next_level_cache, node_id, dont_recache,
							was_cached);
		else {
			pdebug0("[c=%p] getting node [%lu] from disk\n", c, node_id);

			ret = (mt_node_t *)calloc(1, sizeof(mt_node_t));
			ret->is_leaf = node_id < NUM_BLKS;
			ret->blkid = node_id;
			ret->node_id = node_id;

			if (read_meta_from_disk(ret) != 0)
				perr_and_abort1();
			if (was_cached)
				*was_cached = false;
		}

		return ret;
	}

	// Otherwise if c is non-zero capacity, try to fetch from c.
	pdebug0("[c=%p] getting node [%lu] from cache\n", c, node_id);
	c->accesses++;
	if (c->nodes.find(node_id) == c->nodes.end()) {
		if (stats.active_io_type == 0)
			stats.num_misses_during_blk_reads++;
		else if (stats.active_io_type == 1)
			stats.num_misses_during_blk_writes++;

		// If we could not find it, try fetching from next level cache or disk.
		// Then we always move/promote the node into the current cache (ie
		// exclusive caching).
		if (c->next_level_cache) {
			ret = get_cache(c->next_level_cache, node_id, dont_recache,
							was_cached);
			if (promote(c, *ret) != 0)
				perr_and_abort1();
		} else {
			pdebug0("[c=%p] getting node [%lu] from disk\n", c, node_id);

			ret = (mt_node_t *)calloc(1, sizeof(mt_node_t));
			ret->is_leaf = node_id < NUM_BLKS;
			ret->blkid = node_id;
			ret->node_id = node_id;

			if (read_meta_from_disk(ret) != 0)
				perr_and_abort1();
			if (was_cached)
				*was_cached = false;
			// This promotes the node one level (not necessarily all the way to
			// the top level cache).
			//
			// We also use dont_recache here to avoid putting the node into the
			// cache (if it was not already there), mainly because in
			// device_read/device_write we want to return the node but we have
			// not verified it yet.
			if (!dont_recache && (put_cache(c, ret) != 0))
				perr_and_abort1();
		}

		return ret;
	}

	c->hits++;
	if (was_cached)
		*was_cached = true;

	// If the node is in the cache, but we dont want to _recache_ it
	// (ie dont want to pollute LRU ordering), just return it.
	if (dont_recache)
		return copy_mt_node(&c->nodes.at(node_id)->mt_node);

	// Otherwise if the node is in the cache, and we do want to _recache_ it,
	// move it to the front of the cache then return it.
	mt_node_t mt_copy = c->nodes.at(node_id)->mt_node;
	if (put_cache(c, &mt_copy) != 0)
		perr_and_abort1();

	return copy_mt_node(&c->nodes.at(node_id)->mt_node);
}

int demote(cache_t *c, mt_node_t mt_node) {
	// Only proceed with demote if next_level_cache exists and is nonzero
	// capacity. Note that for simplicity we avoid the weird case where both a
	// next_level_cache ptr is allocated *and* is set at a zero capacity. We
	// do allow c to have zero capacity, however, so we can directly demote to
	// next_level_cache (which would generally be the insecure cache) or disk
	// during put_cache. These are mostly sanity checks b/c we handle this logic
	// when calling demote (in put_cache); should clean this up at some point.
	if (!c->next_level_cache)
		perr_and_abort1();
	if (c->next_level_cache->capacity == 0)
		perr_and_abort1();

	// Pop from c and place into next_level_cache or disk.
	pdebug0("[c=%p] demoting cache node [%lu]\n", c, mt_node.node_id);
	if ((c->capacity > 0) && (pop_node(c, mt_node.node_id, true) != 0))
		perr_and_abort1();
	if (put_cache(c->next_level_cache, &mt_node) != 0)
		perr_and_abort1();

	return 0;
}

int promote(cache_t *c, mt_node_t mt_node) {
	// Same sanity checks.
	if (!c->next_level_cache)
		perr_and_abort1();
	if (c->next_level_cache->capacity == 0)
		perr_and_abort1();

	// We do allow c to be zero capacity for the purposes of demotion, so if we
	// are trying to promote (eg during get_cache), and c is zero capacity, we
	// should just return 0 because we cannot promote it. Again, redundant,
	// because we handle this case when c capacity is zero in get_cache.
	if (c->capacity == 0)
		return 0;

	// Pop from next_level_cache and place into c.
	pdebug0("[c=%p] promoting cache node [%lu]\n", c, mt_node.node_id);
	if (pop_node(c->next_level_cache, mt_node.node_id, true) != 0)
		perr_and_abort1();
	if (put_cache(c, &mt_node) != 0)
		perr_and_abort1();

	return 0;
}

int put_cache(cache_t *c, mt_node_t *node) {
	// Note: we do not own node ptr.
	pdebug0("[c=%p] putting node [%lu] in cache\n", c, node->node_id);

	// If c is zero capacity, directly demote to next cache level or disk.
	if (c->capacity == 0) {
		if (c->next_level_cache) {
			if (demote(c, *node) != 0)
				perr_and_abort1();
		} else {
			if (node->dirty && (write_meta_to_disk(node) != 0))
				perr_and_abort1();
		}

		// If c is zero capacity, we are done in put_cache.
		return 0;
	}

	// If node is already in the cache, just pop and re-add it to front below.
	if (c->nodes.find(node->node_id) != c->nodes.end()) {
		pdebug0("node [%lu] already in cache\n", node->node_id);

		if (pop_node(c, node->node_id, true) != 0)
			perr_and_abort1();

		goto ready_insert;
	} else
		pdebug0("node [%lu] not in cache\n", node->node_id);

	// If not already cached, and cache full, demote the LRU (back/tail) node.
	if (c->size == c->capacity) {
		pdebug0("cache full, evicting LRU [%lu]\n", c->tail->mt_node.node_id);

		if (c->tail->mt_node.dirty) {
			if (stats.active_io_type == 0)
				stats.num_evictions_during_blk_reads++;
			else if (stats.active_io_type == 1)
				stats.num_evictions_during_blk_writes++;
		}

		if (c->next_level_cache) {
			if (demote(c, c->tail->mt_node) != 0)
				perr_and_abort1();
		} else {
			// Note that c->tail->mt_node will change after pop, but it is safe
			// to pass the arg by value here.
			if (c->tail->mt_node.dirty &&
				(write_meta_to_disk(&c->tail->mt_node) != 0))
				perr_and_abort1();
			if (pop_node(c, c->tail->mt_node.node_id, true) != 0)
				perr_and_abort1();
		}
	}

ready_insert:
	// Now add the given node to the front of the cache. Use the next free node
	// object in the pre-allocated zone.
	cache_node_t *new_node = c->free_nodes.back();
	if (!new_node)
		perr_and_abort1();
	c->free_nodes.pop_back();

	new_node->mt_node = *node; // ***direct copy, dont save node ptr***
	if (new_node->mt_node.node_id != node->node_id) // sanity check
		perr_and_abort1();
	new_node->next = NULL;
	new_node->prev = NULL;

	// map the new node
	c->nodes.insert({node->node_id, new_node});
	c->size++;

	assert((!c->head && !c->tail) || (c->head && c->tail)); // sanity check
	if (!c->head && !c->tail) {
		// cache is empty
		c->head = new_node;
		c->tail = new_node;
	} else {
		// cache is not empty
		new_node->next = c->head;
		c->head->prev = new_node;
		c->head = new_node;
	}

	return 0;
}

mt_node_t *copy_mt_node(mt_node_t *node) {
	mt_node_t *n = (mt_node_t *)calloc(1, sizeof(mt_node_t));
	if (!n)
		perr_and_abort1();

	n->is_leaf = node->is_leaf;

	if (node->is_leaf)
		memcpy(n->hash, node->hash, MAC_SIZE);
	else
		memcpy(n->hash, node->hash, HASH_SIZE);

	if (node->is_leaf)
		memcpy(n->iv, node->iv, IV_SIZE);

	n->arity = node->arity;

	n->parent = node->parent;
	if (!node->is_leaf)
		memcpy(n->children, node->children, node->arity * sizeof(uint64_t));

	n->blkid = node->blkid;
	n->freq = node->freq;
	n->node_id = node->node_id;
	n->_height = node->_height;

	return n;
}

cache_node_t *copy_cache_node(cache_node_t *node) {
	cache_node_t *n = (cache_node_t *)calloc(1, sizeof(cache_node_t));
	if (!n)
		perr_and_abort1();

	n->mt_node = node->mt_node;
	n->next = node->next;
	n->prev = node->prev;

	return n;
}

double get_cache_hit_rate(cache_t *c) {
	if (c->accesses == 0)
		return 0.0;

	return (double)c->hits / (double)c->accesses;
}

void reset_cache_counters(cache_t *c) {
	c->accesses = 0;
	c->hits = 0;
}
