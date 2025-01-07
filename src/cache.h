#ifndef CACHE_H
#define CACHE_H

#include <unordered_map>
#include <vector>

#include "disk.h"
#include "mt.h"

typedef struct cache_node {
	mt_node_t mt_node;
	struct cache_node *next, *prev;
} cache_node_t;

typedef struct cache {
	cache_node_t *head, *tail;
	struct cache *next_level_cache;
	uint64_t capacity, size;
	cache_node_t *raw_nodes;				// pre-alloc zone for cache nodes
	std::vector<cache_node_t *> free_nodes; // cache nodes not in use
	std::unordered_map<uint64_t, cache_node_t *> nodes; // cache nodes in use

	// cache perf counters
	uint64_t accesses, hits;
} cache_t;

void cache_init(cache_t *, uint64_t, cache_t *);
void flush_cache(cache_t *);
void cleanup_cache(cache_t *);
int pop_node(cache_t *, uint64_t, bool);
mt_node_t *get_cache_low_level(cache_t *, uint64_t, bool, bool *);
mt_node_t *get_cache(cache_t *, uint64_t, bool, bool *);
int demote(cache_t *, mt_node_t);
int promote(cache_t *, mt_node_t);
int put_cache(cache_t *, mt_node_t *);

mt_node_t *copy_mt_node(mt_node_t *);
cache_node_t *copy_cache_node(cache_node_t *);

double get_cache_hit_rate(cache_t *);
void reset_cache_counters(cache_t *);

#endif /* CACHE_H */
