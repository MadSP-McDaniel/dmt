#ifndef MT_SUPPORT_H
#define MT_SUPPORT_H

#include <stdint.h>

uint64_t get_idx_from_blk_id(uint64_t, uint64_t);
uint64_t get_blk_id_from_idx(uint64_t, uint64_t);
uint64_t get_child_idx(uint64_t, uint64_t, uint64_t);
bool check_idx_is_leaf(uint64_t, uint64_t);
uint64_t get_arity_from_idx(uint64_t, uint64_t);

#endif /* MT_SUPPORT_H */
