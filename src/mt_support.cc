/**
 * This code provides support functions for the merkle tree implementation.
 */
#include <cmath>

#include "mt.h"
#include "mt_support.h"

uint64_t get_idx_from_blk_id(uint64_t blk_id, uint64_t arity) {
	switch (mt.type) {
	case PERFECT:
	case DMT:
		return blk_id + ((arity * (uint64_t)pow(arity, mt.height - 1) - 1) /
						 (arity - 1));
	case PARTIAL_SKEW_RIGHT:
		if (blk_id >= 0 && blk_id < mt.n / 4)
			return blk_id + ((1 << mt.height) - 1) - (1 << (mt.height - 1));
		else if (blk_id >= mt.n / 4 && blk_id < mt.n * 3 / 4)
			return blk_id + ((1 << mt.height) - 1) - (1 << (mt.height - 2));
		else if (blk_id >= mt.n * 3 / 4 && blk_id < mt.n)
			return blk_id + ((1 << mt.height) - 1);
		else
			perr_and_abort0("Invalid block id\n");
	case FULL_SKEW_RIGHT:
		return blk_id * 2 + 1;
	case HUFFMAN:
		return 0;
	default:
		perr_and_abort0("Invalid merkle tree type\n");
	}
}

uint64_t get_blk_id_from_idx(uint64_t i, uint64_t arity) {
	switch (mt.type) {
	case PERFECT:
	case DMT:
		return i - ((arity * (uint64_t)pow(arity, mt.height - 1) - 1) /
					(arity - 1));
	case PARTIAL_SKEW_RIGHT:
		uint64_t bb1, bb2, bb3, bb4, bb5, bb6; // boundary block indices
		bb1 = get_idx_from_blk_id(0, arity);
		bb2 = get_idx_from_blk_id(mt.n / 4 - 1, arity);
		bb3 = get_idx_from_blk_id(mt.n / 4, arity);
		bb4 = get_idx_from_blk_id(mt.n / 2 - 1, arity);
		bb5 = get_idx_from_blk_id(mt.n / 2, arity);
		bb6 = get_idx_from_blk_id(mt.n - 1, arity);

		if (i >= bb1 && i <= bb2)
			return i - ((1 << mt.height) - 1) + (1 << (mt.height - 1));
		else if (i >= bb3 && i <= bb4)
			return i - ((1 << mt.height) - 1) + (1 << (mt.height - 2));
		else if (i >= bb5 && i <= bb6)
			return i - ((1 << mt.height) - 1);
		else
			perr_and_abort0("Invalid index\n");
	case FULL_SKEW_RIGHT:
		return i / 2;
	case HUFFMAN:
		return 0;
	default:
		perr_and_abort0("Invalid merkle tree type\n");
	}
}

uint64_t get_child_idx(uint64_t i, uint64_t j, uint64_t arity) {
	uint64_t nth, num_nodes_at_curr_level, num_nodes_at_next_level, num_nodes,
		ii;

	switch (mt.type) {
	case PERFECT:
	case DMT:
		return (i * arity) + j + 1;
	case PARTIAL_SKEW_RIGHT:
		uint64_t bb3, bb5, bb6; // boundary block indices
		bb3 = get_idx_from_blk_id(mt.n / 4, arity);
		bb5 = get_idx_from_blk_id(mt.n / 2, arity);
		bb6 = get_idx_from_blk_id(mt.n - 1, arity);

		if (i > 0 && i < bb3)
			return (i * 2) + j + 1;
		else if (i >= bb3 && i < bb5)
			return (i * 2) - (1 << (mt.height - 1)) + j + 1;
		else if (i >= bb5 && i <= bb6)
			return (i * 2) - (1 << mt.height) + j + 1;
	case FULL_SKEW_RIGHT:
		return i + j + 1;
	case HUFFMAN:
		return 0;
	case VARIABLE_ARITY:
		pdebug0("Getting child idx for [i:%lu] for variable arity MT\n", i);
		if (i < 0 || i >= mt.num_nodes)
			perr_and_abort0("Invalid index\n");

		nth = 1, num_nodes_at_curr_level = 0, num_nodes_at_next_level = 0,
		num_nodes = 0;
		while (1) {
			// curr level is the level we are inspecting to try to find index i
			num_nodes_at_curr_level = (uint64_t)pow(arity, nth * (nth - 1) / 2);
			num_nodes_at_next_level = (uint64_t)pow(arity, (nth + 1) * nth / 2);

			if (num_nodes_at_next_level > mt.n)
				perr_and_abort0("Could not find a proper child index\n");

			// check if the index is at the current level
			// Note that num_nodes tracks the last index in the previous level
			if (i >= num_nodes && i < num_nodes + num_nodes_at_curr_level) {
				ii = i - num_nodes;
				ii = ii * (uint64_t)pow(arity, nth) + j;
				ii += num_nodes + num_nodes_at_curr_level;
				pdebug0("Computed child idx: %lu\n", ii);
				pdebug0("mt.n: %lu, nth: %lu, num_nodes: %lu, "
						"num_nodes_at_curr_level: %lu, "
						"num_nodes_at_next_level: %lu\n",
						mt.n, nth, num_nodes, num_nodes_at_curr_level,
						num_nodes_at_next_level);
				return ii;
			}

			num_nodes += num_nodes_at_curr_level;
			nth++;
		}
		perr_and_abort0("Could not find a proper child index\n");
	default:
		perr_and_abort0("Invalid merkle tree type\n");
	}
}

bool check_idx_is_leaf(uint64_t i, uint64_t arity) {
	uint64_t nth, num_nodes_at_curr_level, num_nodes;

	switch (mt.type) {
	case PERFECT:
	case DMT:
		return i >= ((arity * (uint64_t)pow(arity, mt.height - 1) - 1) /
					 (arity - 1));
	case PARTIAL_SKEW_RIGHT:
		uint64_t bb1, bb2, bb3, bb4, bb5, bb6; // boundary block indices
		bb1 = get_idx_from_blk_id(0, arity);
		bb2 = get_idx_from_blk_id(mt.n / 4 - 1, arity);
		bb3 = get_idx_from_blk_id(mt.n / 4, arity);
		bb4 = get_idx_from_blk_id(mt.n / 2 - 1, arity);
		bb5 = get_idx_from_blk_id(mt.n / 2, arity);
		bb6 = get_idx_from_blk_id(mt.n - 1, arity);

		return (i >= bb1 && i <= bb2) || (i >= bb3 && i <= bb4) ||
			   (i >= bb5 && i <= bb6);
	case FULL_SKEW_RIGHT:
		return (i % 2 == 1);
	case HUFFMAN:
		return 0;
	case VARIABLE_ARITY:
		pdebug0("Checking if idx is leaf for variable arity MT\n");
		if (i < 0 || i >= mt.num_nodes)
			perr_and_abort0("Invalid index\n");

		nth = 1, num_nodes_at_curr_level = 0, num_nodes = 0;
		while (1) {
			num_nodes_at_curr_level = (uint64_t)pow(arity, nth * (nth - 1) / 2);
			if (num_nodes_at_curr_level == mt.n)
				break;
			num_nodes += num_nodes_at_curr_level;
			nth++;
		}
		pdebug0("mt.n: %lu, nth: %lu, num_nodes_at_curr_level: %lu, "
				"num_nodes: %lu\n",
				mt.n, nth, num_nodes_at_curr_level, num_nodes);
		return i >= num_nodes; // num_nodes does not include the leaves
	default:
		perr_and_abort0("Invalid merkle tree type\n");
	}

	return false;
}

uint64_t get_arity_from_idx(uint64_t i, uint64_t arity) {
	pdebug0("Getting arity from idx for [i:%lu] for variable arity MT\n", i);
	uint64_t nth, num_nodes_at_curr_level, num_nodes;

	if (i < 0 || i >= mt.num_nodes)
		perr_and_abort0("Invalid index\n");

	nth = 1, num_nodes_at_curr_level = 0, num_nodes = 0;
	while (1) {
		// curr level is the level we are inspecting to try to find index i
		num_nodes_at_curr_level = (uint64_t)pow(arity, nth * (nth - 1) / 2);

		// check if the index is at the current level
		// Note that num_nodes tracks the last index in the previous level
		if (i >= num_nodes && i < num_nodes + num_nodes_at_curr_level)
			return (uint64_t)pow(arity, nth);

		num_nodes += num_nodes_at_curr_level;
		nth++;
		pdebug0("mt.n: %lu, nth: %lu, num_nodes_at_curr_level: %lu, "
				"num_nodes: %lu\n",
				mt.n, nth, num_nodes_at_curr_level, num_nodes);
	}
	pdebug0("mt.n: %lu, nth: %lu, num_nodes_at_curr_level: %lu, "
			"num_nodes: %lu\n",
			mt.n, nth, num_nodes_at_curr_level, num_nodes);
}
