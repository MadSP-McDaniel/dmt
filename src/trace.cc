/**
 * This code implements a simple tracer that we can use to collect block-level
 * traces. This is mostly just used when collecting traces from higher-level
 * applications (e.g., database) for offline analysis.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "common.h"
#include "trace.h"

static std::vector<trace_entry_t> read_trace, write_trace, trace;
static std::vector<trace_entry_t> meta_read_trace, meta_write_trace, meta_trace;
static std::vector<uint32_t> iosize_read_trace, iosize_write_trace;

static void dump_trace(int meta) {
	const std::vector<trace_entry_t> &rt = meta ? meta_read_trace : read_trace;
	const std::vector<trace_entry_t> &wt =
		meta ? meta_write_trace : write_trace;
	const std::vector<trace_entry_t> &t = meta ? meta_trace : trace;

	perr("Dumping traces [meta=%d]...\n", meta);

	std::string read_trace_str = "";
	std::string out =
		(meta ? "meta-" : "") + std::string("recorded_read_trace.csv");
	for (auto it = rt.begin(); it != rt.end(); it++)
		read_trace_str += std::to_string((*it).timestamp) + std::string(",") +
						  std::to_string((*it).blk_id) + std::string("\n");
	if (!read_trace_str.empty()) {
		read_trace_str.pop_back();
		dump_to_file(out, read_trace_str.c_str(), false);
	}

	std::string write_trace_str = "";
	out = (meta ? "meta-" : "") + std::string("recorded_write_trace.csv");
	for (auto it = wt.begin(); it != wt.end(); it++)
		write_trace_str += std::to_string((*it).timestamp) + std::string(",") +
						   std::to_string((*it).blk_id) + std::string("\n");
	if (!write_trace_str.empty()) {
		write_trace_str.pop_back();
		dump_to_file(out, write_trace_str.c_str(), false);
	}

	std::string trace_str = "";
	out = (meta ? "meta-" : "") + std::string("recorded_trace.csv");
	for (auto it = t.begin(); it != t.end(); it++)
		trace_str += std::to_string((*it).timestamp) + std::string(",") +
					 std::to_string((*it).blk_id) + std::string("\n");
	if (!trace_str.empty()) {
		trace_str.pop_back();
		dump_to_file(out, trace_str.c_str(), false);
	}

	trace_str = "";
	out = (meta ? "meta-" : "") + std::string("recorded_trace-labeled.csv");
	for (auto it = t.begin(); it != t.end(); it++)
		trace_str += ((*it).type == 0 ? "r" : "w") +
					 std::to_string((*it).timestamp) + std::string(",") +
					 std::to_string((*it).blk_id) + std::string("\n");
	if (!trace_str.empty()) {
		trace_str.pop_back();
		dump_to_file(out, trace_str.c_str(), false);
	}

	if (meta)
		return;

	std::string iosize_read_trace_str = "";
	out = "recorded_iosize_read_trace.csv";
	for (auto it = iosize_read_trace.begin(); it != iosize_read_trace.end();
		 it++)
		iosize_read_trace_str += std::to_string(*it) + std::string("\n");
	if (!iosize_read_trace_str.empty()) {
		iosize_read_trace_str.pop_back();
		dump_to_file(out, iosize_read_trace_str.c_str(), false);
	}

	std::string iosize_write_trace_str = "";
	out = "recorded_iosize_write_trace.csv";
	for (auto it = iosize_write_trace.begin(); it != iosize_write_trace.end();
		 it++)
		iosize_write_trace_str += std::to_string(*it) + std::string("\n");
	if (!iosize_write_trace_str.empty()) {
		iosize_write_trace_str.pop_back();
		dump_to_file(out, iosize_write_trace_str.c_str(), false);
	}
}

int cleanup_tracer() {
	dump_trace(0);
	dump_trace(1);

	return 0;
}

int record_blk_read(uint64_t blk_id, int meta) {
	if (mt.status != 1) {
		return 0;
	}

	std::vector<trace_entry_t> &r = meta ? meta_read_trace : read_trace;
	std::vector<trace_entry_t> &t = meta ? meta_trace : trace;

	if (r.size() > MAX_TRACE_SIZE) {
		pdebug0("r at size limit\n");
		return 0;
	}

	if (t.size() > MAX_TRACE_SIZE) {
		pdebug0("t at size limit\n");
		return 0;
	}

	trace_entry_t entry = {0};
	entry.blk_id = blk_id;
	entry.timestamp = __get_time();
	entry.type = 0;
	t.push_back(entry);
	r.push_back(entry);

	return 0;
}

int record_blk_write(uint64_t blk_id, int meta) {
	if (mt.status != 1) {
		return 0;
	}

	std::vector<trace_entry_t> &w = meta ? meta_write_trace : write_trace;
	std::vector<trace_entry_t> &t = meta ? meta_trace : trace;

	if (w.size() > MAX_TRACE_SIZE) {
		pdebug0("w at size limit\n");
		return 0;
	}

	if (t.size() > MAX_TRACE_SIZE) {
		pdebug0("t at size limit\n");
		return 0;
	}

	trace_entry_t entry = {0};
	entry.blk_id = blk_id;
	entry.timestamp = __get_time();
	entry.type = 1;
	t.push_back(entry);
	w.push_back(entry);

	return 0;
}

int record_io_read(uint64_t start_blk_id, uint32_t size) {
	if (mt.status != 1) {
		return 0;
	}

	if (iosize_read_trace.size() > MAX_TRACE_SIZE) {
		pdebug0("iosize_read_trace at size limit\n");
		return 0;
	}

	if (iosize_read_trace.size() > MAX_TRACE_SIZE) {
		pdebug0("iosize_read_trace at size limit\n");
		return 0;
	}

	iosize_read_trace.push_back(size);

	return 0;
}

int record_io_write(uint64_t start_blk_id, uint32_t size) {
	if (mt.status != 1) {
		return 0;
	}

	if (iosize_write_trace.size() > MAX_TRACE_SIZE) {
		pdebug0("iosize_write_trace at size limit\n");
		return 0;
	}

	if (iosize_write_trace.size() > MAX_TRACE_SIZE) {
		pdebug0("iosize_write_trace at size limit\n");
		return 0;
	}

	iosize_write_trace.push_back(size);

	return 0;
}
