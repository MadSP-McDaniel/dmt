#ifndef DISK_H
#define DISK_H

#include "mt.h"

int read_meta_from_disk(mt_node_t *);
int write_meta_to_disk(mt_node_t *);

#endif /* DISK_H */
