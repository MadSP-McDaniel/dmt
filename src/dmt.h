#ifndef DMT_H
#define DMT_H

#include <bdus.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "mt.h"

extern const struct bdus_ops device_ops;
extern const struct bdus_attrs device_attrs;

int device_read(char *, uint64_t, uint32_t, struct bdus_ctx *);
int device_write(const char *, uint64_t, uint32_t, struct bdus_ctx *);
bool configure_device(int, struct bdus_ops *, struct bdus_attrs *);

#endif /* DMT_H */
