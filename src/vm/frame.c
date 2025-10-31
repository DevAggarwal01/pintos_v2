#include "vm/frame.h"

static struct hash frame_table;         // hash table of all frames 
static struct list frame_clock_list;    // eviction policy is clock algorithm
static struct lock frame_lock;

void frame_init(void) {
    hash_init(&frame_table, frame_hash_func, frame_less_func, NULL);
    list_init(&frame_clock_list);
    lock_init(&frame_lock);
}
