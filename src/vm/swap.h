#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/bitmap.h"
#include <stddef.h>

/**
 * Initializes the swap system.
 * It basically does two things:
 * 1. it sets up the swap block device
 * 2. creates a bitmap to track free swap slots
 * Returns true on success, false if no swap device is available.
 */
bool swap_init(void);

/**
 * Swaps out a page to disk (note that this is MEMORY TO DISK).
 * Finds a free slot in the swap area, writes the entire page,
 * and returns the index of the slot used.
 * Panics or returns SIZE_MAX if no free slots remain.
 */
size_t swap_out(void *frame_addr);

/**
 * Swaps in a page from disk into memory (note that this is DISK TO MEMORY).
 * It is assumed that the slot is valid (basically, swap_out was called 
 * before). After reading, the slot is freed for reuse.
 */
void swap_in(size_t sector, void *frame_addr);

/**
 * Frees the swap slot (sector) so it can be reused later.
 * Should be called after a page has been successfully swapped back in,
 * or when cleaning up process resources.
 */
void swap_remove(size_t sector);
