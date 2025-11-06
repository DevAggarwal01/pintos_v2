#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


extern struct bitmap *swap_bitmap;
extern struct lock swap_lock;

// initializes the swap system
bool swap_init(void);
// swaps out a page to disk
size_t swap_out(void *frame_addr);
// swaps in a page from disk into memory
void swap_in(size_t sector, void *frame_addr);
