#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

/* 
 * --------------------------------------------------------------------------------------------
 * SOME IMPORTANT THINGS TO NOTE HERE:
 * - Each user page is 4 KB (PGSIZE), and each disk sector is 512 bytes. Therefore, one page 
 *   occupies exactly 8 sectors (PGSIZE / BLOCK_SECTOR_SIZE). All read/write operations must
 *   always handle one full page (8 contiguous sectors).
 * 
 * - The swap bitmap tracks pages, not individual sectors. This means that one bit in the 
 *   bitmap represents one page-sized slot (8 sectors).
 * 
 * - Each swap operation (in or out), thereforce, must operats on a complete page. Partial 
 *   reads/writes are never performed. The lock must always be used!
 * --------------------------------------------------------------------------------------------
 */


// swap block device
struct block *swap_block;
// bitmap to track used/unused swap slots
struct bitmap *swap_bitmap;
// lock for synchronization
struct lock swap_lock;

// number of sectors per page
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/**
 * Initializes the swap system.
 * It basically does two things:
 * 1. it sets up the swap block device
 * 2. creates a bitmap to track free swap slots
 * Returns true on success, false if no swap device is available.
 */
bool swap_init(void) {
    // get the swap block device; if not available, return false
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL) {
        return false;
    }
    // calculate total swap slots and create bitmap; if not created, return false
    size_t swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
    swap_bitmap = bitmap_create(swap_size);
    if (swap_bitmap == NULL) {
        return false;
    }
    bitmap_set_all(swap_bitmap, false);
    // initialize the lock
    lock_init(&swap_lock);
    // successfully initialized swap system!
    return true;
}

/**
 * Swaps out a page to disk.
 * Finds a free slot in the swap area, writes the entire 
 * page (PGSIZE), and returns the index of the slot used.
 * NOTE THAT THIS OPERATION IS MEMORY TO DISK.
 */
size_t swap_out(void *frame_addr) {
    // sanity checks
    ASSERT(swap_block != NULL);
    ASSERT(frame_addr != NULL);
    // find a free slot in the swap bitmap
    lock_acquire(&swap_lock);
    size_t free_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    lock_release(&swap_lock);
    // if no free slot found, return error
    if (free_index == BITMAP_ERROR){
        return BITMAP_ERROR;
    }
    // write each sector of the page into the swap block
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write(swap_block, free_index * SECTORS_PER_PAGE + i, (uint8_t *)frame_addr + i * BLOCK_SECTOR_SIZE);
    }
    // return the index of the swap slot used
    return free_index;
}

/**
 * Swaps in a page from disk into memory.
 * Reads a page from swap slot (sector) into the frame at 
 * frame_addr. After reading, this slot is freed for reuse.
 * NOTE THAT THIS OPERATION IS DISK TO MEMORY.
 */
void swap_in(size_t sector, void *frame_addr) {
    // sanity checks
    ASSERT(swap_block != NULL);
    ASSERT(frame_addr != NULL);
    ASSERT(sector != BITMAP_ERROR);
    // printf("Swapping in from slot %zu\n", sector);
    // read each sector of the page from the swap block
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_read(swap_block, sector * SECTORS_PER_PAGE + i, (uint8_t *)frame_addr + i * BLOCK_SECTOR_SIZE);
    }
    // free the swap slot after reading
    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, sector, false);
    lock_release(&swap_lock);
}
