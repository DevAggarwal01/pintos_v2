#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>

/* vm/swap.c
 *
 * --------------------------------------------------------------------------
 * SWAP SYSTEM IMPLEMENTATION
 * --------------------------------------------------------------------------
 * This module manages the swap space for virtual memory in PintOS.
 * It provides a simple mechanism to store and retrieve pages that are
 * evicted from physical memory (frames). Pages are written to and read from
 * a dedicated block device (BLOCK_SWAP) that acts as the swap partition.
 *
 * -------------------
 * DESIGN ASSUMPTIONS
 * -------------------
 *
 * 1. **Page and Sector Relationship**
 *    Each user page is 4 KB (PGSIZE), and each disk sector is 512 bytes.
 *    Therefore, one page occupies exactly 8 sectors (PGSIZE / BLOCK_SECTOR_SIZE).
 *    All read/write operations always handle one full page (8 contiguous sectors).
 *
 * 2. **Bitmap Representation**
 *    The swap bitmap tracks *pages*, not individual sectors.
 *    - One bit in the bitmap represents one page-sized slot (8 sectors).
 *    - This simplifies bookkeeping compared to a per-sector bitmap.
 *    - A bit set to 'true' indicates the slot is *occupied*.
 *    - A bit set to 'false' indicates the slot is *free*.
 *
 * 3. **Synchronization**
 *    A single global lock (`swap_lock`) protects all swap metadata,
 *    including the bitmap and the block device. This ensures that
 *    concurrent swap-in and swap-out operations are serialized safely.
 *
 * 4. **Swap Lifecycle**
 *    - `swap_init()` sets up the swap block device and bitmap.
 *    - `swap_out()` finds a free slot and writes an entire page to it.
 *    - `swap_in()` reads a full page from a slot back into memory and
 *      then frees the slot for reuse.
 *    - `swap_remove()` manually frees a slot (e.g., on process cleanup).
 *
 * 5. **Error Handling**
 *    - If the swap device is missing or full, the kernel panics.
 *    - The code assumes the swap partition is persistent across boots
 *      but is not shared between processes.
 *    - The swap system is not fault-tolerant; corruption or overlapping
 *      writes are considered kernel bugs.
 *
 * 6. **Consistency and Atomicity**
 *    - Each swap operation (in or out) operates on a *complete page*.
 *    - Partial reads/writes are never performed.
 *    - The lock ensures atomic updates to both bitmap and data.
 *
 * 7. **Integration Expectations**
 *    - The frame allocator (frame.c) calls `swap_out()` when evicting
 *      a frame.
 *    - The page fault handler (page.c) calls `swap_in()` when bringing
 *      a page back from disk.
 *    - Supplemental page tables store the swap slot index for each
 *      swapped-out page.
 *
 * With these assumptions, this implementation provides a minimal,
 * thread-safe swap layer suitable for PintOS Project 3 (Virtual Memory).
 * --------------------------------------------------------------------------
 */


// swap block device
struct block *swap_block;
// bitmap to track used/unused swap slots
static struct bitmap *swap_bitmap;
// lock for synchronization
static struct lock swap_lock;

// Each page is divided into this many 512-byte sectors
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/**
 * Initializes the swap system.
 * It basically does two things:
 * 1. it sets up the swap block device
 * 2. creates a bitmap to track free swap slots
 * Returns true on success, false if no swap device is available.
 */
bool
swap_init(void) {
    swap_block = block_get_role(BLOCK_SWAP);
    // check if swap block is available
    if (swap_block == NULL) {
        return false;
    }
    // calculate total swap slots
    size_t swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
    swap_bitmap = bitmap_create(swap_size);
    if (swap_bitmap == NULL) {
        return false;
    }

    bitmap_set_all(swap_bitmap, false);
    lock_init(&swap_lock);

    printf("Swap system initialized with %zu slots (%zu pages total).\n",
           swap_size, swap_size);

    return true;
}

/**
 * Swaps out a page to disk.
 * Finds a free slot in the swap area, writes the entire page (PGSIZE),
 * and returns the index of the slot used.
 * Panics or returns SIZE_MAX if no free slots remain.
 */
size_t
swap_out(void *frame_addr)
{
    ASSERT(swap_block != NULL);
    ASSERT(frame_addr != NULL);

    lock_acquire(&swap_lock);
    size_t free_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    lock_release(&swap_lock);

    if (free_index == BITMAP_ERROR)
    {
        PANIC("Out of swap space!");
    }

    // Write each sector of the page into the swap block
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_write(swap_block,
                    free_index * SECTORS_PER_PAGE + i,
                    (uint8_t *)frame_addr + i * BLOCK_SECTOR_SIZE);
    }

    return free_index;
}

/**
 * Swaps in a page from disk into memory.
 * Reads a page from swap slot (sector) into the frame at frame_addr.
 * The slot must be valid and previously written by swap_out.
 * After reading, the slot is automatically freed for reuse.
 */
void
swap_in(size_t sector, void *frame_addr)
{
    ASSERT(swap_block != NULL);
    ASSERT(frame_addr != NULL);

    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_read(swap_block,
                   sector * SECTORS_PER_PAGE + i,
                   (uint8_t *)frame_addr + i * BLOCK_SECTOR_SIZE);
    }

    swap_remove(sector);
}

/**
 * Frees the swap slot (sector) so it can be reused later.
 * Should be called after a page has been successfully swapped back in,
 * or when cleaning up process resources.
 */
void
swap_remove(size_t sector)
{
    ASSERT(swap_block != NULL);

    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, sector, false);
    lock_release(&swap_lock);
}
