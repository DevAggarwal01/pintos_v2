#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <string.h>
#include <round.h>

/**
 * Hash function for supplemental page table entries.
 * Uses the user page address as the key.
 */
static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    const struct sup_page *p = hash_entry(e, struct sup_page, elem);
    return hash_bytes(&p->upage, sizeof p->upage);
}

/**
 * Comparison function for supplemental page table entries.
 * Compares based on user page addresses.
 */
static bool spt_comp_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct sup_page *pa = hash_entry(a, struct sup_page, elem);
    const struct sup_page *pb = hash_entry(b, struct sup_page, elem);
    return pa->upage < pb->upage;
}

/**
 * Initialize supplemental page table.
 * Basically just initializes the hash table.
 */
void spt_init(struct hash *spt) {
    hash_init(spt, spt_hash_func, spt_comp_func, NULL);
}

/**
 * Helper function to destroy a single supplemental page table entry.
 */
static void spt_destroy_entry(struct hash_elem *e, void *aux UNUSED) {
    struct sup_page *sp = hash_entry(e, struct sup_page, elem);
    if (!sp->loaded && sp->from_swap) {
        lock_acquire(&swap_lock);
        bitmap_set(swap_bitmap, sp->swap_slot, false);
        lock_release(&swap_lock);
    }
    free(sp);
}

/**
 * Destroy supplemental page table and free all entries.
 */
void spt_destroy(struct hash *spt) {
    lock_acquire(&thread_current()->spt_lock);
    hash_destroy (spt, spt_destroy_entry);
    lock_release(&thread_current()->spt_lock);
}

/**
 * Find the supplemental page entry for user address (rounded down to page boundary).
 */
struct sup_page* spt_find(struct hash *spt, void *upage){
    lock_acquire(&thread_current()->spt_lock);
    struct sup_page tmp;
    tmp.upage = pg_round_down(upage);
    // look up the entry in the hash table
    struct hash_elem *e = hash_find(spt, &tmp.elem);
    lock_release(&thread_current()->spt_lock);
    if (e == NULL) {
        return NULL;
    }
    return hash_entry(e, struct sup_page, elem);
}

/**
 * Insert a file-backed page entry (lazy load from exec).
 * Returns true on success, false on failure.
 */
bool spt_insert_file(struct hash *spt, 
                        void *upage, 
                        struct file *file,
                        off_t offset, 
                        uint32_t read_bytes, 
                        uint32_t zero_bytes, 
                        bool writable) {
    lock_acquire(&thread_current()->spt_lock);
    // allocate and initialize new sup_page entry
    struct sup_page *sp = malloc (sizeof *sp);
    if (sp == NULL) {
        // allocation failed
        lock_release(&thread_current()->spt_lock);
        return false;
    }
    // default versions of all sup_page fields
    sp->upage = pg_round_down(upage);
    sp->loaded = false;
    sp->writable = writable;
    sp->file = file;
    sp->offset = offset;
    sp->read_bytes = read_bytes;
    sp->zero_bytes = zero_bytes;
    sp->swap_slot = 0;
    sp->from_swap = false;
    // check for duplicates
    if (hash_find(spt, &sp->elem) != NULL) {
        free(sp);
        lock_release(&thread_current()->spt_lock);
        return false;
    }
    // insert into hash table
    bool ok = hash_insert(spt, &sp->elem) == NULL;
    if (!ok) {
        lock_release(&thread_current()->spt_lock);
        free (sp);
    }
    lock_release(&thread_current()->spt_lock);
    // return success or failure
    return ok;
}

/**
 * Insert a zeroed page entry (for stack pages and uninitialized pages).
 * Returns true on success, false on failure.
 */
bool spt_insert_zero (struct hash *spt, void *upage) {
    lock_acquire(&thread_current()->spt_lock);
    // allocate and initialize new sup_page entry
    struct sup_page *sp = malloc (sizeof *sp);
    if (sp == NULL) {
        // allocation failed
        lock_release(&thread_current()->spt_lock);
        return false;
    }
    // default versions of all sup_page fields
    sp->upage = pg_round_down(upage);
    sp->loaded = false;
    sp->writable = true;
    sp->file = NULL;
    sp->offset = 0;
    sp->read_bytes = 0;
    sp->zero_bytes = PGSIZE;
    sp->swap_slot = 0;
    sp->from_swap = false;
    // check for duplicates
    if (hash_find(spt, &sp->elem) != NULL) {
        free(sp);
        lock_release(&thread_current()->spt_lock);
        return false;
    }
    // insert into hash table
    bool ok = hash_insert(spt, &sp->elem) == NULL;
    if (!ok) {
        free (sp);
        lock_release(&thread_current()->spt_lock);
    }
    // return success or failure
    lock_release(&thread_current()->spt_lock);
    return ok;
}

/**
 * Load a page into memory (called on page fault).
 * Loads the page from file or swap into a newly allocated frame.
 * Returns true on success, false on failure.
 */
bool spt_load_page (struct sup_page *sp) {
    // check if we already hold the spt_lock
    bool already_had_lock = lock_held_by_current_thread(&thread_current()->spt_lock);
    if (!already_had_lock) {
        // acquire the lock if not held
       lock_acquire(&thread_current()->spt_lock);
    }
    struct thread *t = thread_current();
    // check if page is already loaded
    void *already = pagedir_get_page(t->pagedir, sp->upage);
    if (already != NULL) {
        // page already loaded
        sp->loaded = true;
        sp->from_swap = false;
        return true;
    }
    // allocate a frame for this page; retry once if allocation fails
    // [
    //   THIS PART OF THE CODE IS REQUIRED, DO NOT REMOVE. IF FRAME ALLOCATION FAILS,
    //   WE YIELD THE CPU AND TRY AGAIN TO AVOID PAGEFAULTS DURING HIGH MEMORY USAGE.
    //   THIS PART OF CODE IS PARTICULARLY IMPORTANT FOR PAGE-MERGE-STK.
    // ]
    void *kpage = frame_alloc(sp->upage, PAL_USER, sp);             
    if (kpage == NULL) {
        thread_yield();
        kpage = frame_alloc(sp->upage, PAL_USER, sp); 
        if (kpage == NULL) {
            // if second attempt fails, return false
            if (!already_had_lock) {
                lock_release(&thread_current()->spt_lock);
            }
            return false;
        }
    }
    // pin the frame during loading
    frame_pin(kpage);
    if (sp->from_swap) {
        // if page is in swap, load from swap
        swap_in (sp->swap_slot, kpage);
        sp->swap_slot = BITMAP_ERROR;
        sp->from_swap = false;
    } else if (sp->file != NULL) {
        // if page is file-backed, load from file
        lock_acquire(&file_lock);
        file_seek(sp->file, sp->offset);
        int bytes_read = file_read(sp->file, kpage, sp->read_bytes);
        lock_release(&file_lock);
        if (bytes_read != (int) sp->read_bytes) {
            // read failed: unpin then free
            frame_unpin(kpage);
            frame_free(kpage);
            if (!already_had_lock) {
                lock_release(&thread_current()->spt_lock);
            }
            return false;
        }
        // zero the remaining bytes
        memset((uint8_t*) kpage + sp->read_bytes, 0, sp->zero_bytes);
    } else {
        // zero page (for stack or uninitialized pages)
        memset(kpage, 0, PGSIZE);
    }
    // map the page into the process's page directory
    if (!pagedir_set_page(t->pagedir, sp->upage, kpage, sp->writable)){
        // map failed: unpin then free
        frame_unpin(kpage);
        frame_free(kpage);
        if (!already_had_lock) {
            lock_release(&thread_current()->spt_lock);
        }
        return false;
    }
    // mark the page as loaded
    sp->loaded = true;
    // unpin the frame after loading
    frame_unpin(kpage);
    if (!already_had_lock) {
        // release the lock if we acquired it
        lock_release(&thread_current()->spt_lock);
    }
    return true;
}

