#include "vm/page.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <string.h>
#include <round.h>
#include "userprog/syscall.h"

/**
 * Hash function for supplemental page table entries.
 * Uses the user page address as the key.
 */
static unsigned sup_page_hash (const struct hash_elem *e, void *aux UNUSED) {
    // get the sup_page struct from hash_elem
    const struct sup_page *p = hash_entry(e, struct sup_page, elem);
    // return hash of the user page address
    return hash_bytes(&p->upage, sizeof p->upage);
}

/**
 * Comparison function for supplemental page table entries.
 * Compares based on user page addresses.
 */
static bool sup_page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct sup_page *pa = hash_entry(a, struct sup_page, elem);
    const struct sup_page *pb = hash_entry(b, struct sup_page, elem);
    return pa->upage < pb->upage;
}

/**
 * Initialize supplemental page table.
 * Basically just initializes the hash table.
 */
void spt_init (struct hash *spt) {
    hash_init (spt, sup_page_hash, sup_page_less, NULL);
}

spt_destroy_entry(struct hash_elem *e, void *aux UNUSED) {
    struct sup_page *sp = hash_entry(e, struct sup_page, elem);
    if (sp->from_swap) {
        lock_acquire(&swap_lock);
        bitmap_set(swap_bitmap, sp->swap_slot, false);
        lock_release(&swap_lock);
    }
    free(sp);
}

/**
 * Destroy supplemental page table and free all entries.
 */
void spt_destroy (struct hash *spt) {
    lock_acquire(&thread_current()->spt_lock);
    hash_destroy (spt, spt_destroy_entry);
    lock_release(&thread_current()->spt_lock);
}

/**
 * Find the supplemental page entry for user address (rounded down to page boundary).
 */
struct sup_page* spt_find (struct hash *spt, void *upage){
    lock_acquire(&thread_current()->spt_lock);
    struct sup_page tmp;
    tmp.upage = pg_round_down(upage);
    struct hash_elem *e = hash_find(spt, &tmp.elem);
    lock_release(&thread_current()->spt_lock);
    return e ? hash_entry(e, struct sup_page, elem) : NULL;
}

/**
 * Insert a file-backed page entry (lazy load from exec).
 * Returns true on success, false on failure.
 */
bool spt_insert_file (struct hash *spt, 
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
    // allocate and initialize new sup_page entry
    lock_acquire(&thread_current()->spt_lock);
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
    // get current thread and allocate a frame for the page
    struct thread *t = thread_current();
    void *kpage = frame_alloc(sp->upage, PAL_USER, sp);
    if (kpage == NULL) {
        // frame allocation failed
        return false;
    }
    // don't let this page get evicted while loading
    frame_pin(kpage);
    // load the page data
    memset(kpage, 0, PGSIZE); 
    if (sp->from_swap) {
        // page was swapped out, read from swap
        swap_in (sp->swap_slot, kpage);
    } else if (sp->file != NULL) {
        // page is from executable, read data from this file
        lock_acquire(&file_lock);
        file_seek(sp->file, sp->offset);
        int bytes_read = file_read(sp->file, kpage, sp->read_bytes);
        lock_release(&file_lock);
        if(bytes_read != (int) sp->read_bytes) {
            frame_free (kpage);
            return false;
        }
        memset((uint8_t*) kpage + sp->read_bytes, 0, sp->zero_bytes);
    } else {
        // page is zeroed
        memset(kpage, 0, PGSIZE);
    }
    // add the page to the process's page directory
    if (!pagedir_set_page(t->pagedir, sp->upage, kpage, sp->writable)){
        // failed to map page, free frame and return false
        frame_free (kpage);
        return false;
    }
    // update supplemental page table entry
    sp->loaded = true;
    sp->from_swap = false;
    frame_unpin(kpage);  // allow this frame to be evicted now that loading is over
    // return success
    return true;
}
