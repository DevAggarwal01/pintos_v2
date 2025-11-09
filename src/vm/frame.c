#include "lib/kernel/bitmap.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

// hash table of all frames 
struct hash frame_table;
// eviction policy is clock algorithm
struct list frame_clock_list;
// lock for frame table and clock list
struct lock frame_lock;
// clock hand for clock algorithm
static struct list_elem *clock_hand; 

/**
 * Hash function for frame table entries.
 * Uses the kernel page address as the key.
 */
static unsigned frame_hash_func(struct hash_elem *e, void *aux) {
    struct frame *f = hash_entry(e, struct frame, hash_elem);
    return hash_bytes(&f->kpage, sizeof(f->kpage));
}

/**
 * Comparison function for frame table entries.
 * Compares based on kernel page addresses.
 */
static bool frame_comp_func(struct hash_elem *a, struct hash_elem *b, void *aux) {
    struct frame *fa = hash_entry(a, struct frame, hash_elem);
    struct frame *fb = hash_entry(b, struct frame, hash_elem);
    return fa->kpage < fb->kpage;
}

/**
 * Initialize frame table and clock list.
 * Sets up the necessary data structures and lock. clock_hand is initialized to NULL.
 */
void frame_init(void) {
    hash_init(&frame_table, frame_hash_func, frame_comp_func, NULL);
    list_init(&frame_clock_list);
    lock_init(&frame_lock);
    clock_hand = NULL;
}


/**
 * Allocate a frame for a given user virtual address with specified flags.
 * Returns the kernel page address of the allocated frame, or NULL on failure.
 */
void *frame_alloc(void *user_vaddr, enum palloc_flags flags, struct sup_page *spte) {
    // sanity check
    ASSERT(spte != NULL);
    // try to allocate a physical page
    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        // no free page, need to evict one
        kpage = frame_evict();
        if (kpage == NULL) {
            // eviction failed
            return NULL;
        }
    }
    // create and initialize frame structure
    struct frame *new_frame = malloc(sizeof(struct frame));
    if (new_frame == NULL) {
        // allocation failed
        palloc_free_page(kpage);
        return NULL;
    }
    // initialize frame fields
    new_frame->owner = thread_current();
    new_frame->kpage = kpage;
    new_frame->user_vaddr = user_vaddr;
    new_frame->spte = spte;
    new_frame->pin = true;
    // insert into frame table and clock list
    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &new_frame->hash_elem);
    list_push_back(&frame_clock_list, &new_frame->clock_elem);
    lock_release(&frame_lock);
    // return the kernel page address
    return kpage;
}


/**
 * Free a given frame.
 * Remove the frame from the frame table and clock list.
 */
void frame_free(void* page_addr) {
    lock_acquire(&frame_lock);
    // look up the frame in the hash table
    struct frame f_lookup;
    f_lookup.kpage = page_addr;
    struct hash_elem *e = hash_find(&frame_table, &f_lookup.hash_elem);
    // if found, remove from hash table and free resources
    if (e != NULL) {
        struct frame *f = hash_entry(e, struct frame, hash_elem);
        hash_delete(&frame_table, e);
        if (f->clock_elem.prev != NULL && f->clock_elem.next != NULL)
            list_remove(&f->clock_elem);
        palloc_free_page(f->kpage);
        free(f);
    }
    lock_release(&frame_lock);
}


/**
 * Free all frames associated with a thread.
 * Iterates through the frame table and removes all frames owned by the specified thread.
 */
void frame_free_all(struct thread *t) {
    lock_acquire(&frame_lock);
    // iterate through frame_clock_list to find frames owned by thread t
    struct list_elem *e = list_begin(&frame_clock_list);
    while (e != list_end(&frame_clock_list)) {  
        struct list_elem *next = list_next(e); 
        struct frame *f = list_entry(e, struct frame, clock_elem);

        if (f->owner == t) { 
            // adjust clock_hand if it points to the frame being removed
            if (clock_hand == e) {
                // advance clock_hand to next element
                if (next != list_end(&frame_clock_list)) {
                    clock_hand = next;
                } else {
                    // wrap around to beginning
                    if (list_begin(&frame_clock_list) == e) {
                        clock_hand = NULL;
                    } else {
                        clock_hand = list_begin(&frame_clock_list);
                    }
                }
            }
            // remove frame from hash table and clock list
            hash_delete(&frame_table, &f->hash_elem);
            list_remove(&f->clock_elem);
            // clear page from owner's page directory
            if (f->owner->pagedir != NULL) {
                pagedir_clear_page(f->owner->pagedir, f->user_vaddr);
            }
            // free the physical page and frame structure
            palloc_free_page(f->kpage);
            free(f);
        }
        // move to next element
        e = next;
    }
    // if list is now empty, reset clock_hand
    if (list_empty(&frame_clock_list)) {
        clock_hand = NULL;
    }
    lock_release(&frame_lock);
}


/**
 * Find a frame by its kernel page address.
 * Returns the frame structure if found, or NULL if not found.
 */
struct frame *find_frame(void *kpage) {
    // check if current thread already holds the frame_lock
    bool held = lock_held_by_current_thread(&frame_lock);
    if (!held) {    
        // if not, acquire the lock
        lock_acquire(&frame_lock);
    }
    // look up the frame in the hash table
    struct frame f_find;
    f_find.kpage = kpage;
    struct hash_elem *e = hash_find(&frame_table, &f_find.hash_elem);
    struct frame *result = NULL;
    if (e != NULL) {
        result = hash_entry(e, struct frame, hash_elem);
    }
    // release the lock if it was not held before
    if (!held) {
        lock_release(&frame_lock);
    }
    // return the found frame
    return result;
}


/**
 * Choose a frame to evict using the clock algorithm.
 * Returns the frame selected for eviction.
 */
struct frame * choose_evicted_frame(void) {
    // sanity check
    ASSERT(lock_held_by_current_thread(&frame_lock));
    // if clock list is empty, return NULL
    if (list_empty(&frame_clock_list)) {
        clock_hand = NULL;
    }
    // initialize clock_hand if needed
    if (clock_hand == NULL || clock_hand == list_end(&frame_clock_list))
        clock_hand = list_begin(&frame_clock_list);
    // iterate through frames using clock algorithm
    while (true) {
        // wrap around clock_hand if at end
        if (clock_hand == list_end(&frame_clock_list)) {
            clock_hand = list_begin(&frame_clock_list);
        }
        // get the current frame
        struct frame *f = list_entry(clock_hand, struct frame, clock_elem);
        // skip pinned frames or frames with no owner/page directory
        if (f->pin || f->owner == NULL || f->owner->pagedir == NULL) {
            clock_hand = list_next(clock_hand);
            continue;
        }
        // check accessed bit: if set, clear it and advance clock hand [SECOND CHANCE]
        if (pagedir_is_accessed(f->owner->pagedir, f->user_vaddr)) {
            pagedir_set_accessed(f->owner->pagedir, f->user_vaddr, false);
            clock_hand = list_next(clock_hand);
            continue;
        }
        // found a victim frame to evict
        struct frame *victim = f;
        clock_hand = list_next(clock_hand);
        return victim;
    }
}

/**
 * Evict a frame using the clock algorithm.
 * Returns the kernel page address of the evicted frame, or NULL on failure.
 */
void *frame_evict(void) {
    lock_acquire(&frame_lock);
    // choose a victim frame to evict
    struct frame *victim = choose_evicted_frame();
    if (!victim) {
        // no suitable frame found
        lock_release(&frame_lock);
        return NULL;
    }
    // pin the victim frame during eviction
    victim->pin = true;
    // determine if the page was dirty
    bool was_dirty = false;
    if (victim->owner && victim->owner->pagedir) {
        was_dirty = pagedir_is_dirty(victim->owner->pagedir, victim->user_vaddr);
    }
    // release frame lock before performing swap I/O
    bool already_had_lock = lock_held_by_current_thread(&file_lock);
    lock_release(&frame_lock);
    // get the supplemental page table entry
    struct sup_page *spte = victim->spte;
    size_t swap_slot = BITMAP_ERROR;
    // decide whether to swap out the page
    if (spte != NULL && (was_dirty || spte->file == NULL || spte->from_swap)) {
        // if holding file lock, avoid deadlock by not swapping
        if (already_had_lock) {
            lock_acquire(&frame_lock);
            victim->pin = false;
            lock_release(&frame_lock);
            return NULL;
        }
        // perform swap out
        swap_slot = swap_out(victim->kpage);
        if (swap_slot == BITMAP_ERROR) {
            lock_acquire(&frame_lock);
            victim->pin = false;
            lock_release(&frame_lock);
            return NULL;
        }
    }
    lock_acquire(&frame_lock);
    // double-check that the victim frame is still valid
    struct frame *f_check = find_frame(victim->kpage);
    // if not, abort eviction
    if (f_check != victim) {
        if (f_check) {
            f_check->pin = false;
        }
        lock_release(&frame_lock);
        return NULL;
    }
    // update supplemental page table entry
    if (spte != NULL && swap_slot != BITMAP_ERROR) {
        spte->swap_slot = swap_slot;
        spte->from_swap = true;
        spte->loaded = false;
        // if the page was file-backed and dirty, clear the file pointer
        if (spte->file != NULL && was_dirty) {
            spte->file = NULL;
        }
    }
    // clear page from owner's page directory
    if (victim->owner && victim->owner->pagedir) {
        pagedir_clear_page(victim->owner->pagedir, victim->user_vaddr);
    }
    // mark the supplemental page table entry as unloaded
    if (spte) {
        spte->loaded = false;
    }
    // prepare to reuse the frame's physical page
    void *reuse_kpage = victim->kpage;
    // remove the victim frame from frame table and clock list
    hash_delete(&frame_table, &victim->hash_elem);
    list_remove(&victim->clock_elem);
    free(victim);
    lock_release(&frame_lock);
    // return the kernel page address for reuse
    return reuse_kpage;
}

/**
 * Pin a frame to prevent eviction.
 */
void frame_pin(void *kpage) {
    lock_acquire(&frame_lock);
    struct frame *f = find_frame(kpage);
    if (f != NULL) {
        f->pin = true;
    }
    lock_release(&frame_lock);
}

/**
 * Unpin a frame to allow eviction.
 */
void frame_unpin(void *kpage) {
    lock_acquire(&frame_lock);
    struct frame *f = find_frame(kpage);
    if (f != NULL) {
        f->pin = false;
    }
    lock_release(&frame_lock);
}