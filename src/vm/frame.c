#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "lib/kernel/bitmap.h"

struct hash frame_table;         // hash table of all frames 
struct list frame_clock_list;    // eviction policy is clock algorithm
struct lock frame_lock;          // lock for frame table and clock list

static struct list_elem *clock_hand; 


unsigned frame_hash_func(struct hash_elem *e, void *aux) {
    struct frame *f = hash_entry(e, struct frame, hash_elem);
    return hash_bytes(&f->kpage, sizeof(f->kpage)); 
}

bool frame_less_func(struct hash_elem *a, struct hash_elem *b, void *aux) {
    struct frame *fa = hash_entry(a, struct frame, hash_elem);
    struct frame *fb = hash_entry(b, struct frame, hash_elem);
    return fa->kpage < fb->kpage;
} 

void frame_init(void) {
    hash_init(&frame_table, frame_hash_func, frame_less_func, NULL);
    list_init(&frame_clock_list);
    lock_init(&frame_lock);
    clock_hand = NULL;
}

void *frame_alloc(void *user_vaddr, enum palloc_flags flags, struct sup_page *spte) {
    ASSERT(spte != NULL);  // Defensive check

    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        kpage = frame_evict(NULL);  // NULL because we’re not reusing the old kpage
        if (kpage == NULL)
            return NULL;
    }

    struct frame *new_frame = malloc(sizeof(struct frame));
    if (new_frame == NULL) {
        palloc_free_page(kpage);
        return NULL;
    }

    new_frame->owner = thread_current();
    new_frame->kpage = kpage;
    new_frame->user_vaddr = user_vaddr;
    new_frame->spte = spte;
    new_frame->pin = true;

    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &new_frame->hash_elem);
    list_push_back(&frame_clock_list, &new_frame->clock_elem);
    lock_release(&frame_lock);

    return kpage;
}


void frame_pin(void *kpage) {
    lock_acquire(&frame_lock);
    struct frame *f = find_frame(kpage);
    if (f != NULL) {
        f->pin = true;
    }
    lock_release(&frame_lock);
}

void frame_unpin(void *kpage) {
    lock_acquire(&frame_lock);
    struct frame *f = find_frame(kpage);
    if (f != NULL) {
        f->pin = false;
    }
    lock_release(&frame_lock);
}

void frame_free(void* page_addr) {
    lock_acquire(&frame_lock);
    // look up the frame in the hash table
    struct frame f_lookup;
    f_lookup.kpage = page_addr;
    struct hash_elem *he = hash_find(&frame_table, &f_lookup.hash_elem);
    // if found, remove from hash table and free resources
    if (he != NULL) {
        struct frame *f = hash_entry(he, struct frame, hash_elem);
        hash_delete(&frame_table, he);
        if (f->clock_elem.prev != NULL && f->clock_elem.next != NULL)
            list_remove(&f->clock_elem);
        palloc_free_page(f->kpage);
        free(f);
    }
    lock_release(&frame_lock);
}

struct frame *find_frame(void *kpage) {
    bool held = lock_held_by_current_thread(&frame_lock);
    if (!held) {    
        lock_acquire(&frame_lock);
    }

    struct frame f_find;
    f_find.kpage = kpage;

    struct hash_elem *he = hash_find(&frame_table, &f_find.hash_elem);
    struct frame *res = NULL;
    if (he != NULL) {
        res = hash_entry(he, struct frame, hash_elem);
    }

    if (!held) {
        lock_release(&frame_lock);
    }
    return res;
}

/*
NOTE: must be called with frame_lock acquired
Returns: pointer to evicted frame, or NULL on failure
*/ 
void *choose_evicted_frame(void) {
    ASSERT(lock_held_by_current_thread(&frame_lock));
    if (list_empty(&frame_clock_list)) {
        return NULL;
    }
    // Initialize clock hand if needed
    if (clock_hand == NULL || clock_hand == list_end(&frame_clock_list)) {
        clock_hand = list_begin(&frame_clock_list);
    }
    while (true) {
        if (clock_hand == list_end(&frame_clock_list)) {
            clock_hand = list_begin(&frame_clock_list);
        }
        struct frame *f = list_entry(clock_hand, struct frame, clock_elem);
        // skip pinned frames
        if (f->pin || f->owner == NULL || f->owner->pagedir == NULL) {
            clock_hand = list_next(clock_hand);
            continue;
        }
        if (pagedir_is_accessed(f->owner->pagedir, f->user_vaddr)) {
            pagedir_set_accessed(f->owner->pagedir, f->user_vaddr, false);
            clock_hand = list_next(clock_hand);
            // give second chance, skip this frame for now
            continue;
        } else {
            // Advance hand for next time
            clock_hand = list_next(clock_hand);
            return f;
        }
        // clear accessed bit and advance
        pagedir_set_accessed(f->owner->pagedir, f->user_vaddr, false);
        clock_hand = list_next(clock_hand);
    }
}


void *frame_evict(void *frame_addr UNUSED) {
    lock_acquire(&frame_lock);
    struct frame *victim = choose_evicted_frame();
    if (!victim) {
        lock_release(&frame_lock);
        return NULL;
    }

    /* mark pinned so nobody else will touch this page while we do I/O */
    victim->pin = true;

    /* Get spte pointer now (may be NULL). We compute dirty now too. */
    struct sup_page *spte = victim->spte;
    bool was_dirty = false;
    if (victim->owner != NULL && victim->owner->pagedir != NULL)
        was_dirty = pagedir_is_dirty(victim->owner->pagedir, victim->user_vaddr);

    /* We'll do the actual disk I/O without holding frame_lock. */
    lock_release(&frame_lock);

    size_t swap_slot = BITMAP_ERROR;
    if (spte != NULL && (was_dirty || spte->file == NULL || spte->from_swap)) {
        swap_slot = swap_out(victim->kpage);
        if (swap_slot == BITMAP_ERROR) {
            /* swap failed: release pin and abort */
            lock_acquire(&frame_lock);
            victim->pin = false;
            lock_release(&frame_lock);
            return NULL;
        }
    }

    /* Re-acquire lock to finalize eviction */
    lock_acquire(&frame_lock);

    /* Re-validate victim is still in the frame table (not freed or replaced). */
    struct frame *f_check = find_frame(victim->kpage);
    if (f_check != victim) {
        /* Something changed while we did I/O: undo or abort. */
        if (swap_slot != BITMAP_ERROR) {
            /* if we used a swap slot, mark it free */
            lock_acquire(&swap_lock);
            bitmap_set(swap_bitmap, swap_slot, false);
            lock_release(&swap_lock);
        }
        /* if the frame still exists, clear pin; otherwise it's already gone */
        if (f_check)
            f_check->pin = false;
        lock_release(&frame_lock);
        return NULL;
    }

    /* If we actually swapped, update spte */
    if (spte != NULL && swap_slot != BITMAP_ERROR) {
        spte->swap_slot = swap_slot;
        spte->from_swap = true;
    } else if (spte != NULL) {
        /* no swap used; if file-backed and not dirty, we can just discard content */
    }

    /* Remove mapping from page directory and mark spte not loaded. */
    if (victim->owner && victim->owner->pagedir)
        pagedir_clear_page(victim->owner->pagedir, victim->user_vaddr);
    if (spte) spte->loaded = false;

    void *reuse_kpage = victim->kpage;

    /* Remove frame from bookkeeping and free frame struct (kpage is reused). */
    hash_delete(&frame_table, &victim->hash_elem);
    list_remove(&victim->clock_elem);
    free(victim);

    /* If list empty or clock hand pointed at removed element the choose code should handle it */
    lock_release(&frame_lock);
    return reuse_kpage;
}

static void really_free_frame(struct frame *f) {
    if (f->freed) return;
    f->freed = true;
    free(f);
}


void frame_free_all(struct thread *t) {
    lock_acquire(&frame_lock);

    struct list_elem *e = list_begin(&frame_clock_list);
    while (e != list_end(&frame_clock_list)) {
        struct list_elem *next = list_next(e);
        struct frame *f = list_entry(e, struct frame, clock_elem);

        if (f->owner == t) {
            /* If the clock hand points to this element, advance it to avoid
               leaving clock_hand pointing at a removed element. */
            if (clock_hand == e) {
                /* Prefer to advance to next; if that is end, wrap to begin.
                   If the list will become empty, set clock_hand = NULL. */
                if (next != list_end(&frame_clock_list)) {
                    clock_hand = next;
                } else {
                    /* find a new begin (which might be the same element
                       if there are duplicates) or NULL if the list will be empty. */
                    if (list_begin(&frame_clock_list) == e) {
                        clock_hand = NULL;
                    } else {
                        clock_hand = list_begin(&frame_clock_list);
                    }
                }
            }

            /* Remove from frame structures (hash and clock list). */
            hash_delete(&frame_table, &f->hash_elem);
            list_remove(&f->clock_elem);

            /* Do NOT free the kpage here. pagedir_destroy (or other
               owner cleanup) will free kernel pages. Prevent double-free
               by clearing the pointer and freeing the frame struct. */
            // free(f);
            really_free_frame(f);
        }

        e = next;
    }

    /* If we've removed everything, ensure clock_hand is NULL. */
    if (list_empty(&frame_clock_list))
        clock_hand = NULL;

    lock_release(&frame_lock);
}


struct frame *frame_get(void *user_vaddr, enum palloc_flags flags) {
    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        kpage = frame_evict(kpage);
        if (kpage == NULL)
            return NULL;
    }

    struct frame *new_frame = malloc(sizeof(struct frame));
    if (new_frame == NULL) {
        palloc_free_page(kpage);
        return NULL;
    }

    new_frame->owner = thread_current();
    new_frame->kpage = kpage;
    new_frame->user_vaddr = user_vaddr;
    new_frame->spte = NULL;
    new_frame->pin = false;

    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &new_frame->hash_elem);
    list_push_back(&frame_clock_list, &new_frame->clock_elem);
    lock_release(&frame_lock);

    return new_frame; 
}


