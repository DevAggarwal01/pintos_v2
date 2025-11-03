#include "vm/frame.h"
#include "vm/page.h"
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

void *frame_alloc(void *user_vaddr, enum palloc_flags flags) {
    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        // evict a frame so that kpage can make use of physical address returned by frame_evict
        kpage = frame_evict(kpage);
        if (kpage == NULL) {
            return NULL;
        }
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
        list_remove(&f->clock_elem);
        palloc_free_page(f->kpage);
        free(f);
    }
    lock_release(&frame_lock);
}

struct frame *find_frame(void *kpage) {
    struct frame f_find;
    f_find.kpage = kpage;
    struct hash_elem *he = hash_find(&frame_table, &f_find.hash_elem);
    if (he != NULL) {
        return hash_entry(he, struct frame, hash_elem);
    }
    return NULL;
}
/*
NOTE: must be called with frame_lock acquired
Returns: pointer to evicted frame, or NULL on failure
*/ 
void *choose_evicted_frame() {
    if(list_empty(&frame_clock_list)) {
        lock_release(&frame_lock);
        return NULL;
    }
    if (clock_hand == NULL) {
        clock_hand = list_begin(&frame_clock_list);
    }
    while (true) {
        if(clock_hand == list_end(&frame_clock_list)) {
            clock_hand = list_begin(&frame_clock_list);
        }
        struct frame *f = list_entry(clock_hand, struct frame, clock_elem);
        if(f->pin) // don't evict if pinned
            continue;
        clock_hand = list_next(clock_hand);
        // if it hasn't been accessed evict it
        if (!pagedir_is_accessed(f->owner->pagedir, f->user_vaddr)) {
            // found a victim frame
            lock_release(&frame_lock);
            return f;
        }
        // reset accessed bit since clock hand has reached it and move on
        pagedir_set_accessed(f->owner->pagedir, f->user_vaddr, false);
        clock_hand = list_next(clock_hand);
        if (clock_hand == NULL) {
            clock_hand = list_begin(&frame_clock_list);
        }
    }
}

void *frame_evict(void* frame_addr) {
    // TODO implement clock algorithm to evict a frame
    // for now, just return NULL to indicate failure
    lock_acquire(&frame_lock);
    struct frame *victim_frame = choose_evicted_frame();
    if(!victim_frame) {
        lock_release(&frame_lock);
        return NULL;
    }
    struct sup_page *spte = victim_frame->spte;
    if(spte == NULL) {
        // should not happen
        lock_release(&frame_lock);
        return NULL;
    }
    // if its been written to after loading, need to swap out since memory copy and file copy are not the same anymore
    bool dirty = pagedir_is_dirty(victim_frame->owner->pagedir, victim_frame->user_vaddr);
    // if there is no file backing, then need to swap out to save it somewhere
    // frames that have a backup file and are not dirty do not need to be saved in swap, they can be discarded
    if(dirty || spte->file == NULL) {
        // swap out the page to disk
        size_t swap_slot = swap_out(victim_frame->kpage);
        if (swap_slot == BITMAP_ERROR) {
            // swap out failed
            lock_release(&frame_lock);
            return NULL;
        }
        spte->swap_slot = swap_slot;
        spte->from_swap = true;
    }
    
    // remove from page directory
    pagedir_clear_page(victim_frame->owner->pagedir, victim_frame->user_vaddr);
    spte->loaded = false;

    // reuse the kernel page and free resources
    void *reuse_page = victim_frame->kpage;
    hash_delete(&frame_table, &victim_frame->hash_elem);
    list_remove(&victim_frame->clock_elem);
    free(victim_frame);

    lock_release(&frame_lock);
    return reuse_page;
}
