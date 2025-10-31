#include "vm/frame.h"

struct hash frame_table;         // hash table of all frames 
struct list frame_clock_list;    // eviction policy is clock algorithm
struct lock frame_lock;          // lock for frame table and clock list

unsigned frame_hash_func(struct hash_elem *e, void *aux) {
    struct frame *f = hash_entry(e, struct frame, hash_elem);
    return hash_bytes(&f->kpage_addr, sizeof(f->kpage_addr));
}

bool frame_less_func(struct hash_elem *a, struct hash_elem *b, void *aux) {
    struct frame *fa = hash_entry(a, struct frame, hash_elem);
    struct frame *fb = hash_entry(b, struct frame, hash_elem);
    return fa->kpage_addr < fb->kpage_addr;
}

void frame_init(void) {
    hash_init(&frame_table, frame_hash_func, frame_less_func, NULL);
    list_init(&frame_clock_list);
    lock_init(&frame_lock);
}

void *frame_alloc(void *user_vaddr, enum palloc_flags flags) {
    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        // TODO need to implement frame_evict instead of panicking
        PANIC("No free frames available, need to evict a frame TODO");

        // evict a frame so that kpage can make use of physical address returned by frame_evict
        kpage = frame_evict(NULL);
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
    new_frame->kpage_addr = kpage;
    new_frame->user_vaddr = user_vaddr;
    new_frame->spte = NULL;

    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &new_frame->hash_elem);
    list_push_back(&frame_clock_list, &new_frame->clock_elem);
    lock_release(&frame_lock);

    return kpage;
}
void frame_free(void* frame) {
    lock_acquire(&frame_lock);
    // look up the frame in the hash table
    struct frame f_lookup;
    f_lookup.kpage_addr = frame;
    struct hash_elem *he = hash_find(&frame_table, &f_lookup.hash_elem);
    // if found, remove from hash table and free resources
    if (he != NULL) {
        struct frame *f = hash_entry(he, struct frame, hash_elem);
        hash_delete(&frame_table, he);
        list_remove(&f->clock_elem);
        palloc_free_page(f->kpage_addr);
        free(f);
    }
    lock_release(&frame_lock);
}

void *frame_evict(void* frame_addr) {
    // TODO implement clock algorithm to evict a frame
    // for now, just return NULL to indicate failure
    return NULL;
}


