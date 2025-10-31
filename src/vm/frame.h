#include "threads/thread.h"
#include "kernel/hash.h"
#include "kernel/list.h"
#include "threads/palloc.h"
#include "threads/synch.h"


// structure to store frame information
struct frame {
    struct thread *owner;           // thread that owns this frame
    void* kpage;                    // kernel page address
    void* user_vaddr;               // user virtual address mapped to this frame
    struct spt_entry *spte;         // supplemental page table entry associated with this frame
    struct hash_elem hash_elem;     // hash table element for frame table
    struct list_elem clock_elem;    // list element for clock algorithm
};

// initialize frame table and clock list
void frame_init(void);
// allocate a frame for a given user virtual address with specified flags
void* frame_alloc(void* user_vaddr, enum palloc_flags flags);
// free a given frame
void frame_free(void* frame);
// evict a frame using the clock algorithm
void* frame_evict(void* frame);
