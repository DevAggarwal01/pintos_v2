#include "threads/thread.h"
#include <hash.h>
#include <list.h>

struct frame {
  void *kpage;
  void *upage;     // user 
  struct thread *owner;     // address space that maps upage->kpage
  struct spt_entry *spte;
  struct hash_elem  hash_elem;
  struct list_elem  clock_elem;
};

void frame_init(void);
void *frame_alloc(enum palloc_flags flags, struct spt_entry *spte, void *upage);
void frame_free(void *kpage);   // free physical page + metadata