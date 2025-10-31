#include <stdbool.h>
#include <stddef.h>
#include "threads/thread.h"
#include "kernel/hash.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/swap.h"


// Page types for supplemental page table entries.
enum spt_page_type {
    SPT_PAGE_FILE,          // file-backed page
    SPT_PAGE_SWAP,          // page is swapped out
    SPT_PAGE_ANONYMOUS      // anonymous page
};

// structure for supplemental page table entry
struct spt_entry {
    void *upage;                    // user virtual address (page-aligned)
    enum spt_page_type type;        // page type
    bool writable;                  // is page writable?
    bool loaded;                    // is page currently loaded in physical memory?
    void* kernel_vaddr;             // kernel virtual address if loaded; NULL otherwise
    struct hash_elem hash_elem;     // hash table element

    // file-backed fields (valid when type == SPT_PAGE_FILE)
    struct file *file;         // file from which to load this page
    off_t ofs;                 // offset in file to read from
    size_t read_bytes;         // bytes to read from file
    size_t zero_bytes;         // bytes to zero after reading

    // swap-backed fields (valid when type == SPT_PAGE_SWAP)
    size_t swap_slot;          // swap slot index
};

/* Per-process SPT helper API ----------------------------------------------*/
/* Initialize supplemental page table (call at process/thread creation). */
void spt_init(struct hash *spt);

/* Destroy SPT: free all spt_entry structures and release resources.
   This function will call page_unload() where appropriate. */
void spt_destroy(struct hash *spt);

/* Find an entry by user virtual address (not necessarily page aligned).
   Returns NULL if not present. */
struct spt_entry *spt_find(struct hash *spt, void *addr);

/* Insert a new entry (must not already exist). Returns true on success. */
bool spt_insert(struct hash *spt, struct spt_entry *entry);

/* Remove an entry from the SPT and free it (unload page if loaded).
   Returns true if removed, false if not present. */
bool spt_remove(struct hash *spt, struct spt_entry *entry);