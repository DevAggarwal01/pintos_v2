#include "filesys/file.h"
#include <hash.h>
#include <stdbool.h>
#include <stdint.h>

// supplemental page table entry
struct sup_page {
    void *upage;             // user virtual address (page-aligned)
    bool loaded;             // is page currently loaded in a frame?
    bool writable;           // is the page writable?
    struct hash_elem elem;   // hash table element

    // file-backed page information 
    // (file-backed basically means lazy that this page is from an executable file)
    struct file *file;       // executable file (NULL if not file-backed).
    off_t offset;            // offset in file to load from.
    uint32_t read_bytes;     // bytes to read from file.
    uint32_t zero_bytes;     // bytes to set to zero after file bytes.

    // swap-backed page information 
    // (swap-backed basically means page was swapped out to disk)
    size_t swap_slot;        // swap slot index (if page is swapped out)
    bool from_swap;          // true if page is currently in swap
};

// initialize supplemental page table
void spt_init (struct hash *spt);
// destroy supplemental page table and free all entries
void spt_destroy (struct hash *spt);
// insert a file-backed page entry
bool spt_insert_file (struct hash *spt, void *upage, struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
// insert a zeroed page entry
bool spt_insert_zero (struct hash *spt, void *upage);
// find the supplemental page entry for user address (rounded down to page boundary)
struct sup_page *spt_find (struct hash *spt, void *upage);
// load the page into memory (from file or swap)
bool spt_load_page (struct sup_page *sp);
