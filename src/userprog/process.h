#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


/**
 * Struct to track a relationship between a parent and a child process.
 */
struct child_record {
    tid_t parent_tid;               // parent thread ID
    tid_t child_tid;                // child thread ID
    int exit_code;                  // exit status
    bool exited;                    // if the child has exited
    bool waited;                    // if the parent has already waited
    bool loaded;                    // if the child successfully loaded its executable
    struct list_elem elem_child;    // for representing in parent->children list
    int refcnt;                     // to avoid child and parent simultaneously freeing the same child record
    struct semaphore start_sema;    // child waits until parent finishes setup
    struct semaphore load_sema;     // parent waits until child finishes loading
    struct semaphore exit_sema;     // parent waits until child exits
};

/*
* Struct to pass information to the process_start function
*/
struct start_info {
    char *fn_copy;              // copy of the file name (command line)
    struct child_record *rec;   // child record for this process
    struct thread *parent;      // parent thread pointer
}; 

#endif /* userprog/process.h */
