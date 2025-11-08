#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>

// the function that handles all system calls
static void syscall_handler (struct intr_frame *);
// lock for file system operations
struct lock file_lock;


/**
 * Initializes the system call system by setting the system call interrupt gate
 * The method must be called exactly once during kernel startup, before user processes.
 */
void syscall_init (void) {
    // initialize the syscall handler.
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    // initialize the file lock
    lock_init(&file_lock);
}

/**
 * Exits the current process with the given status code.
 */
void system_exit (int status) {
    // get the current thread and set its exit code
    struct thread *t = thread_current();
    t->exit_code = status;
    // print exit message and terminate the thread
    printf("%s: exit(%d)\n", t->name, status);
    process_exit();
    thread_exit();
}

/**
 * Translates a user virtual address to a kernel page.
 * Returns NULL if the address is invalid.
 */
static uint8_t *addr_to_page(const void *useraddr) {
    // check for null and that the address is in user address range
    if (useraddr == NULL || !is_user_vaddr(useraddr)) {
        return NULL;
    }
    // look up the page in the current thread's page directory
    return pagedir_get_page(thread_current()->pagedir, useraddr);
}

/**
 * Copies data from user space to kernel space.
 * Returns true on success, false if any byte could not be accessed.
 */
static bool copy_data(void *kernel_dst, const void *user_src, size_t size) {
    // create pointers for source and destination
    const uint8_t *user_ptr = user_src;
    uint8_t *kernel_ptr = kernel_dst;
    uint8_t *end = user_ptr + size;
    // validate the entire user memory range
    if (user_ptr == NULL || !is_user_vaddr(user_ptr) || !is_user_vaddr(end - 1)) {
        return false;
    }
    // for all pages in the range, ensure they are present (load from swap if necessary)
    for (void *page = pg_round_down(user_ptr); page < (void *)end; page = (uint8_t *)page + PGSIZE) {
        // if page is already present, continue
        if (addr_to_page(page) != NULL) {
            continue;
        }
        // page not present; try to load it from the supplemental page table
        struct thread *t = thread_current();
        struct sup_page *sp = spt_find(&t->spt, page);
        if (sp == NULL) {
            // no spt entry; check if it's a stack growth
            uintptr_t fault_u = (uintptr_t) page;
            uintptr_t esp_u = (uintptr_t) t->esp;
            uintptr_t phys_base_u = (uintptr_t) PHYS_BASE;
            if (fault_u < phys_base_u && fault_u >= esp_u - 32) {
                // attempt to grow the stack by inserting a zeroed page
                if (!spt_insert_zero(&t->spt, page)) {
                    return false;
                }
                sp = spt_find(&t->spt, page);
            }
            if (sp == NULL) {
                // still no spt entry; invalid pointer
                return false;
            }
        }
        // load the page into memory
        if (!spt_load_page(sp)) {
            return false;
        }
    }
    // all pages validated and loaded; now safe to copy
    memcpy(kernel_dst, user_ptr, size);
    // successfully copied all bytes
    return true;
}

/**
 * Copies a null-terminated string from user space to kernel space.
 * Returns pointer to kernel string on success, NULL on failure.
 */
static bool copy_string(char *kernel_dst, const char *user_src) {
    // check for null and that the address is in user address range
    if (user_src == NULL || !is_user_vaddr(user_src)) {
        return false;
    }
    // then, copy byte by byte up to a reasonable limit (128 bytes)
    for (size_t i = 0; i < 128; i++) {
        void *page = pg_round_down(user_src + i);
        // ensure the page is present
        if (addr_to_page(page) == NULL) {
            struct sup_page *sp = spt_find(&thread_current()->spt, page);
            if (sp == NULL) {
                // no mapping and no spt entry, so invalid pointer
                system_exit(-1);
            }
            if (!spt_load_page(sp)) {
                // couldn't load backing page
                system_exit(-1);
            }
        }
        // now safe to access the byte without risking a kernel-mode page fault
        char c = user_src[i];
        kernel_dst[i] = c;
        if (c == '\0') {
            // successfully copied the string
            return true;
        }
    }
    // no terminator within limit
    return false;
}

/**
 * Creates a new file descriptor entry for the given file in the current thread.
 * Returns pointer to the new file descriptor entry on success, NULL on failure.
 *
 * This implementation uses the per-thread fixed-size fd_table in struct thread,
 * finds the lowest available fd (reusing freed descriptors), and never assigns
 * an fd >= FD_MAX (127).
 */
static struct fd_entry *create_fd(struct file *file) {
    struct thread *t = thread_current();
    // check for null file
    if (file == NULL) {
        return NULL;
    }
    // find lowest available fd (start at 2 because you do not allocate 0/1 (stdin/stdout))
    for (int i = 2; i < FD_MAX; i++) {
        if (t->fd_table[i] == NULL) {
            struct fd_entry *fd_entry = palloc_get_page(0);
            if (fd_entry == NULL) {
                return NULL;
            }
            fd_entry->fd = i;
            fd_entry->f = file;
            t->fd_table[i] = fd_entry;
            return fd_entry;
        }
    }
    // no free descriptors available; thread's fd_table is full, so return NULL
    return NULL;
}

/**
 * Finds the file descriptor entry for the given fd in the current thread.
 * Returns pointer to the file descriptor entry on success, NULL if not found.
 */
static struct fd_entry *find_fd(int fd) {
    // check for valid file descriptor range
    if (fd < 0 || fd >= FD_MAX) {
        return NULL;
    }
    // get current thread and return the fd entry
    struct thread *t = thread_current();
    return t->fd_table[fd];
}

/**
 * Removes the file descriptor entry for the given fd in the current thread.
 * Does nothing if the fd is not found.
 */
void remove_fd(int fd) {
    // check for valid file descriptor range
    if (fd < 0 || fd >= FD_MAX) {
        return;
    }
    // get current thread and fd entry
    struct thread *t = thread_current();
    struct fd_entry *fd_entry = t->fd_table[fd];
    // if found, remove from table and free the entry
    if (fd_entry != NULL) {
        t->fd_table[fd] = NULL;
        palloc_free_page(fd_entry);
    }
}

/**
 * The main system call handler function.
 * Uses the appropriate system call based on the syscall number.
 */

static void syscall_handler (struct intr_frame *f UNUSED) {
    struct thread *cur = thread_current();
    // save the user stack pointer for stack growth checks
    cur->esp = f->esp;
    // get the syscall number from the stack
    uint8_t *sp = f->esp;
    // check for null and that the stack pointer is in user address range
    if (sp == NULL || !is_user_vaddr(sp)) {
        system_exit(-1);
    }
    // read the syscall number by copying from user space to kernel space
    int syscall_num;
    if (!copy_data(&syscall_num, sp, sizeof(int))) {
        system_exit(-1);
    }
    // ALL SYSTEM CALLS HANDLED HERE
    switch (syscall_num) {
        // CASE: SYS_HALT
        // shuts down the system
        case SYS_HALT: {
            shutdown_power_off();
            break;
        }
        // CASE: SYS_EXIT
        // exits the current process with the given status code
        case SYS_EXIT: {
            int status;
            if (!copy_data(&status, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            system_exit(status);
            break;
        }
        // CASE: SYS_EXEC
        // executes a new process
        case SYS_EXEC: {
            // get the command line pointer and command line string from user stack
            const char *cmd_linePtr;
            char cmd_line[128];
            if (!copy_data(&cmd_linePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (cmd_linePtr == NULL) {
                system_exit(-1);
            }
            if (!copy_string(cmd_line, cmd_linePtr)) {
                system_exit(-1);
            }
            if (cmd_line == NULL) {
                system_exit(-1);
            }
            f->eax = process_execute(cmd_line);
            break;
        }
        // CASE: SYS_WAIT
        // waits for a child process to terminate and retrieves its exit code
        case SYS_WAIT: {
            tid_t tid;
            if (!copy_data(&tid, sp + 4, sizeof(tid_t))) {
                f->eax = -1;
                break;
            }
            f->eax = process_wait(tid);
            break;
        }
        // CASE: SYS_CREATE
        // creates a new file with the given name and initial size
        case SYS_CREATE: {
            // get the file name pointer, initial size and file name string from user stack
            const char *filePtr;
            unsigned initial_size;
            char file[128];
            if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (filePtr == NULL) {
                system_exit(-1);
            }
            if (!copy_data(&initial_size, sp + 8, sizeof(unsigned))) {
                system_exit(-1);
            }
            if(!copy_string(file, filePtr)) {
                f->eax = false;
                break;
            }
            if (file == NULL) {
                system_exit(-1);
            }
            // check for empty file name
            if (file[0] == '\0') {
                f->eax = false;
                return;
            }
            // create the file
            lock_acquire(&file_lock);
            f->eax = filesys_create(file, initial_size);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_REMOVE
        // removes the file with the given name
        case SYS_REMOVE: {
            // get the file name pointer and file name string from user stack
            const char *filePtr;
            char file[128];
            if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (filePtr == NULL) {
                system_exit(-1);
            }
            if(!copy_string(file, filePtr)) {
                system_exit(-1);
            }
            if (file == NULL) {
                system_exit(-1);
            }
            // check for empty file name
            if (file[0] == '\0') {
                f->eax = false;
                return;
            }
            // remove the file
            lock_acquire(&file_lock);
            f->eax = filesys_remove(file);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_OPEN
        // opens the file with the given name and returns its file descriptor
        case SYS_OPEN: {
            // get the file name pointer and file name string from user stack
            const char *fileNamePtr;
            char fileName[128];
            if (!copy_data(&fileNamePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (fileNamePtr == NULL) {
                system_exit(-1);
            }
            if(!copy_string(fileName, fileNamePtr)) {
                system_exit(-1);
            }
            if (fileName == NULL) {
                system_exit(-1);
            }
            // check for empty file name
            if (fileName[0] == '\0') {
                f->eax = -1;
                return;
            }
            // open the file
            lock_acquire(&file_lock);
            struct file *file = filesys_open(fileName);
            lock_release(&file_lock);
            // check if file opened successfully
            if (file == NULL) {
                f->eax = -1;
                break;
            }
            // create a new file descriptor entry
            struct fd_entry *fd = create_fd(file);
            if (fd == NULL) {
                // could not create fd entry, close file and return -1
                f->eax = -1;
                lock_acquire(&file_lock);
                file_close(file);
                lock_release(&file_lock);
                break;
            }
            f->eax = fd->fd;
            break;
        }
        // CASE: SYS_FILESIZE
        // returns the size of the file with the given file descriptor
        case SYS_FILESIZE: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            // find the fd entry
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            // get the file size
            lock_acquire(&file_lock);
            f->eax = file_length(fd_entry->f);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_READ
        // reads from the file with the given file descriptor into the buffer
        case SYS_READ: {
            // get the file descriptor, buffer pointer, and size from user stack
            int fd;
            void *buffer;
            unsigned size;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }  
            if (!copy_data(&buffer, sp + 8, sizeof(void *))) {
                system_exit(-1);
            }
            if (buffer == NULL) {
                system_exit(-1);
            }
            if (!copy_data(&size, sp + 12, sizeof(unsigned))) {
                system_exit(-1);
            }
            // handle size 0 read
            if (size == 0) {
                f->eax = 0;
                break;
            }
            // copy data into kernel buffer to validate user buffer
            if (!copy_data(buffer, buffer, size)) {
                system_exit(-1);
            }
            // handle stdin read
            if (fd == 0) {
                for (unsigned i = 0; i < size; i++) {
                    ((char *)buffer)[i] = input_getc();
                }
                f->eax = size;
                break;
            }
            // find the fd entry
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            // read from the file into the buffer
            lock_acquire(&file_lock);
            f->eax = file_read(fd_entry->f, buffer, size);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_WRITE
        // writes to the file with the given file descriptor from the buffer
        case SYS_WRITE: {
            // get the file descriptor, buffer pointer, and size from user stack
            int fd;
            void *buffer;
            unsigned size;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }  
            if (!copy_data(&buffer, sp + 8, sizeof(void *))) {
                system_exit(-1);
            }
            if (buffer == NULL) {
                system_exit(-1);
            }
            if (!copy_data(&size, sp + 12, sizeof(unsigned))) {
                system_exit(-1);
            }
            // handle size 0 write
            if (size == 0) {
                f->eax = 0;
                break;
            }
            // copy data into kernel buffer to validate user buffer
            if (!copy_data(buffer, buffer, size)) {
                system_exit(-1);
            }
            if (fd == 1) {
                // handle stdout write
                putbuf(buffer, size);
                f->eax = size;
                break;
            } else if (fd == 0) {
                // cannot write to stdin
                f->eax = -1;
                break;
            } else {
                // find the fd entry
                struct fd_entry *fd_entry = find_fd(fd);
                if (fd_entry == NULL) {
                    f->eax = -1;
                    break;
                }
                // write to the file from the buffer
                lock_acquire(&file_lock);
                int written = 0;
                while (written < (int)size) {
                    int needWrite = size - written;
                    int wrote = file_write(fd_entry->f, (const uint8_t *)buffer + written, needWrite);
                    if (wrote <= 0) {
                        break;
                    }
                    written += wrote;
                }
                lock_release(&file_lock);
                f->eax = written;
                break;
            }
        }
        // CASE: SYS_SEEK
        // sets the file position of the file with the given file descriptor
        case SYS_SEEK: {
            int fd;
            unsigned position;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            if (!copy_data(&position, sp + 8, sizeof(unsigned))) {
                system_exit(-1);
            }
            // find the fd entry
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                system_exit(-1);
            }
            // set the file position
            lock_acquire(&file_lock);
            file_seek(fd_entry->f, position);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_TELL
        // gets the current file position of the file with the given file descriptor
        case SYS_TELL: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            // find the fd entry
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            // get the current file position
            lock_acquire(&file_lock);
            f->eax = file_tell(fd_entry->f);
            lock_release(&file_lock);
            break;
        }
        // CASE: SYS_CLOSE
        // closes the file with the given file descriptor
        case SYS_CLOSE: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            // find the fd entry
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            // close the file and remove the fd entry
            lock_acquire(&file_lock);
            file_close(fd_entry->f);
            lock_release(&file_lock);
            remove_fd(fd);
            break;
        }
        default:
            // unknown syscall number; terminate the process
            system_exit(-1);
    }
}
