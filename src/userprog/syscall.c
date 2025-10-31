#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include <string.h>

// the function that handles all system calls
static void syscall_handler (struct intr_frame *);
// lock for file system operations
struct lock file_lock;


/**
 * Initializes the system call system by setting the system call interrupt gate
 * The method be called exactly once during kernel startup, before any user process.
 */
void syscall_init (void)
{
    // initialize the syscall handler.
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    // initialize the file lock
    lock_init(&file_lock);
}

/**
 * Exits the current process with the given status code.
 */
void system_exit (int status){
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
static bool copy_data(void *kernel_dst, const void *user_src_, size_t size) {
    // create pointers for source and destination
    const uint8_t *user_src = user_src_;
    uint8_t *kernel_ptr = kernel_dst;
    uint8_t *end = user_src + size;
    // TODO no need to copy byte by byte or allocate kernel space. just get the variable already from the stack
    // TODO need to catch page faults in syscall handler instead of exception handler

    if (user_src == NULL || !is_user_vaddr(user_src) || !is_user_vaddr(end - 1))
        return false;

    // copy byte by byte, checking each address
    for (uint8_t *p = pg_round_down(user_src); p < end; p += PGSIZE) {
        if (addr_to_page(p) == NULL)
            return false;
    }
    memcpy(kernel_dst, user_src, size);
    // successfully copied all bytes
    return true;
}

/**
 * Copies a null-terminated string from user space to kernel space.
 * Returns pointer to kernel string on success, NULL on failure.
 */
// static char *copy_string(const char *user_str) {
//     // check for null and that the address is in user address range
//     if (user_str == NULL || !is_user_vaddr(user_str)) {
//         return NULL;
//     }
//     // allocate a page for the string buffer
//     char *buffer = palloc_get_page(0);
    
//     if (buffer == NULL) {
//         return NULL;
//     }
//     // copy byte by byte until null terminator or page size limit
//     for (size_t i = 0; i < PGSIZE; i++) {
//         uint8_t *page = addr_to_page(user_str + i);
//         if (page == NULL) {
//             palloc_free_page(buffer);
//             return NULL;
//         }
//         buffer[i] = *(user_str + i);
//         if (buffer[i] == '\0') {
//             return buffer;
//         }
//     }
//     // string too long (no null terminator within page)
//     palloc_free_page(buffer);
//     return NULL;
// }


static bool copy_string(char *dst, const char *usrc)
{
    if (usrc == NULL || !is_user_vaddr(usrc))
        return false;
    // 128 B limit for args
    for (size_t i = 0; i < 128; i++) {
        if (addr_to_page(usrc + i) == NULL)
            system_exit(-1);

        char c = usrc[i];
        dst[i] = c;
        if (c == '\0')
            return true;
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
    // get the syscall number from the stack
    uint8_t *sp = f->esp;
    // check for null and that the stack pointer is in user address range
    if (sp == NULL || !is_user_vaddr((const void *)sp)) {
        system_exit(-1);
    }
    // read the syscall number by copying from user space to kernel space
    int syscall_num;
    if (!copy_data(&syscall_num, sp, sizeof(int))) {
        system_exit(-1);
    }

    // ALL SYSTEM CALLS HANDLED HERE
    switch (syscall_num) {
        case SYS_HALT: {
            shutdown_power_off();
            break;
        }
        case SYS_EXIT: {
            int status;
            if (!copy_data(&status, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            system_exit(status);
            break;
        }
        case SYS_EXEC: {
            const char *cmd_linePtr;
            if (!copy_data(&cmd_linePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (cmd_linePtr == NULL) {
                system_exit(-1);
            }
            // char *cmd_line = copy_string((char *)cmd_linePtr);
            char cmd_line[128];
            if(!copy_string(cmd_line, cmd_linePtr)) {
                system_exit(-1);
            }
            if (cmd_line == NULL) {
                system_exit(-1);
            }
            f->eax = process_execute(cmd_line);
            // palloc_free_page(cmd_line);
            break;
        }
        case SYS_WAIT: {
            tid_t tid;
            if (!copy_data(&tid, sp + 4, sizeof(tid_t))) {
                f->eax = -1;
                break;
            }
            f->eax = process_wait(tid);
            break;
        }
        case SYS_CREATE: {
            const char *filePtr;
            unsigned initial_size;
            if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (filePtr == NULL) {
                system_exit(-1);
            }
            if (!copy_data(&initial_size, sp + 8, sizeof(unsigned))) {
                system_exit(-1);
            }
            // char *file = copy_string((char *)filePtr);
            char file[128];
            if(!copy_string(file, filePtr)) {
                f->eax = false;
                break;
            }
            if (file == NULL) {
                system_exit(-1);
            }
            if (file[0] == '\0') {
                // palloc_free_page(file);
                f->eax = false;
                return;
            }
            lock_acquire(&file_lock);
            f->eax = filesys_create(file, initial_size);
            lock_release(&file_lock);
            // palloc_free_page(file);
            break;
        }
        case SYS_REMOVE: {
            const char *filePtr;
            if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (filePtr == NULL) {
                system_exit(-1);
            }
            // char *file = copy_string((char *)filePtr);
            char file[128];
            if(!copy_string(file, filePtr)) {
                system_exit(-1);
            }
            if (file == NULL) {
                system_exit(-1);
            }
            if (file[0] == '\0') {
                // palloc_free_page(file);
                f->eax = false;
                return;
            }
            lock_acquire(&file_lock);
            f->eax = filesys_remove(file);
            lock_release(&file_lock);
            // palloc_free_page(file);
            break;
        }
        case SYS_OPEN: {
            const char *fileNamePtr;
            if (!copy_data(&fileNamePtr, sp + 4, sizeof(const char *))) {
                system_exit(-1);
            }
            if (fileNamePtr == NULL) {
                system_exit(-1);
            }
            // char *fileName = copy_string((char *)fileNamePtr);
            char fileName[128];
            if(!copy_string(fileName, fileNamePtr)) {
                system_exit(-1);
            }
            if (fileName == NULL) {
                system_exit(-1);
            }
            if (fileName[0] == '\0') {
                // palloc_free_page(fileName);
                f->eax = -1;
                return;
            }
            lock_acquire(&file_lock);
            struct file *file = filesys_open(fileName);
            lock_release(&file_lock);
            if (file == NULL) {
                // palloc_free_page(fileName);
                f->eax = -1;
                break;
            }
            struct fd_entry *fd = create_fd(file);
            if (fd == NULL) {
                // could not create fd entry, close file and return -1
                f->eax = -1;
                file_close(file);
                // palloc_free_page(fileName);
                break;
            }
            f->eax = fd->fd;
            // palloc_free_page(fileName);
            break;
        }
        case SYS_FILESIZE: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            lock_acquire(&file_lock);
            f->eax = file_length(fd_entry->f);
            lock_release(&file_lock);
            break;
        }
        case SYS_READ: {
            int fd;
            void *buffer;
            unsigned size;
            if (!copy_data(&fd, sp + 4, sizeof(int)) ||
                !copy_data(&buffer, sp + 8, sizeof(void *)) ||
                !copy_data(&size, sp + 12, sizeof(unsigned))) {
                system_exit(-1);
            }
            if (size == 0) {
                f->eax = 0;
                break;
            }
            if (buffer == NULL) {
                system_exit(-1);
            }
            char *buf = (char *)buffer;
            unsigned remaining = size;
            while (remaining > 0) {
                if (addr_to_page(buf) == NULL) {
                    system_exit(-1);
                }
                size_t offset = (uintptr_t)buf & (PGSIZE - 1);
                size_t chunk = PGSIZE - offset;
                if (chunk > remaining) {
                    chunk = remaining;
                }
                buf += chunk;
                remaining -= chunk;
            }
            if (fd == 0) {
                for (unsigned i = 0; i < size; i++) {
                    ((char *)buffer)[i] = input_getc();
                }
                f->eax = size;
                break;
            }
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            lock_acquire(&file_lock);
            f->eax = file_read(fd_entry->f, buffer, size);
            lock_release(&file_lock);
            break;
        }
        case SYS_WRITE: {
            int fd;
            const void *buffer;
            unsigned size;
            if (!copy_data(&fd, sp + 4, sizeof(int)) ||
                !copy_data(&buffer, sp + 8, sizeof(const void *)) ||
                !copy_data(&size, sp + 12, sizeof(unsigned))) {
                system_exit(-1);
            }
            if (size == 0) {
                f->eax = 0;
                break;
            }
            if (buffer == NULL) {
                system_exit(-1);
            }
            const char *bufw = (const char *)buffer;
            unsigned remainingw = size;
            while (remainingw > 0) {
                if (addr_to_page(bufw) == NULL) {
                    system_exit(-1);
                }
                size_t offset = (uintptr_t)bufw & (PGSIZE - 1);
                size_t chunk = PGSIZE - offset;
                if (chunk > remainingw) {
                    chunk = remainingw;
                }
                bufw += chunk;
                remainingw -= chunk;
            }
            if (fd == 1) {
                putbuf(buffer, size);
                f->eax = size;
                break;
            } else if (fd == 0) {
                f->eax = -1;
                break;
            } else {
                struct fd_entry *fd_entry = find_fd(fd);
                if (fd_entry == NULL) {
                    f->eax = -1;
                    break;
                }
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
        case SYS_SEEK: {
            int fd;
            unsigned position;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            if (!copy_data(&position, sp + 8, sizeof(unsigned))) {
                system_exit(-1);
            }
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                system_exit(-1);
            }
            lock_acquire(&file_lock);
            file_seek(fd_entry->f, position);
            lock_release(&file_lock);
            break;
        }
        case SYS_TELL: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            lock_acquire(&file_lock);
            f->eax = file_tell(fd_entry->f);
            lock_release(&file_lock);
            break;
        }
        case SYS_CLOSE: {
            int fd;
            if (!copy_data(&fd, sp + 4, sizeof(int))) {
                system_exit(-1);
            }
            struct fd_entry *fd_entry = find_fd(fd);
            if (fd_entry == NULL) {
                f->eax = -1;
                break;
            }
            lock_acquire(&file_lock);
            file_close(fd_entry->f);
            lock_release(&file_lock);
            remove_fd(fd);
            break;
        }
        default:
            system_exit(-1);
    }
}
