#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

extern struct lock file_lock;

void syscall_init (void);
void remove_fd(int fd);
void system_exit (int status);

#endif /* userprog/syscall.h */
