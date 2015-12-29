// Copyright 2015 Sandstorm Development Group, Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

static int my_errno;
#define SYS_ERRNO my_errno
#include "linux_syscall_support.h"

// Includes for type definitions only.
#include <sys/user.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <sys/socket.h>

/*
 * Some GCC versions are so clever that they recognize these simple loops
 * as having the semantics of standard library functions and replace them
 * with calls.  That defeats the whole purpose, which is to avoid requiring
 * any C library at all.  Fortunately, this optimization can be disabled
 * for all (following) functions in the file via #pragma.
 */
#if (defined(__GNUC__) && !defined(__clang__) && \
     (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)))
# pragma GCC optimize("-fno-tree-loop-distribute-patterns")
#endif

static void my_memcpy(void *dest, const void *src, size_t size) {
  char *d = dest;
  const char *s = src;
  while (size > 0) {
    *d++ = *s++;
    size--;
  }
}

static void my_bzero(void *buf, size_t n) {
  char *p = buf;
  while (n-- > 0)
    *p++ = 0;
}

static size_t my_strlen(const char *s) {
  size_t n = 0;
  while (*s++ != '\0')
    ++n;
  return n;
}

static int my_strcmp(const char *a, const char *b) {
  while (*a == *b) {
    if (*a == '\0')
      return 0;
    ++a;
    ++b;
  }
  return (int) (unsigned char) *a - (int) (unsigned char) *b;
}






struct replay_thread_state {
  // Required thread ID (process ID for main thread). We'll abort if we don't
  // get this ID. This implies that replays must run in a PID namespace where
  // PID assignment is reproducible.
  pid_t tid;

  // CPU state.
  struct user_regs_struct regs;
  struct user_fpregs_struct fpregs;

  // Thread state.
  uint64_t tid_address;
  sigset_t sigmask;
};

// This function is defined in the generated code and calls the other functions below.
static void replay();

// Called first. Abort if our PID is not the given PID.
static void replay_init(pid_t pid, int maxfd, size_t memsize);

// Map memory from snapshot.
static void replay_memory(uint64_t address, size_t length, int prot, off_t offset);

// Map memory from file on disk.
static void replay_mmap(uint64_t address, size_t length, int prot, int flags,
                        const char* path, off_t offset);

// Create various types of file descriptors. In all cases, the first parameter
// specifies the descriptor number to use.
static void replay_open(int fd, const char* path, int flags, off_t seek);
static void replay_epoll_create(int fd, int flags);
static void replay_eventfd(int fd, unsigned int initval, int flags);
static void replay_signalfd(int fd, const sigset_t* mask, int flags);
static void replay_socket(int fd, int domain, int type, int protocol);
static void replay_accept(int fd, int listener_socket, int flags, int barrier);

// These two each create two file descriptors (the first two args).
static void replay_pipe(int read_fd, int write_fd, int flags);
static void replay_socketpair(int fd1, int fd2, int domain, int type, int protocol);

// Manipulate existing descirptors.
static void replay_write(int fd, const void* data, size_t size);
static void replay_epoll_add(int epoll_fd, int watch_fd, uint32_t events, uint64_t data);
static void replay_bind(int socket_fd, struct sockaddr* bind_addr, socklen_t addrlen);
static void replay_listen(int socket_fd, int backlog, int barrier);
static void replay_connect(int socket_fd, struct sockaddr* addr, socklen_t addrlen);
static void replay_setsockopt(int socket_fd, int level, int optname,
                              const void* optval, socklen_t optlen);

// Manipulate signal handlers.
static void replay_sigaction(int signum, __sighandler_t handler, const sigset_t* mask, int flags);

// Start a child thread.
static void replay_thread(struct replay_thread_state* state);

// Start the main thread. Does not return.
static void replay_finish(struct replay_thread_state* state);

typedef uintptr_t __attribute__((may_alias)) stack_val_t;

static int progfd;
static uintptr_t progmem;

void replay_main(stack_val_t* argp) {
  ++argp;                // skip argc
  while (*argp++ != 0);  // skip argv
  while (*argp++ != 0);  // skip envp

  const char* prog = NULL;
  for (; *argp != AT_NULL; argp += 2) {
    if (*argp == AT_EXECFN) {
      prog = (const char*)argp[1];
      break;
    }
  }

  if (prog == NULL) {
    sys_write(2, "no AT_EXECFN\n", 13);
    sys_exit_group(1);
  }

  progfd = sys_open(prog, O_RDONLY, 0);
  if (progfd < 0) {
    sys_write(2, "couldn't open: ", 15);
    sys_write(2, prog, my_strlen(prog));
    sys_write(2, "\n", 1);
    sys_exit_group(1);
  }

  replay();

  // Won't get here.
  sys_exit_group(1);
}

static void replay_init(pid_t pid, int maxfd, size_t memsize) {
  if (progfd <= maxfd) {
    sys_dup2(progfd, maxfd + 1);
    sys_close(progfd);
    progfd = maxfd + 1;
  }

  struct kernel_stat stats;
  sys_fstat(progfd, &stats);
  if (stats.st_size < memsize) sys_exit_group(1);
  progmem = stats.st_size - memsize;
}

static void replay_memory(uint64_t address, size_t length, int prot, off_t offset) {
  if (sys_mmap((void*)address, length, prot, MAP_PRIVATE,
               progfd, progmem + offset) != (void*)address) {
    sys_exit_group(1);
  }
}

static void replay_mmap(uint64_t address, size_t length, int prot, int flags,
                        const char* path, off_t offset) {
  int fd = sys_open(path, O_RDONLY, 0);
  if (fd < 0 || sys_mmap((void*)address, length, prot, flags, fd, offset) != (void*)address) {
    sys_exit_group(1);
  }
  sys_close(fd);
}

static void replay_write(int fd, const void *data, size_t size) {
  while (size > 0) {
    ssize_t n = sys_write(fd, data, size);
    if (n < 0) sys_exit_group(1);
    size -= n;
    data = (const char*)data + n;
  }
}

static void replay_close(int fd) {
  if (sys_close(fd) < 0) {
    sys_exit_group(1);
  }
}

static void replay_finish(struct replay_thread_state* state) {
  sys_close(progfd);

  if (sys_arch_prctl(ARCH_SET_FS, (void*)state->regs.fs_base) < 0 ||
      sys_set_tid_address((int*)state->tid_address) < 0) {
    sys_exit_group(1);
  }

  asm("mov %%cs, %0" : "=r"(state->regs.cs));
  asm("mov %%ss, %0" : "=r"(state->regs.ss));

  asm("movq %0, %%rsp\n"
      "popq %%r15\n"
      "popq %%r14\n"
      "popq %%r13\n"
      "popq %%r12\n"
      "popq %%rbp\n"
      "popq %%rbx\n"
      "popq %%r11\n"
      "popq %%r10\n"
      "popq %%r9\n"
      "popq %%r8\n"
      "popq %%rax\n"
      "popq %%rcx\n"
      "popq %%rdx\n"
      "popq %%rsi\n"
      "popq %%rdi\n"
      "addq $8, %%rsp\n"
      "iretq\n"
      : : "r"(&state->regs) : "memory");
}

/*
 * We have to define the actual entry point code (_start) in assembly for
 * each machine.  The kernel startup protocol is not compatible with the
 * normal C function calling convention.  Here, we call do_load (above)
 * using the normal C convention as per the ABI, with the starting stack
 * pointer as its argument; switch to the new stack; and finally, jump to
 * the dynamic linker's entry point address.
 */
#if defined(__x86_64__)
asm(".pushsection \".text\",\"ax\",@progbits\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "xorq %rbp, %rbp\n"
    "movq %rsp, %rdi\n"         /* Argument: stack block.  */
    "andq $-16, %rsp\n"         /* Align the stack as per ABI.  */
    "call replay_main\n"
    ".popsection"
    );
#else
# error "Need _start code for this architecture!"
#endif
