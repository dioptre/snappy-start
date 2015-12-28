// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <asm/prctl.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <vector>

// This is an example of using ptrace() to log syscalls called by a
// child process.

namespace {

class EpollInfo;

// State of an open file description.
class FileInfo {
 public:
  inline explicit FileInfo(bool nonblock): nonblock(nonblock) {}
  virtual ~FileInfo();

  // Whether the file is in non-blocking mode.
  bool nonblock;

  // Epoll FD which is reporting events for this file.
  EpollInfo* epoll_watcher = nullptr;
  int epoll_watch_fd;  // FD number under which this file was watched.

  // Write code that replays creation of this FD.
  virtual void WriteReplay(int fd, std::ostream& out) = 0;

  // Write code that replays the side effects of the operations performed
  // on this FD, but does not create the FD. Used when the FD was closed
  // before the end of recording. Default implementation writes nothing on
  // the assumption that there are no side-effects if the FD has gone away.
  //
  // Replays of closed files will take place before replays of open files.
  virtual void WriteReplayClosed(std::ostream& out) {}

  // TODO: Closed files may still require replay!

  // For each system call `foo` targeting a file descriptor, the method
  // `CanFoo()` is called on entry. If it returns false, then the recording
  // ends and the snapshot is dumped here. If `CanFoo()` returns true, then
  // we proceed with the syscall. When it completes, if it completed
  // successfully, we call `DidFoo()` to report the results. If the syscall
  // returned an error, no method is called, since an error generally means
  // that nothing happened.
  //
  // All methods have default implementations that indicate the syscall cannot
  // be recorded.

  // Handle mmap(). DidMmap() returns the path of the mapped file.
  virtual bool CanMmap() {return false;}
  virtual std::string DidMmap(off_t offset, size_t size) {abort();}

  // Handle write(). Only the data actually written (as indicated by write()'s
  // return value) is reported.
  virtual bool CanWrite() {return false;}
  virtual void DidWrite(const std::string& data) {abort();}

  // Handle read(). The data produced is not reported here; it has already been
  // consumed into the process's memory state.
  virtual bool CanRead() {return false;}
  virtual void DidRead(size_t amount) {abort();}

  // Handle bind().
  virtual bool CanBind() {return false;}
  virtual void DidBind(struct sockaddr* addr, socklen_t attrlen) {abort();}

  // Handle listen().
  virtual bool CanListen() {return false;}
  virtual void DidListen(int backlog) {abort();}

  // Handle epoll_ctl().
  virtual bool CanEpollCtl(FileInfo* target) {return false;}
  virtual void DidEpollCtl(int op, int fd, FileInfo* target,
                           struct epoll_event event) {abort();}

  // Handle epoll_wait().
  virtual bool CanEpollWait(int timeout) {return false;}
  virtual void DidEpollWait(struct epoll_event events[], int count) {abort();}

  // Handle signalfd() on existing file.
  virtual bool CanSignalfd() {return false;}
  virtual void DidSignalfd(const sigset_t* mask, int flags) {abort();}
};

void WriteEscaped(std::ostream& out, const std::string& data) {
  for (char c: data) {
    switch (c) {
      case '\a': out << "\\a"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      case '\v': out << "\\v"; break;
      case '\'': out << "\\\'"; break;
      case '\"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          out << "\\x";
          char old_fill = out.fill('0');
          out.width(2);
          out << static_cast<unsigned int>(static_cast<uint8_t>(c));
          out.fill(old_fill);
        } else {
          out.put(c);
        }
        break;
    }
  }
}

// Standard input. Assumed to be empty.
class StdinInfo final : public FileInfo {
public:
  StdinInfo(): FileInfo(false) {}

  void WriteReplay(int fd, std::ostream& out) override {}
  void WriteReplayClosed(std::ostream& out) override {
    out << "  replay_close(0);\n";
  }

  bool CanRead() override {return true;}
  void DidRead(size_t amount) override { assert(amount = 0); }

private:
  std::string written;  // concatenation of all write()s
};

// Standard output and error (assumed to be the same pipe). We record the raw
// writes to replay later.
class StdoutInfo final : public FileInfo {
public:
  StdoutInfo(): FileInfo(false) {}

  void WriteReplay(int fd, std::ostream& out) override {
    out << "  replay_write(1, \"";
    WriteEscaped(out, written);
    out << "\", " << written.size() << ");\n";

    // TODO: Deal with stdout being dup()ed and the original closed.
    assert(fd == 1);
  }

  void WriteReplayClosed(std::ostream& out) override {
    WriteReplay(1, out);
    out << "  replay_close(1);\n"
           "  replay_close(2);\n";
  }

  bool CanWrite() override {
    return true;
  }

  void DidWrite(const std::string& data) override {
    written.append(data);
  }

private:
  std::string written;  // concatenation of all write()s
};

// A "static file" is a file on disk which is expected to have exactly the
// same content at record and replay times, e.g. libraries.
class StaticFileInfo final : public FileInfo {
public:
  StaticFileInfo(std::string path, int open_flags)
      : FileInfo(open_flags & O_NONBLOCK),
        path(std::move(path)), open_flags(open_flags) {}

  void WriteReplay(int fd, std::ostream& out) override {
    out << "  replay_open(" << fd << ", \"";
    WriteEscaped(out, path);
    out << "\", " << open_flags << ", 0, " << offset << ");\n";
  }

  bool CanMmap() override {return true;}
  std::string DidMmap(off_t offset, size_t size) override {
    return path;
  }

  bool CanRead() override { return true; }
  void DidRead(size_t amount) override { offset += amount; }

private:
  std::string path;
  int open_flags;
  off_t offset = 0;
};

// A "dynamic file" is a file on disk created by the recorded process. The
// creation will be replayed later.
class DynamicFileInfo final : public FileInfo {
public:

private:
  int open_flags;
  std::string path;
  // TODO: Track file writes.
};

// A network socket. Mainly we support setting up listen sockets.
class SocketInfo final : public FileInfo {
public:

private:
  int socket_domain;
  int socket_type;
  int socket_protocol;
  std::string bind_addr;
  std::string connect_addr;
  int listen_backlog;
};

// An epoll FD.
class EpollInfo final : public FileInfo {
public:
  ~EpollInfo() {
    for (auto& entry: watching) {
      assert(entry.second->epoll_watcher == this);
      entry.second->epoll_watcher = nullptr;
    }
  }

  void Unwatch(int fd, FileInfo* file) {
    auto iter = watching.find(fd);
    assert(iter != watching.end() && iter->second == file);
    watching.erase(iter);
  }

private:
  std::map<int, FileInfo*> watching;
};

// An eventfd.
class EventfdInfo final : public FileInfo {
public:

private:
  int event_flags;  // only for EFD_SEMAPHORE
  unsigned int event_value;
};

// A signalfd.
class SignalfdInfo final : public FileInfo {
public:

private:
  sigset_t siganl_mask;
};

FileInfo::~FileInfo() {
  if (epoll_watcher != nullptr) {
    epoll_watcher->Unwatch(epoll_watch_fd, this);
  }
}

// ===================================================================

// Flag which is set in the signal number for syscall entry/exit when
// the option PTRACE_O_TRACESYSGOOD is enabled.
const int kSysFlag = 0x80;

uintptr_t RoundUpPageSize(uintptr_t val) {
  uintptr_t page_size = getpagesize();
  return (val + page_size - 1) & ~(page_size - 1);
}

class SyscallParams {
 public:
  SyscallParams(const struct user_regs_struct *regs) {
    sysnum = regs->orig_rax;
    result = regs->rax;
    args[0] = regs->rdi;
    args[1] = regs->rsi;
    args[2] = regs->rdx;
    args[3] = regs->r10;
    args[4] = regs->r8;
    args[5] = regs->r9;
  }

  uintptr_t sysnum;
  uintptr_t args[6];
  uintptr_t result;
};

// State of a memory mapping.
class MmapInfo {
 public:
  uintptr_t addr;
  size_t size;
  // Current access permissions.
  int prot;
  int flags;
  // Maximum access permissions that this mapping has ever been
  // mmap()'d or mprotect()'d with.  This is used to determine whether
  // mapping could have been written to.
  int max_prot;
  std::string filename;
  uint64_t file_offset;
};

// State of an open file descriptor.
//
// (In Unix terminology, a file descriptor number is a reference to a file
// description object in kernel space. Multiple file descriptors can reference
// the same file description, especially as a result of calling dup(). The
// close-on-exec flag is a property of the descriptor itself, not the
// description. All other state is generally on the description.)
struct FdInfo {
  std::shared_ptr<FileInfo> file;
  bool cloexec;
};

class Ptracer {
  int pid_;
  std::list<MmapInfo> mappings_;
  std::map<int, FdInfo> fds_;
  std::vector<std::shared_ptr<FileInfo>> files_;
  uint64_t fs_segment_base_;
  uintptr_t tid_address_;

  uintptr_t ReadWord(uintptr_t addr) {
    errno = 0;
    uintptr_t value = ptrace(PTRACE_PEEKDATA, pid_, addr, 0);
    assert(errno == 0);
    return value;
  }

  char ReadByte(uintptr_t addr) {
    uintptr_t mask = sizeof(uintptr_t) - 1;
    uintptr_t word = ReadWord(addr & ~mask);
    return word >> ((addr & mask) * 8);
  }

  std::string ReadString(uintptr_t addr) {
    // TODO: Reading one byte at a time is inefficient (though reading
    // one word at a time is not great either).
    std::string buf;
    for (;;) {
      char ch = ReadByte(addr++);
      if (!ch)
        break;
      buf.push_back(ch);
    }
    return buf;
  }

  std::string ReadBytes(uintptr_t addr, size_t size) {
    // TODO: Reading one byte at a time is inefficient (though reading
    // one word at a time is not great either).
    std::string buf;
    for (size_t i = 0; i < size; i++) {
      char ch = ReadByte(addr + i);
      buf.push_back(ch);
    }
    return buf;
  }

  void ChangeMapping(uintptr_t change_start, size_t change_size,
                     bool do_unmap, int new_prot) {
    change_size = RoundUpPageSize(change_size);
    uintptr_t change_end = change_start + change_size;
    assert(change_end >= change_start);
    for (std::list<MmapInfo>::iterator iter = mappings_.begin();
         iter != mappings_.end(); ) {
      std::list<MmapInfo>::iterator mapping = iter++;
      uintptr_t mapping_end = mapping->addr + mapping->size;
      // Does this existing mapping overlap with the range we are
      // unmapping?
      if (mapping_end <= change_start ||
          change_end <= mapping->addr) {
        // No overlap.
        continue;
      }
      // Do we need to keep the start and/or end of the existing
      // mapping?
      if (change_start > mapping->addr) {
        // Keep the start of the mapping.
        MmapInfo new_part(*mapping);
        new_part.size = change_start - mapping->addr;
        mappings_.insert(mapping, new_part);
      }
      if (change_end < mapping_end) {
        // Keep the end of the mapping.
        MmapInfo new_part(*mapping);
        size_t diff = change_end - mapping->addr;
        new_part.addr += diff;
        new_part.size -= diff;
        new_part.file_offset += diff;
        mappings_.insert(mapping, new_part);
      }
      if (do_unmap) {
        // munmap() case.
        mappings_.erase(mapping);
      } else {
        // mprotect() case.
        uintptr_t new_start = std::max(change_start, mapping->addr);
        uintptr_t new_end = std::min(change_end, mapping_end);
        mapping->file_offset += new_start - mapping->addr;
        mapping->addr = new_start;
        mapping->size = new_end - new_start;
        mapping->prot = new_prot;
        mapping->max_prot |= new_prot;
      }
    }
  }

  void HandleMunmap(uintptr_t addr, size_t size) {
    ChangeMapping(addr, size, true, 0);
  }

  void HandleMprotect(uintptr_t addr, size_t size, int prot) {
    ChangeMapping(addr, size, false, prot);
  }

 public:
  Ptracer(int pid): pid_(pid), fs_segment_base_(0), tid_address_(0) {}

  void SetFd(int fd, FdInfo info) {
    fds_[fd] = info;
    files_.push_back(info.file);
  }

  // Returns whether we should allow the syscall to proceed.
  // Returning false indicates that we should snapshot the process.
  bool CanHandleSyscall(struct user_regs_struct *regs) {
    SyscallParams params(regs);

    switch (params.sysnum) {
      case __NR_arch_prctl:
        return params.args[0] == ARCH_SET_FS;

      case __NR_mmap: {
        // TODO: Be stricter about which flags we allow.
        uintptr_t flags = params.args[3];
        if ((flags & MAP_SHARED) != 0) return false;

        int fd_arg = params.args[4];
        if (fd_arg == -1) {
          return true;
        } else {
          auto iter = fds_.find(fd_arg);
          return iter != fds_.end() && iter->second.file->CanMmap();
        }
      }

      case __NR_open: {
        uintptr_t flags = params.args[1];
        uintptr_t allowed_flags = O_ACCMODE | O_CLOEXEC;
        return (flags & O_ACCMODE) == O_RDONLY &&
               (flags & ~allowed_flags) == 0;
      }

      case __NR_write: {
        int fd_arg = params.args[0];
        auto iter = fds_.find(fd_arg);
        return iter != fds_.end() && iter->second.file->CanWrite();
      }

      // These are handled below.
      case __NR_close:
      case __NR_mprotect:
      case __NR_munmap:
      case __NR_set_tid_address:
        return true;

      // These are safe to ignore.
      case __NR_access:     // TODO: Only allow on static file paths.
      case __NR_fadvise64:
      case __NR_fstat:
      case __NR_futex:      // TODO: Don't allow blocking.
      case __NR_getcwd:
      case __NR_getdents:   // TODO: Treat like read().
      case __NR_getegid:
      case __NR_geteuid:
      case __NR_getgid:
      case __NR_getrlimit:
      case __NR_getuid:
      case __NR_ioctl:      // TODO: Filter on specific ioctls.
      case __NR_lseek:      // TODO: Must handle.
      case __NR_lstat:      // TODO: Only allow on static file paths.
      case __NR_pread64:    // Only valid on disk files and doesn't
                            // affect seek pos, so we can ignore!
      case __NR_read:       // TODO: Must handle.
      case __NR_readlink:   // TODO: Only allow on static file paths.
      case __NR_stat:       // TODO: Only allow on static file paths.
      case __NR_uname:
        return true;

      // TODO: The following will require further handling.
      case __NR_openat:
      case __NR_rt_sigaction:
      case __NR_rt_sigprocmask:
      case __NR_set_robust_list:
        return true;
    }
    return false;
  }

  // Handle a syscall after it has executed.
  void HandleSyscall(struct user_regs_struct *regs) {
    SyscallParams params(regs);

    if (params.result > -(uintptr_t) 0x1000 &&
        params.sysnum != __NR_close) {
      // Syscall returned an error so should have had no effect.
      // (Except for close() which does in fact close the FD even on error.)
      return;
    }

    switch (params.sysnum) {
      case __NR_open: {
        std::string filename(ReadString(params.args[0]));
        int fd_result = params.result;
        // TODO: inspect flags
        int flags = params.args[1];
        if (fd_result >= 0) {
          fds_[fd_result] = FdInfo {
            std::make_shared<StaticFileInfo>(std::move(filename), flags),
            static_cast<bool>(flags & O_CLOEXEC)
          };
        }
        break;
      }
      case __NR_close: {
        fds_.erase(params.args[0]);
        break;
      }
      case __NR_mmap: {
        uintptr_t addr = params.result;
        size_t size = RoundUpPageSize(params.args[1]);
        assert(addr + size >= addr);
        // Record overwriting of any existing mappings in this range
        // in case this mmap() call uses MAP_FIXED.
        HandleMunmap(addr, size);

        MmapInfo map;
        map.addr = addr;
        map.size = size;
        map.prot = params.args[2];
        map.flags = params.args[3];
        map.max_prot = map.prot;
        map.file_offset = params.args[5];
        int fd_arg = params.args[4];
        if (fd_arg != -1) {
          auto iter = fds_.find(fd_arg);
          assert(iter != fds_.end());
          map.filename = iter->second.file->DidMmap(
              map.file_offset, map.size);
        }
        mappings_.push_back(map);
        break;
      }
      case __NR_munmap: {
        HandleMunmap(params.args[0], params.args[1]);
        break;
      }
      case __NR_mprotect: {
        HandleMprotect(params.args[0], params.args[1], params.args[2]);
        break;
      }
      case __NR_arch_prctl: {
        if (params.args[0] == ARCH_SET_FS) {
          fs_segment_base_ = params.args[1];
        }
        break;
      }
      case __NR_set_tid_address: {
        tid_address_ = params.args[0];
        break;
      }
      case __NR_write: {
        auto iter = fds_.find(params.args[0]);
        assert(iter != fds_.end());
        iter->second.file->DidWrite(ReadBytes(params.args[1], params.result));
        break;
      }
    }
  }

  void Dump(std::ostream& out, const struct user_regs_struct *regs,
                               const struct user_fpregs_struct *fpregs) {
    // Determine the final FD numbers mapping to each file.
    std::map<FileInfo*, int> final_fds;
    for (auto& fd: fds_) {
      // This will only insert the first fd we see mapping to this file.
      final_fds.insert(std::make_pair(fd.second.file.get(), fd.first));
    }

    // Replay all closed files.
    for (auto& file: files_) {
      if (final_fds.count(file.get()) == 0) {
        file->WriteReplayClosed(out);
        final_fds.insert(std::make_pair(file.get(), -1));
      }
    }

    // Replay open files.
    for (auto& fd: fds_) {
      int final_fd = final_fds[fd.second.file.get()];
      if (fd.first == final_fd) {
        fd.second.file->WriteReplay(fd.first, out);
      } else {
        // This is a duplicate.
        out << "  replay_dup(" << fd.first << ", " << final_fd << ");\n";
      }
    }

    FILE *mapfile = fopen("out_pages", "w");
    assert(mapfile);
    uintptr_t mapfile_offset = 0;

    for (auto &map : mappings_) {
      if (map.filename.empty() || (map.max_prot & PROT_WRITE)) {
        // Data in memory does not necessarily match anything on disk.
        // Must copy into mapfile.
        out << "  replay_memory(" << map.addr << ", " << map.size << ", "
            << map.prot << ", " << map.file_offset << ");\n";

        for (uintptr_t offset = 0; offset < map.size;
             offset += sizeof(uintptr_t)) {
          uintptr_t word = ReadWord(map.addr + offset);
          fwrite(&word, sizeof(word), 1, mapfile);
        }
        mapfile_offset += map.size;
      } else {
        // Map directly from original file.
        out << "  replay_mmap(" << map.addr << ", " << map.size << ", "
            << map.prot << ", " << map.flags << ", \"";
        WriteEscaped(out, map.filename);
        out << "\", " << map.file_offset << ");\n";
      }
    }

    assert(regs->fs_base == fs_segment_base_);

    out << "  struct replay_thread_state state;\n"
           "  state.tid = " << pid_ << ";\n"
           "  memcpy(&state.regs, \"";
    WriteEscaped(out, std::string(reinterpret_cast<const char*>(regs), sizeof(*regs)));
    out <<                           "\";\n"
           "  memcpy(&state.fpregs, \"";
    WriteEscaped(out, std::string(reinterpret_cast<const char*>(fpregs), sizeof(*fpregs)));
    out <<                             "\";\n"
           "  state.tid_address = " << reinterpret_cast<uintptr_t>(tid_address_) << ";\n"
           // TODO: stack_start
           // TODO: sigmask
           "  replay_finish(&state);\n";

    fclose(mapfile);
  }

  void TerminateSubprocess() {
    int rc = kill(pid_, SIGKILL);
    assert(rc == 0);

    // Wait for the SIGKILL signal to take effect.
    int status;
    int pid2 = waitpid(pid_, &status, 0);
    assert(pid2 == pid_);
    assert(WIFSIGNALED(status));
    assert(WTERMSIG(status) == SIGKILL);
  }
};

}

int main(int argc, char **argv) {
  assert(argc >= 2);

  int pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    // Start tracing of the current process by the parent process.
    int rc = ptrace(PTRACE_TRACEME);
    assert(rc == 0);

    // This will trigger a SIGTRAP signal, which the parent will catch.
    execv(argv[1], argv + 1);
    perror("exec");

    _exit(1);
  }

  // Wait for the initial SIGTRAP signal generated by the child's
  // execve() call.  Since we haven't done PTRACE_SETOPTIONS yet,
  // kSysFlag isn't set in the signal number yet.
  int status;
  int pid2 = waitpid(pid, &status, 0);
  assert(pid2 == pid);
  assert(WIFSTOPPED(status));
  assert(WSTOPSIG(status) == SIGTRAP);

  // Enable kSysFlag.
  int rc = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  assert(rc == 0);

  // Allow the process to continue until the next syscall entry/exit.
  rc = ptrace(PTRACE_SYSCALL, pid, 0, 0);
  assert(rc == 0);

  // Whether the next signal will indicate a syscall entry.  If false,
  // the next signal will indicate a syscall exit.
  bool syscall_entry = true;

  Ptracer ptracer(pid);

  // Initialize inherited FDs.
  //
  // TODO: The right thing to do here depends on the context. Provide an API!

  ptracer.SetFd(STDIN_FILENO, {std::make_shared<StdinInfo>(), false});

  // For now we're assuming stdout and stderr are merged.
  auto stdout = std::make_shared<StdoutInfo>();
  ptracer.SetFd(STDOUT_FILENO, {stdout, false});
  ptracer.SetFd(STDERR_FILENO, {std::move(stdout), false});

  for (;;) {
    int status;
    int rc = waitpid(pid, &status, 0);
    assert(rc == pid);

    assert(WIFSTOPPED(status));

    if (WSTOPSIG(status) == (SIGTRAP | kSysFlag)) {
      struct user_regs_struct regs;
      rc = ptrace(PTRACE_GETREGS, pid, 0, &regs);
      assert(rc == 0);
      if (syscall_entry) {
        // Disable use of the brk() heap so that we don't have to save
        // and restore the brk() heap pointer and heap contents.
        if (regs.orig_rax == __NR_brk) {
          regs.orig_rax = -1;
          rc = ptrace(PTRACE_SETREGS, pid, 0, &regs);
          assert(rc == 0);
        } else if (!ptracer.CanHandleSyscall(&regs)) {
          // Unrecognised syscall: trigger snapshotting.

          std::cerr << "ending record due to syscall: " << regs.orig_rax << std::endl;

          // Rewind instruction pointer to before the syscall instruction.
          regs.rip -= 2;
          regs.rax = regs.orig_rax;

          struct user_fpregs_struct fpregs;
          rc = ptrace(PTRACE_GETFPREGS, pid, 0, &fpregs);
          assert(rc == 0);

          ptracer.Dump(std::cout, &regs, &fpregs);
          ptracer.TerminateSubprocess();
          break;
        }
      } else {
        ptracer.HandleSyscall(&regs);
      }
      syscall_entry = !syscall_entry;

      // Allow the process to continue until the next syscall entry/exit.
      rc = ptrace(PTRACE_SYSCALL, pid, 0, 0);
      assert(rc == 0);
    }
  }
  return 0;
}
