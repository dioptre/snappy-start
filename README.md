
# snappy-start: Tool for process startup snapshots

snappy-start is a tool which takes a snapshot of a Linux program's process
state after it has started up.  It allows multiple instances of the program
to be quickly launched from the snapshot.

This has two potential benefits:

* Faster startup, if the program does a non-trivial amount of computation
  during startup.

* Saving memory, because memory pages that the program writes to during
  startup will be shared between the instances.


## Usage

First, build the tool by running `make.sh` (which also runs some tests).

To create a snapshot:

```
./out/ptracer ./out/elf_loader PROG ARGS...
```

This creates a self-contained executable `replay.out` in the current
directory. Run it to restore the snapshot.

The program will be snapshotted when it first calls an unhandled
syscall, such as `getpid()`.

Example:

```
$ ./out/ptracer ./out/elf_loader /usr/bin/python tests/python_example.py
$ ./replay.out
Hello world, from restored Python process
```


## Credits

The idea for this tool comes from Kenton Varda, who proposed using a
"record/replay" approach, using `ptrace()` to monitor syscalls so that
they can later be replayed.

Mark Seaborn put together an initial working end-to-end implementation.

Kenton enhanced the implementation to produce a self-contained binary
and extended it with support for more syscalls.
