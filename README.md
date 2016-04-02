# liblibinject
##### The library injection library for GNU/Linux

## What it does
liblibinject injects libraries into running processes and calls the provided code.

Using liblibinject is easy, it comes with a simple CLI implementation.
To inject a library into a process using the implementation, use
```./libinject [PID] [LIBRARY]```

Help about the command line can be found with
```./libinject --help```

## Problem description
Library injection on GNU/Linux is much more involved than that on Windows systems.
Windows developers may be familiar with the APIs that aid in code injection,
namely WriteProcessMemory, VirtualAllocEx, and CreateRemoteThread.
I described only three, but there are a number of other interfaces Windows exposes to manipulate processes making
library injection trivial.

Unfortunately on Linux systems, there is only one way to manipulate processes -- through the ptrace(2) API.
While what ptrace can do is limited, I am still able to manipulate the process into loading a library
with some effort and a few clever tricks.

## How it does it
liblibinject depends on two APIs supplied by the OS to do its job:
the ptrace(2) API, and on the function ```__libc_dlopen_mode``` supplied by glibc.

Using ptrace, we are able to modify the execution of running processes.
First, ptrace is used to force the running process to create a code cave through mmap(2).

Through this code cave we can now inject code that will be ran by the process,
such as calls to ```__libc_dlopen_mode```, a clone of dlopen(2) that loads libraries.

You can of course understand the full picture by reading the documentation and code at
```src/liblibinject/liblibinject.cpp```
to get the non-simplified version of this process.

#### License
Everything included is licensed as GPLv3

Check COPYING for explanations
