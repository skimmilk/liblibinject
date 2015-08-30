# liblibinject
##### The library injection library for GNU/Linux

## What it does
The program injects libraries into running processes.
Windows developers may recognize its similarity to the CreateRemoteThread() types of code injection.

Using liblibinject is easy, it comes with a simple CLI implementation of the library.
To inject a library into a process using the implementation, libinject, use
```./libinject [PID] [LIBRARY]```

Help can be found by running
```./libinject --help```

## Problem description
Library injection on GNU/Linux is much more involved than that on Windows systems.
Windows developers may be familiar with the APIs that aid in code injection,
namely WriteProcessMemory, VirtualAllocEx, and CreateRemoteThread.
I described only three, but are a large number of functions Windows exposes to manipulate processes making
library injection trivial.

However, on Linux systems, there is only one way to manipulate processes -- through the ptrace(2) API.
While what ptrace can do is limited, I am still able to manipulate the process into loading a library
with some effort and a few clever tricks.

## How it does it
liblibinject relies on two uncanny utilities supplied by the OS to do its job:
the ptrace(2) API, and on the function ```__libc_dlopen_mode``` supplied by glibc.

Using ptrace, we are able to modify the execution of running processes.
The first thing to happen is we use ptrace to force the running process to create a code cave through mmap(2).

Through this code cave we can now inject code that will be ran by the process --
the calls to ```__libc_dlopen_mode```, a clone of dlopen(2) that loads libraries, being most notable.

You can of course get the full picture by browsing to ```src/liblibinject/liblibinject.cpp``` and reading the code to
get the non-simplified version of how it works.

#### License
Everything included is licensed as GPLv3

Check COPYING for explanations
