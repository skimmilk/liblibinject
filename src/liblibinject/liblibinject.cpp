/*
 * liblibinject.cpp
 *
 *  Created on: Sep 17, 2014
 *      Author: skim
 */

// c++ includes
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <functional>

// c includes
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/syscall.h>
#include <error.h>
#include <errno.h>

// project includes
#include "liblibinject.h"
#include "multiarch.h"


namespace inject {

// What happens (small version)
// We attach to the program first
// Then we write a call to syscall in assembly to a region of memory
// The program is set to execute the modified region of memory
// The application then continues to call the syscall and we intercept it
// Intercepting the syscall, we make it call mmap and make
//   another region of memory that we can play with
// We inject the code we want in this region of memory
// We restore the small region of memory to normal


// Returns the location of libname in the attached application
// Returns 0 on error
long baseof(pid_t pid, const std::string& libname)
{
	// /proc/$PID/maps file contains the locations of all loaded executables
	std::string proc_str ("/proc/");
	proc_str += std::to_string(pid);
	proc_str += "/maps";

	// Open the maps file and check if opened successfully
	std::ifstream proc_file (proc_str);
	if (proc_file.fail())
		return 0;

	std::string line;
	long base_ptr = 0;
	// each line in maps file is laid out this way
	// <base ptr>-<end ptr> <permissions, rwxp> <ignore> <ignore> <ignore> /path/to/library.so
	while (std::getline(proc_file, line))
	{
		// Does this line describe where libname is?
		auto position = line.find(libname);
		if (position == line.npos)
			continue;

		// Is this mapping executable?
		position = line.find("r-xp");
		if (position == line.npos)
			continue;

		std::string map_begin = line.substr(0, line.find('-'));
		base_ptr = std::stoul(map_begin, nullptr, 16);
	}

	return base_ptr;
}

// Forces the attached program to make a syscall
// Stops execution right before the call is made
void inject_syscall(const remote_state& state, long exec_base)
{
	// This is the data that gets executed and makes a syscall
	//long data = get_syscall_execution();
	unsigned char sis [8]{0x0f, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	long data = *(long*)sis;

	PCHECK(PTRACE_POKEDATA, state.pid, exec_base, data);

	auto regs = state.regs_old;
	COUNTER(regs) = exec_base;
	PCHECK(PTRACE_SETREGS, state.pid, 0, &regs);
}

// Allocate memory inside the attached application
long make_mmap_call(const remote_state& state, long exec_base)
{
	// This is the backup of the executable data being overwritten
	long backup = ptrace(PTRACE_PEEKDATA, state.pid, exec_base, 0);
	auto regs = state.regs_old;

	inject_syscall(state, exec_base);

	// Now the program is stuck right before the system call
	// Make it call mmap
	//mmap(void *addr, size_t length, int prot, int flags,
	//                  int fd, off_t offset);
	set_syscall_arguments(state, SYS_mmap,
			0, MAP_LENGTH, PROT_READ | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, 0);
    PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);

	// Make it call the correct syscall
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);
    PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);

	// Continue with the syscall
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);

	// The syscall has finished and mmap has been called
	// Get the result of the syscall
    PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);

    // Restore the overwritten executable data
    PCHECK(PTRACE_POKEDATA, state.pid, exec_base, backup);

	return RESULT(regs);
}

// This function is injected into the program
void external_call_dlopen(
		std::function<void*(const char*,int)> extern_dlopen,
		std::function<int(int)> extern_syscall,
		const char* extern_filename)
{
	extern_dlopen(extern_filename, 0);
	extern_syscall(1337);
}

inject_error create_remote_thread(pid_t pid, int verbose)
{
	remote_state state;
	state.verbose = verbose;
	state.pid = pid;

	// Attach to the program
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
    	std::cerr << "Could not attach, are you sure ptrace_scope is disabled?\n";
    	return inject_error::attach;
    }
    wait(0);

    // Backup the registers
    PCHECK(PTRACE_GETREGS, pid, 0, &state.regs_old);

    // Get the base of libc
    auto extern_libc_base = baseof(pid, "libc");
    auto libc_base = baseof(getpid(), "libc");
    // Get the offset of the functions __libc_dlopen_mode and syscall
    //   in the process
    auto extern_dlopen = __libc_dlopen_mode - libc_base + extern_libc_base;
    auto extern_syscall = syscall - libc_base + extern_libc_base;

    if (verbose)
    	printf(stderr, "External dlopen is at %p\nExternal syscall is at %p\n",
    			extern_dlopen, extern_syscall);

    // Get the location of libc in the attached program and in the current one
    state.executable_page = make_mmap_call(state, extern_libc_base);
    if (verbose)
    	fprintf(stderr, "Executable page is at %p, or error %s\n",
    			(void*)state.executable_page, strerror(state.executable_page * -1));

    // Restore the registers from the backup
	PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);

    return inject_error::none;
}

};