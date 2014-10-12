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
#include <dlfcn.h>

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
// Set up the program to do a syscall, but without doing so
void setup_syscall(const remote_state& state, long exec_base)
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

// Saves a part of the top of the stack, assumes empty backup
void backup_stack(remote_state& state)
{
	long* top = (long*)STACK_TOP(state.regs_old);
	for (int i = 0; i < 64; i++)
	{
		state.stack_backup.push_back(
				ptrace(PTRACE_PEEKTEXT, state.pid, top - i, 0));
	}
}
// Restores the stack and deletes the backup
void restore_stack(remote_state& state)
{
	long* top = (long*)STACK_TOP(state.regs_old);
	for (int i = 0; i < 64; i++)
		PCHECK(PTRACE_POKEDATA, state.pid, top - i, state.stack_backup[i]);
	state.stack_backup.clear();
}

// Make the program do a syscall
long make_syscall(remote_state& state, long exec_base,
		long syscall_num,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct regs;

	// This is the backup of the executable data
	long backup = ptrace(PTRACE_PEEKDATA, state.pid, exec_base, 0);

	// Backup the registers and stack
	PCHECK(PTRACE_GETREGS, state.pid, 0, &state.regs_old);
	backup_stack(state);


	// Now the program is stuck right before the system call,
	//   make it do the call
	setup_syscall(state, exec_base);
	set_syscall_arguments(state, syscall_num, a1, a2, a3, a4, a5, a6);

	// Make it call the correct syscall
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);

	// Continue with the syscall
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);

	// The syscall has finished, get the result of the syscall
	PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);

	// Restore the overwritten executable data
	PCHECK(PTRACE_POKEDATA, state.pid, exec_base, backup);

	// Restore the registers and stack from backup
	PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);
	restore_stack(state);

	return RESULT(regs);
}

// Get the offsets of dlopen and syscall in the process
void get_external_offsets(
		long local_libc_base, long extern_libc_base,
		long& extern_dlopen, long& extern_syscall)
{
	// Get the offset of the functions __libc_dlopen_mode and syscall
	//   in the process
	long local_dlopen = (long)dlsym(0, "__libc_dlopen_mode");
	long local_syscall = (long)dlsym(0, "syscall");

	extern_dlopen = local_dlopen - local_libc_base + extern_libc_base;
	extern_syscall = local_syscall - local_libc_base + extern_libc_base;

#ifdef DEBUG
		fprintf(stderr, "Local libc is loaded at %p\n", (void*)local_libc_base);
		fprintf(stderr, "Local dlopen is at %p\n", (void*)local_dlopen);
		fprintf(stderr, "Local syscall is at %p\n", (void*)local_syscall);

		fprintf(stderr, "Offset of dlopen is %p\n",
				(void*)(local_dlopen - local_libc_base));
		fprintf(stderr, "Offset of syscall is %p\n",
				(void*)(local_syscall - local_libc_base));

		fprintf(stderr, "External libc is loaded at %p\n",
				(void*)extern_libc_base);
		fprintf(stderr,
				"External dlopen is at %p\nExternal syscall is at %p\n\n",
				(void*)extern_dlopen, (void*)extern_syscall);
#endif
}

// copy amount of longs into process
void extern_longcpy(pid_t pid, long* input, int amount, long* output)
{
	for (int i = 0; i < amount; i++)
		PCHECK(PTRACE_POKEDATA, pid, (void*)(output + i), (void*)input[i]);
}
// Copy string into location ptr in external process
void extern_strcpy(pid_t pid, const char* str, long ptr)
{
	// Amount of longs to copy, round up +1
	int amount = (strlen(str) + sizeof(long)) / sizeof(long);
	extern_longcpy(pid, (long*)str, amount, (long*)ptr);
}

// Force the process to call function
void extern_call(remote_state& state, long fnptr,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0)
{
	// Backup stack, registers
	PCHECK(PTRACE_GETREGS, state.pid, 0, &state.regs_old);
	backup_stack(state);

	set_usercall_arguments(state,a1,a2,a3,a4,a5);

	// Set the program counter to the function pointer
	user_regs_struct regs;
	PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);
	COUNTER(regs) = fnptr;
	PCHECK(PTRACE_SETREGS, state.pid, 0, &regs);


	// Wait for syscall(1337)
	while (true)
	{
		PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
		wait(0);
		PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);
		if (ORIG_SYSCALL(regs) == 1337)
			break;
	}

	// Let it fire the syscall and return back to normal
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);

	// Restore stack, registers
	PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);
	restore_stack(state);
}

// This function is injected into the program
void external_call_dlopen(
		void* (*extern_dlopen)(const char*, int),
		int (*extern_syscall)(int),
		const char* extern_filename)
{
	extern_dlopen(extern_filename, RTLD_NOW);
	extern_syscall(1337);
}

inject_error create_remote_thread(pid_t pid, const char* libname)
{
	remote_state state;
	state.pid = pid;

	// Attach to the program
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
		return inject_error::attach;
	wait(0);

	// Get the base of libc
	long extern_libc_base = baseof(pid, "libc");
	long local_libc_base = baseof(getpid(), "libc");

	// Get the offsets of dlopen and syscall in the program's memory
	long extern_dlopen, extern_syscall;
	get_external_offsets(local_libc_base, extern_libc_base,
			extern_dlopen, extern_syscall);

	// Force the program to make a buffer for us to inject code/data into
	state.executable_page = make_syscall(state, extern_libc_base,
			SYS_mmap,
			0, MAP_LENGTH, PROT_READ | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, 0);

	if (state.executable_page == (long)0xffffffffffffffda)
	{
		// This gets returned from a bad syscall for unknown reasons
		PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);
		PCHECK(PTRACE_DETACH, state.pid, 0, 0);
		return inject_error::interrupt;
	}

#ifdef DEBUG
		fprintf(stderr, "Executable page is at %p, or error %s\n",
				(void*)state.executable_page, strerror(state.executable_page));
#endif

	// Copy libname into the program's buffer
	extern_strcpy(pid, libname, state.executable_page + 1024);

#ifdef DEBUG
	// Test the syscall and copy_mem function
	make_syscall(state, extern_libc_base,
			SYS_write, 2, state.executable_page + 1024, strlen(libname));
#endif

	// Copy the function to call into the buffer and make the process call it
	extern_longcpy(pid, (long*)external_call_dlopen, 1024 / sizeof(long),
			(long*)state.executable_page);
	extern_call(state, state.executable_page,
			extern_dlopen, extern_syscall, state.executable_page + 1024);

	// Delete the executable buffer
	make_syscall(state, extern_libc_base,
			SYS_munmap, state.executable_page, MAP_LENGTH);

	// Detach
	PCHECK(PTRACE_DETACH, state.pid, 0, 0);

	return inject_error::none;
}

};
