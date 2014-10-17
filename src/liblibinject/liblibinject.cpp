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
#include <pthread.h>
#include <linux/limits.h>

// project includes
#include "liblibinject.h"
#include "multiarch.h"


namespace inject {

// What happens (small version)
// We attach to the program first
// Then we force the process to create a small executable buffer
// We write code to the buffer that will load the library
// We force the application to run the injected code
// We force the application to run the library main function
// Clean up and exit


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
	// <base ptr>-<end ptr> <permissions> <ignore> <ignore> <ignore> lib.so
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

		// Get the base pointer
		std::string map_begin = line.substr(0, line.find('-'));
		base_ptr = std::stoul(map_begin, nullptr, 16);
	}

	return base_ptr;
}

// Forces the attached program to make a syscall
// Set up the program to do a syscall, but without doing so
void setup_syscall(const remote_state& state, long exec_base)
{
	// Shellcode to inject, shellcode calls syscall interrupt
	long data = SHELL_SYSCALL;
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
		state.stack_backup.push_back(
				ptrace(PTRACE_PEEKTEXT, state.pid, top - i, 0));
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
// Will backup & restore program state
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
	set_syscall_arguments(state.pid, syscall_num, a1, a2, a3, a4, a5, a6);

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
long get_offset(const char* lib, pid_t pid, const char* symbol)
{
	long local_offset = (long)dlsym(0, symbol);
	return local_offset - baseof(getpid(), lib) + baseof(pid, lib);
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
// Will backup & restore program state
void extern_call(remote_state& state, long* local_fn,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	// Write the function stored here to the process
	extern_longcpy(state.pid, local_fn, 1024 / sizeof(long),
			(long*)state.executable_page);

	// Backup stack, registers
	PCHECK(PTRACE_GETREGS, state.pid, 0, &state.regs_old);
	backup_stack(state);

	set_usercall_arguments(state.pid,a1,a2,a3,a4,a5,a6);

	// Set the program counter to the function pointer
	user_regs_struct regs;
	PCHECK(PTRACE_GETREGS, state.pid, 0, &regs);
	COUNTER(regs) = state.executable_page;
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

// This function is injected into the program to load a library
void external_call_dlopen(
		void* (*extern_dlopen)(const char*, int),
		int (*extern_syscall)(int),
		const char* extern_filename)
{
	extern_dlopen(extern_filename, RTLD_NOW | RTLD_GLOBAL);
	extern_syscall(1337);
}

// Run the libmain function in the background
void external_main(int (*extern_syscall)(...),
		int (*extern_pt_create)(long*, pthread_attr_t*, void*, void*),
		int (*extern_pt_attr_init)(pthread_attr_t*),
		int (*pt_attr_setdetachstate)(pthread_attr_t*, int),
		void* (*extern_dlsym)(int, const char*),
		const char* fn_name)
{
	// Initialize the created thread as detached
	pthread_attr_t tattr;
	extern_pt_attr_init(&tattr);
	pt_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

	// Get the function to run in the background
	void* libmain = extern_dlsym(0, fn_name);
	long thread;
	// Call the function in the background
	extern_pt_create(&thread, &tattr, libmain, NULL);
	extern_syscall(1337);
}

void inject_library(remote_state& state, const char* name,
		long extern_dlopen, long extern_syscall)
{
	// Copy libname into the program's buffer
	extern_strcpy(state.pid, name, state.executable_page + 1024);

	extern_call(state, (long*)external_call_dlopen,
			extern_dlopen, extern_syscall, state.executable_page + 1024);
}

inject_error create_remote_thread(pid_t pid, const char* libname,
		const char* libmain)
{
	remote_state state;
	state.pid = pid;

	// Get the full path to libname if it doesn't start with /
	std::string library_path;
	if (libname[0] != '/')
	{
		char buf[PATH_MAX];
		if (!getcwd(buf, PATH_MAX))
			return inject_error::path;

		library_path = buf;
		library_path += "/";
		library_path += libname;
	}
	else
		library_path = libname;

	// Don't continue if libname or fn_name is too long and can't be copied
	const size_t max_strlen = MAP_LENGTH / 2 - 1;
	if (library_path.length() >= max_strlen)
		return inject_error::path;
	if (libmain && strlen(libmain) >= max_strlen)
		return inject_error::path;

	// Attach to the program
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
		return inject_error::attach;
	wait(0);

	// Get the base of libc, needed for make_syscall
	long extern_libc_base = baseof(pid, "libc");

	// Get the offsets of dlopen and syscall in the program's memory
	long extern_dlopen = get_offset("libc", pid, "__libc_dlopen_mode");
	long extern_syscall = get_offset("libc", pid, "syscall");

	// Force the program to make a buffer for us to inject code/data into
	state.executable_page = make_syscall(state, extern_libc_base,
			SYS_mmap,
			0, MAP_LENGTH, PROT_READ | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, 0);

	if (state.executable_page == (long)0xffffffffffffffda)
	{
		// Returned from processes that are SIGSTOP'ed for unknown reasons
		PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);
		PCHECK(PTRACE_DETACH, state.pid, 0, 0);
		return inject_error::interrupt;
	}

#ifdef DEBUG
		fprintf(stderr, "Executable page is at %p, or error %s\n",
				(void*)state.executable_page, strerror(state.executable_page));
		// Test syscall and strcpy
		extern_strcpy(pid, "hello world\n", state.executable_page + 1024);
		make_syscall(state, extern_libc_base, SYS_write, 1,
				state.executable_page + 1024, 12);
#endif

	// Inject the given library and others into the process
	inject_library(state, library_path.c_str(), extern_dlopen, extern_syscall);
	inject_library(state, "libpthread.so.0", extern_dlopen, extern_syscall);
	inject_library(state, "libdl.so.2", extern_dlopen, extern_syscall);

	// Get necessary pthread functions
	long extern_ptcreate = get_offset("pthread", pid, "pthread_create");
	long extern_ptattrinit = get_offset("pthread", pid, "pthread_attr_init");
	long extern_ptattrset = get_offset("pthread", pid,
			"pthread_attr_setdetachstate");

	// Get the dlsym function so the process can find the libmain function
	long extern_dlsym = get_offset("libdl", pid, "dlsym");

	// Finally, copy the name of the library function to execute and run it
	libmain = libmain? libmain : "libmain";
	extern_strcpy(pid, libmain, state.executable_page + 1024);

	extern_call(state, (long*)external_main, extern_syscall, extern_ptcreate,
			extern_ptattrinit, extern_ptattrset, extern_dlsym,
			state.executable_page + 1024);

	// Delete the executable buffer
	make_syscall(state, extern_libc_base,
			SYS_munmap, state.executable_page, MAP_LENGTH);
	PCHECK(PTRACE_DETACH, pid, 0, 0);

	return inject_error::none;
}

};
