/*
 * ptrace.cpp
 *
 *  Created on: Feb 22, 2015
 *      Author: skim
 */

#include "ptrace.h"

#include <string>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/syscall.h>
#include <error.h>
#include <errno.h>

#include "multiarch.h"
#include "external.h"

namespace inject {

// Forces the attached program to make a syscall
// Set up the program to do a syscall, but without doing so
static void setup_syscall(const remote_state& state, long exec_base)
{
	// Shellcode to inject, shellcode calls syscall interrupt
	long data = SHELL_SYSCALL;
	PCHECK(PTRACE_POKEDATA, state.pid, exec_base, data);

	auto regs = state.regs_old;
	COUNTER(regs) = exec_base;
	PCHECK(PTRACE_SETREGS, state.pid, 0, &regs);
}

// Saves a part of the top of the stack, assumes empty backup
static void backup_stack(remote_state& state)
{
	long* top = (long*)STACK_TOP(state.regs_old) + 64;
	for (int i = 0; i < 128; i++)
		state.stack_backup.push_back(
				ptrace(PTRACE_PEEKTEXT, state.pid, top - i, 0));
}
// Restores the stack and deletes the backup
static void restore_stack(remote_state& state)
{
	long* top = (long*)STACK_TOP(state.regs_old) + 64;
	for (int i = 0; i < 128; i++)
		PCHECK(PTRACE_POKEDATA, state.pid, top - i, state.stack_backup[i]);
	state.stack_backup.clear();
}

// Make the program do a syscall
// Will backup & restore program state
long make_syscall(remote_state& state,
		long syscall_num,
		long a1, long a2, long a3, long a4, long a5, long a6)
{
	user_regs_struct regs;

	// Location of libc in process, needed to find syscall shellcode
	auto exec_base = baseof(state.pid, "libc-2.19.so");

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
// copy amount of longs into process
static void extern_longcpy(pid_t pid, long* input, int amount, long* output)
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
long extern_call(remote_state& state, long* local_fn,
		long a1, long a2, long a3, long a4, long a5, long a6)
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
#ifdef DEBUG
		std::cerr << "Intercepted syscall " << ORIG_SYSCALL(regs) << "\n";
#endif
		if (ORIG_SYSCALL(regs) == 1337)
			break;
	}

	long result = (long)SECOND_ARGUMENT(regs);
#ifdef DEBUG
	std::cerr << "Callee returned " << result << "\n";
#endif

	// Let it fire the syscall and return back to normal
	PCHECK(PTRACE_SYSCALL, state.pid, 0, 0);
	wait(0);

	// Restore stack, registers
	PCHECK(PTRACE_SETREGS, state.pid, 0, &state.regs_old);
	restore_stack(state);

	return result;
}

bool attach(remote_state& state)
{
	if (ptrace(PTRACE_ATTACH, state.pid, 0, 0) == -1)
		return false;
	wait(0);

#ifdef __x86_64__
	const int syscall_mmap = SYS_mmap;
#else
	const int syscall_mmap = SYS_mmap2;
#endif

	// Force the program to make a buffer for us to inject code/data into
	state.executable_page = make_syscall(state,
			syscall_mmap,
			0, MAP_LENGTH, PROT_READ | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, 0);

	return true;
}

void detach(remote_state& state)
{
	// Delete the executable buffer
	make_syscall(state,
			SYS_munmap, state.executable_page, MAP_LENGTH);
	PCHECK(PTRACE_DETACH, state.pid, 0, 0);
}
}; /* namespace inject */
