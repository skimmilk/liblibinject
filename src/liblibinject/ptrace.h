/*
 * ptrace.h
 *
 *  Created on: Feb 22, 2015
 *      Author: skim
 *
 * Purpose: This layer deals with ptrace debugging and injection
 */

#ifndef PTRACE_H_
#define PTRACE_H_

#include <sys/user.h>
#include <unistd.h>
#include <vector>

namespace inject{

// Stores information about the attached application
struct remote_state
{
	// PID of the application to mess with
	pid_t pid;
	// The backup registers of the program
	user_regs_struct regs_old;
	// Where we mapped the region to inject code
	long executable_page;
	// The backup of the stack
	std::vector<long> stack_backup;
};

// length of the executable buffer in the attached application
#define MAP_LENGTH (sysconf(_SC_PAGESIZE))

// Make the program do a syscall
// Will backup & restore program state
long make_syscall(remote_state& state,
		long syscall_num,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0);

// Force the process to call function
// Will backup & restore program state
// Returns the result of the call
long extern_call(remote_state& state, long* local_fn,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0);

// Copy string into location ptr in external process
void extern_strcpy(pid_t pid, const char* str, long ptr);

// Return false on failure
bool attach(remote_state&);
void detach(remote_state&);

}; /* namespace inject */
#endif /* PTRACE_H_ */
