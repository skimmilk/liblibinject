/*
 * multiarch.h
 *
 *  Created on: Oct 10, 2014
 *      Author: skim
 */

#ifndef MULTIARCH_H_
#define MULTIARCH_H_

namespace inject{

// Stores information about the attached application
struct remote_state
{
	int verbose;
	// PID of the application to mess with
	pid_t pid;
	// The backup registers of the program
	user_regs_struct regs_old;
	// Where we mapped the region to inject code
	long executable_page;
	// The backup of the stack
	std::vector<long> stack_backup;
};


#define PCHECK(a,b,c,d) {if (ptrace(a,b,c,d)) error(1, errno, __FILE__ ":%d", __LINE__);}

// length of the executable buffer in the attached application
#define MAP_LENGTH (sysconf(_SC_PAGESIZE))


#ifdef __x86_64__
// AMD64 low-level helpers
// Pointer to the stack frame
#define FRAME_PTR(m) m.rbp
#define STACK_TOP(m) m.rsp
// Pointer to the current execution location
#define COUNTER(m) m.rip
#define INJECT_SYSCALL asm volatile (".align 8\t\nsyscall");
#define RESULT(m) m.rax
// Sets the arguments to a system call
void set_syscall_arguments(const remote_state& state, long syscall_n,
		long a1, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct newregs;
	PCHECK(PTRACE_GETREGS, state.pid, 0, &newregs);

	// x86_64 rdi rsi rdx r10 r8 r9
	newregs.rdi = a1;
	newregs.rsi = a2;
	newregs.rdx = a3;
	newregs.r10 = a4;
	newregs.r8 = a5;
	newregs.r9 = a6;

	// The RAX register holds the syscall number
	newregs.rax = newregs.orig_rax = syscall_n;

	// Set the registers
	PCHECK(PTRACE_SETREGS, state.pid, 0, &newregs);
}
#else
// Intel32 low-level helpers
#define FRAME_PTR(m) m.ebp
#define STACK_TOP(m) m.esp
#define COUNTER(m) m.eip
#define INJECT_SYSCALL asm volatile (".align 4\t\nint 0x80");
#define RESULT(m) m.eax
void set_syscall_arguments(remote_state state, long syscall_n
		long a1, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{}
#endif

} /* namespace inject */

#endif /* MULTIARCH_H_ */
