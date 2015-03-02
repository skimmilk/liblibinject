/*
 * multiarch.h
 *
 *  Created on: Oct 10, 2014
 *      Author: skim
 * Purpose: To be used by ptrace.cpp only
 */

#ifndef MULTIARCH_H_
#define MULTIARCH_H_

namespace inject{

#define PCHECK(a,b,c,d) {if (ptrace(a,b,c,d)) error(1, errno, __FILE__ ":%d", __LINE__);}

#ifdef __x86_64__
// AMD64 low-level helpers
// Pointer to the stack frame
#define FRAME_PTR(m) m.rbp
#define STACK_TOP(m) m.rsp
// Pointer to the current execution location
#define COUNTER(m) m.rip
#define RESULT(m) m.rax
#define ORIG_SYSCALL(m) m.orig_rax
#define SECOND_ARGUMENT(m) m.rdi
// Shellcode for syscall
#define SHELL_SYSCALL 0x050f
// Sets the arguments to a system call
static void set_syscall_arguments(pid_t pid, long syscall_n,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct newregs;
	PCHECK(PTRACE_GETREGS, pid, 0, &newregs);

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
	PCHECK(PTRACE_SETREGS, pid, 0, &newregs);
}
static void set_usercall_arguments(pid_t pid,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct newregs;
	PCHECK(PTRACE_GETREGS, pid, 0, &newregs);

	// x86_64 rdi rsi rdx rcx r8 r9 XMM0...
	newregs.rdi = a1;
	newregs.rsi = a2;
	newregs.rdx = a3;
	newregs.rcx = a4;
	newregs.r8 = a5;
	newregs.r9 = a6;

	// Set the registers
	PCHECK(PTRACE_SETREGS, pid, 0, &newregs);
}
#else
// Intel32 low-level helpers
#define FRAME_PTR(m) m.ebp
#define STACK_TOP(m) m.esp
#define COUNTER(m) m.eip
#define RESULT(m) m.eax
#define ORIG_SYSCALL(m) m.orig_eax
#define SECOND_ARGUMENT(m) m.ebx
#define SHELL_SYSCALL 0x80CD
// http://esec-lab.sogeti.com/post/2011/07/05/Linux-syscall-ABI
static void set_syscall_arguments(pid_t pid, long syscall_n,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct newregs;
	PCHECK(PTRACE_GETREGS, pid, 0, &newregs);

	// i386 ebx ecx edx esi edi ebp
	newregs.ebx = a1;
	newregs.ecx = a2;
	newregs.edx = a3;
	newregs.esi = a4;
	newregs.edi = a5;
	newregs.ebp = a6;

	newregs.eax = newregs.orig_eax = syscall_n;

	PCHECK(PTRACE_SETREGS, pid, 0, &newregs);
}
static void set_usercall_arguments(pid_t pid,
		long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
{
	user_regs_struct newregs;
	PCHECK(PTRACE_GETREGS, pid, 0, &newregs);

	long* argptr = (long*)newregs.ebp + 1;
	newregs.esp = newregs.ebp;
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a1);
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a2);
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a3);
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a4);
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a5);
	PCHECK(PTRACE_POKEDATA, pid, argptr++, a6);

	PCHECK(PTRACE_SETREGS, pid, 0, &newregs);
}
#endif

} /* namespace inject */

#endif /* MULTIARCH_H_ */
