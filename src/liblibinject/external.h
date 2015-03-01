/*
 * external.h
 *
 *  Created on: Feb 22, 2015
 *      Author: skim
 */

#ifndef EXTERNAL_H_
#define EXTERNAL_H_

#include <unistd.h>
#include <string>

namespace inject {

// Returns the location of libname in the attached application
// Returns 0 on error
long baseof(pid_t pid, const std::string& libname);

// Get the offset of a symbol in the executable region of a library in memory
long get_offset(const char* lib, pid_t pid, const char* symbol);

// This function is injected into the program to load a library
void external_call_dlopen(
		void* (*extern_dlopen)(const char*, int),
		int (*extern_syscall)(int),
		const char* extern_filename);

// This function is injected to unload a library
void external_call_dlclose(
		void* (*extern_dlopen)(const char*, int),
		int (*extern_dlclose)(void*),
		int (*extern_syscall)(int),
		const char* extern_filename);

// Run the libmain function in the background
void external_main(int (*extern_syscall)(...),
		int (*extern_pt_create)(long*, pthread_attr_t*, void*, void*),
		int (*extern_pt_attr_init)(pthread_attr_t*),
		int (*pt_attr_setdetachstate)(pthread_attr_t*, int),
		void* (*extern_dlsym)(int, const char*),
		const char* fn_name);

} /* namespace inject */
#endif /* EXTERNAL_H_ */
