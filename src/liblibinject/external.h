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

// The function type of libc's syscall()
typedef int (*syscall_fn)(int, ...);

// Function types of libdl functions
typedef void* (*dlopen_fn)(const char*, int);
typedef int (*dlclose_fn)(void*);
typedef void* (*dlsym_fn)(int, const char*);

// Function types of pthread library functions
typedef int (*pthread_create_fn)(long*, pthread_attr_t*, void*, void*);
typedef int (*pthread_attr_init_fn)(pthread_attr_t*);
typedef int (*pthread_attr_setdetachstate_fn)(pthread_attr_t*, int);

// This function is injected into the program to load a library
// flags variable is passed to the dlopen function
void external_call_dlopen(dlopen_fn, syscall_fn, int flags, const char* extern_filename);

// Unloads a library opened by dlopen by handle
void external_call_dlclose(dlclose_fn, syscall_fn, void* handle);

// Run the libmain function in the background
void external_main(
		syscall_fn,
		pthread_create_fn,
		pthread_attr_init_fn,
		pthread_attr_setdetachstate_fn,
		dlsym_fn,
		const char* fn_name);

} /* namespace inject */
#endif /* EXTERNAL_H_ */
