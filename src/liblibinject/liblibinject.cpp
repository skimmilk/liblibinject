/*
 * liblibinject.cpp
 *
 *  Created on: Sep 17, 2014
 *      Author: skim
 */

#include <string>
#include <iostream>
#include <vector>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include <dlfcn.h>

// project includes
#include "liblibinject.h"
#include "ptrace.h"
#include "external.h"
#include "libdeps.h"


namespace inject {

#ifdef __x86_64__
#define LIB_FLDR "/lib/x86_64-linux-gnu"
#else
#define LIB_FLDR "/lib/i386-linux-gnu"
#endif

// What happens (small version)
// We attach to the program first
// Then we force the process to create a small executable buffer
// We write code to the buffer that will load the library
// We force the application to run the injected code
// We force the application to run the library main function
// Clean up and exit

// Call dlopen with name and dl_flags as arguments
// Returns handle provided by dlopen
long load_library(remote_state& state, const char* name,
		long extern_dlopen, long extern_syscall,
		long dl_flags)
{
	// Copy libname into the program's buffer
	extern_strcpy(state.pid, name, state.executable_page + 1024);

	return extern_call(state, (long*)external_call_dlopen,
			extern_dlopen, extern_syscall, dl_flags, state.executable_page + 1024);
}

// Force the program to unload a library
long remove_library(remote_state& state,
		long extern_dlclose, long extern_syscall,
		long handle)
{
	return extern_call(state, (long*)external_call_dlclose,
			extern_dlclose, extern_syscall, handle);
}

// Returns true if error
// Sets library_path to full path to libname
bool library_full_path(const char* libname, std::string& library_path)
{
	// Get the full path to libname if it doesn't start with /
	if (libname[0] != '/')
	{
		char buf[PATH_MAX];
		if (!getcwd(buf, PATH_MAX))
			return true;

		library_path = buf;
		library_path += "/";
		library_path += libname;
	}
	else
		library_path = libname;
	return false;
}

// Return true if name of library or function is invalid
bool check_lib_strs(const std::string& library_path, const char* libmain)
{
	// Don't continue if libname or fn_name is too long and can't be copied
	const size_t max_strlen = MAP_LENGTH / 2 - 1;
	if (library_path.length() >= max_strlen)
		return true;
	if (libmain && strlen(libmain) >= max_strlen)
		return true;
	return false;
}

// Return a list of library paths
bool generate_sorted_dependencies(const std::string& name,
		std::vector<std::string>& result)
{
	// Get all the libraries the library depends on
	std::set<std::string> dependencies;
	if (library_dependencies(name, dependencies))
		return true;

	// Insert our dependencies, libdl and libpthread
	dependencies.insert(LIB_FLDR "/libdl.so.2");
	dependencies.insert(LIB_FLDR "/libpthread.so.0");

	// Sort the dependencies
	result = sort_dependencies(dependencies);
#ifdef DEBUG
	for (const auto& a : result)
		std::cerr << "Injection depends on " << a << "\n";
#endif
	return false;
}

inject_error create_remote_thread(pid_t pid, const char* libname,
		const char* libmain)
{
	remote_state state;
	state.pid = pid;

	// Get the full path of program
	std::string library_path;
	if (library_full_path(libname, library_path))
		return inject_error::path;

	// Check if strings are copyable
	if (check_lib_strs(library_path, libmain))
		return inject_error::path;

	// Get the dependences for the library to be injected
	std::vector<std::string> dependencies;
	if (generate_sorted_dependencies(library_path, dependencies))
		return inject_error::path;

	// Attach to the program
	if (!attach(state))
		return inject_error::attach;

	// Get the offsets of dlopen and syscall in the program's memory
	long extern_dlopen = get_offset(LIB_FLDR "/libc-2.19.so", pid, "__libc_dlopen_mode");
	long extern_syscall = get_offset(LIB_FLDR "/libc-2.19.so", pid, "syscall");

	// Inject the given library and other libraries that we need into the process
	for (const auto& dep : dependencies)
		load_library(state, dep.c_str(), extern_dlopen, extern_syscall, RTLD_NOW | RTLD_GLOBAL);
	load_library(state, library_path.c_str(), extern_dlopen, extern_syscall, RTLD_NOW | RTLD_GLOBAL);

	// Get necessary pthread functions
	long extern_ptcreate = get_offset(LIB_FLDR "/libpthread-2.19.so", pid, "pthread_create");
	long extern_ptattrinit = get_offset(LIB_FLDR "/libpthread-2.19.so", pid, "pthread_attr_init");
	long extern_ptattrset = get_offset(LIB_FLDR "/libpthread-2.19.so", pid,
			"pthread_attr_setdetachstate");

	// Get the dlsym function so the process can find the libmain function
	long extern_dlsym = get_offset(LIB_FLDR "/libdl-2.19.so", pid, "dlsym");

	// Finally, copy the name of the library function to execute and run it
	libmain = libmain? libmain : "libmain";
	extern_strcpy(pid, libmain, state.executable_page + 1024);

	extern_call(state, (long*)external_main, extern_syscall, extern_ptcreate,
			extern_ptattrinit, extern_ptattrset, extern_dlsym,
			state.executable_page + 1024);

	detach(state);
	return inject_error::none;
}

inject_error unload_library(pid_t pid, const char* libname)
{
	remote_state state;
	state.pid = pid;

	// Get the full path of program
	std::string library_path;
	if (library_full_path(libname, library_path))
		return inject_error::path;

	// Check if strings are copyable
	if (check_lib_strs(library_path, nullptr))
		return inject_error::path;

	// Get the dependences for the library to be injected
	std::vector<std::string> dependencies;
	if (generate_sorted_dependencies(library_path, dependencies))
		return inject_error::path;

	// Attach to the program
	if (!attach(state))
		return inject_error::attach;

	// Get the offsets of dlclose and syscall in the program's memory
	long extern_dlclose = get_offset(LIB_FLDR "/libdl-2.19.so", pid, "dlclose");
	long extern_dlopen = get_offset(LIB_FLDR "/libdl-2.19.so", pid, "dlopen");
	long extern_syscall = get_offset(LIB_FLDR "/libc-2.19.so", pid, "syscall");

	// Remove the library and its dependencies in reverse order
	long handle = load_library(state, libname,
			extern_dlopen, extern_syscall,
			RTLD_NOLOAD);
	remove_library(state, extern_dlclose, extern_syscall, handle);

	for (auto dep = dependencies.rbegin(); dep != dependencies.rend(); dep++)
	{
		handle = load_library(state, dep->c_str(),
				extern_dlopen, extern_syscall,
				RTLD_NOLOAD);
		remove_library(state, extern_dlclose, extern_syscall, handle);
	}

	detach(state);
	return inject_error::none;
}

};
