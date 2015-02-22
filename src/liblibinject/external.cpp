/*
 * external.cpp
 *
 *  Created on: Feb 22, 2015
 *      Author: skim
 */

#include "external.h"

#include <fstream>
#include <dlfcn.h>

namespace inject {

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

// Get the offset of a symbol in the executable region of a library in memory
long get_offset(const char* lib, pid_t pid, const char* symbol)
{
	void* handle = dlopen(lib, RTLD_LAZY);
	if (!handle)
		puts(dlerror());
	long local_offset = (long)dlsym(handle, symbol);
	return local_offset - baseof(getpid(), lib) + baseof(pid, lib);
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

}; /* namespace inject */
