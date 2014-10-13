/*
 * liblibinject.h
 *
 *  Created on: Sep 17, 2014
 *      Author: skim
 */

#ifndef LIBLIBINJECT_H_
#define LIBLIBINJECT_H_

#include <sys/types.h>

namespace inject {

enum class inject_error {
	none, attach, interrupt, path
	// attach signals that we cannot use ptrace against the process
	// interrupt signals that the program is not in a modifiable state
	// path signals that the length of libname or function is too long
};

// libname is the path to the library to inject
// function is the name of the library function, defaults to "libmain"
inject_error create_remote_thread(pid_t pid, const char* libname,
		const char* function = NULL);

};


#endif /* LIBLIBINJECT_H_ */
