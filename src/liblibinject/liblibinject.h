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
	none, attach, interrupt
};
inject_error create_remote_thread(pid_t pid, const char* libname);

};


#endif /* LIBLIBINJECT_H_ */
