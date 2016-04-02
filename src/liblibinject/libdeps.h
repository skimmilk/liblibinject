/*
 * libdeps.h
 *
 *  Created on: Feb 21, 2015
 *      Author: skim
 */

#ifndef LIBDEPS_H_
#define LIBDEPS_H_

#include <set>
#include <vector>
#include <string>

namespace inject{

// Get all shared library dependencies of a library
// Returns true if error
bool library_dependencies(const std::string& libname, std::set<std::string>& result);

// Sort libraries so that the previous do not depend on the latter
// The input set is destroyed in the process
std::vector<std::string> sort_dependencies(const std::set<std::string>& input);

}; /* namespace inject */
#endif /* LIBDEPS_H_ */
