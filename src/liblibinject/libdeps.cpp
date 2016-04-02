/*
 * libdeps.cpp
 *
 *  Created on: Feb 21, 2015
 *      Author: skim
 */

#include <vector>
#include <algorithm>
#include <iostream>
#include <limits.h>
#include <csp/string.h>
#include <csp/exec.h>

#include "libdeps.h"

namespace inject{

CSP_DECL(accumulate, csp::string, csp::nothing, std::set<std::string>*)
												(std::set<std::string>* result)
{
	csp::string input;
	while (read(input))
		result->insert(input.std_string());
}

// Get the names of all libraries needed by library
bool library_dependencies(const std::string& libraryname, std::set<std::string>& result)
{
	std::atomic<int> error;

	// This grabs the path of all libraries it depends on
	// It also effectively removes the pseudo-library linux-gate.so by
	//   grep'ing for the path / to make sure the file is in a folder
	//   and ignores errors from ldd scripts that check for executable bit
	std::string arg = "ldd ";
	arg += libraryname;
	arg += " 2>/dev/null | cut -d/ -f2- | awk '{print $1}' | grep /"
			" | sed 's/^/\\//g' | xargs realpath 2>/dev/null"
			" | ifne xargs readlink -e 2>/dev/null";

	csp::exec_r(arg.c_str(), &error) | accumulate(&result);

	return error.load(std::memory_order_relaxed);
}

// Sort the dependencies based on their dependencies
std::vector<std::string> sort_dependencies(const std::set<std::string>& input)
{
	std::vector<std::string> result;
	std::set<std::string> copy;
	for (auto plib = input.begin(); plib != input.end(); plib++)
	{
		char path [PATH_MAX];
		copy.insert(std::string(realpath(plib->c_str(), path)));
	}

	while (copy.size())
	{
		// For each library in the input,
		//  if it has any dependencies other than what is in the result,
		//    throw it out
		//  otherwise, put it in the result
		for (auto plib = copy.begin(); plib != copy.end(); plib++)
		{
			// The dependencies for this specific library
			std::set<std::string> deps;
			//auto name = plib->substr(plib->find_last_of('/'));
			library_dependencies(*plib, deps);
			// Determine if all of the dependencies are in the result
			if (std::all_of(deps.begin(), deps.end(),
				[result](std::string d)
				{
					return std::count(result.begin(), result.end(), d) > 0;
				}))
			{
				// Add to the result vector
				result.push_back(*plib);
				copy.erase(plib);
				break;
			}
		}
	}
	return result;
}

}; /* namespace inject */
