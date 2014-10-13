//============================================================================
// Name        : liblibinject.cpp
// Author      : William DeGraaf
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <argp.h>
#include <liblibinject.h>

#include "cmdargs.h"

int main(int argc, char** argv)
{
	inject::inject_settings args;
	args.fn_name = "libmain";
	argp_parse(&inject::argp, argc, argv, 0, 0, &args);

	auto result =
			inject::create_remote_thread(args.pid, args.libname,args.fn_name);
	if (result == inject::inject_error::attach)
	{
		std::cerr <<
				"Could not attach, are you sure ptrace_scope is disabled?\n";
		return 1;
	}
	else if (result != inject::inject_error::none)
	{
		std::cerr << "Could not complete injection\n";
		return 1;
	}
	return 0;
}
