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
	inject::cmdargs::inject_settings args;
	argp_parse(&inject::cmdargs::argp, argc, argv, 0, 0, &args);

	if (inject::create_remote_thread(args.pid, args.verbose) != inject::inject_error::none)
	{
		std::cerr << "Could not complete injection.\n";
		return 1;
	}
	return 0;
}
