/*
 * cmdargs.h
 *
 *  Created on: Sep 17, 2014
 *      Author: skim
 */

// To be only included by
#ifndef CMDARGS_H_
#define CMDARGS_H_

#include <argp.h>
#include <stdlib.h>
#include <liblibinject.h>

namespace inject
{

struct inject_settings
{
	pid_t pid;
	const char* libname;
	// The name of the function to run, defaults to 'libmain'
	const char* fn_name;
	// True if injecting, false if unloading
	bool inject;
};

struct inject_settings* punstate;
static char args_doc[] = "PID LIBRARY";
static char doc[] =
		"libinject - inject libraries into processes";

static struct argp_option options[] = {
		{"function", 'f', "NAME", 0, "The name of the library function to run", 0},
		{"inject", 'i', 0, 0, "Inject library into process", 0},
		{"unload", 'u', 0, 0, "Unload a library that was injected from the process", 0},
		// The things I do to silence compiler warnings...
		{0,0,0,0,0,0}
};

error_t parse_opt (int key, char* arg, struct argp_state* state)
{
	inject_settings* punstate = (inject_settings*)state->input;
	switch (key)
	{
	case 'f':
		punstate->fn_name = arg;
		break;
	case 'i':
		punstate->inject = true;
		break;
	case 'u':
		punstate->inject = false;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num > 1)
			argp_usage(state);
		if (state->arg_num == 0)
			punstate->pid = atoi(arg);
		else if (state->arg_num == 1)
			punstate->libname = arg;
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 2)
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}


static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};

} /* namespace inject */

#endif /* CMDARGS_H_ */
