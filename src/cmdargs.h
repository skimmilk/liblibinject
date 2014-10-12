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
};

struct inject_settings* punstate;
static char args_doc[] = "PID LIBRARY";
static char doc[] =
		"libinject - inject libraries into processes";

static struct argp_option options[] = {
		// The things I do to silence compiler warnings...
		{0,0,0,0,0,0}
};

error_t parse_opt (int key, char* arg, struct argp_state* state)
{
	inject_settings* punstate = (inject_settings*)state->input;
	switch (key)
	{
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
