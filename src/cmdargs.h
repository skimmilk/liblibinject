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

namespace cmdargs
{
	struct inject_settings
	{
		int verbose;
		pid_t pid;
	};

	struct inject_settings* punstate;
	static char args_doc[] = "PID";
	static char doc[] =
	  "libinject - inject libraries into processes";

	static struct argp_option options[] = {
			{"verbose",		'v', 0, 0, "Produce verbose output", 0},

			// The things I do to silence compiler warnings...
			{0,0,0,0,0,0}
	};

	error_t parse_opt (int key, char* arg, struct argp_state* state)
	{
		inject_settings* punstate = (inject_settings*)state->input;
		switch (key)
		{
		case 'v':
			punstate->verbose = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num > 1)
				argp_usage(state);
			punstate->pid = atoi(arg);
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 1)
				argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
		return 0;
	}


	static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};

};

} /* namespace inject */

#endif /* CMDARGS_H_ */
