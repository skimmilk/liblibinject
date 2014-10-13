#include <stdio.h>
#include <unistd.h>

void libmain()
{
	while (1)
	{
		puts("Hello world");
		sleep(3);
	}
}

void hello()
{
	puts("moshi mosh");
}
