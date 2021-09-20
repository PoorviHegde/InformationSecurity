#include <stdio.h>
#include <string.h>

void vulnerable(char *arg)
{
	char buf[100];
	strcpy(buf, arg);
}

void call_vul(char *arg)
{
	char temp[50];
	vulnerable(arg);
}

int _main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Error: need a command-line argument\n");
		return 1;
	}
	call_vul(argv[1]);
	return 0;
}
