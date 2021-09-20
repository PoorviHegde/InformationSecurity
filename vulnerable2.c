#include <stdio.h>
#include <string.h>

void vulnerable(char *arg)
{
	int *p;
	int a;
	char buf[2048];

	fprintf(stderr, "%s\n", buf);

	strncpy(buf, arg, sizeof(buf) + 8);

	*p = a;
}

void call_vul(char *arg)
{
	char temp[75];
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
