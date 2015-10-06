#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ulogd/conffile.h>

enum {
	CFTEST_CONFIG_ZEILE,
	CFTEST_CONFIG_SPALTE,
	CFTEST_CONFIG_MAX,
};

int bla(const char *args)
{
	printf("bla called: %s\n", args);
	return 0;
}

static struct config_keyset test_kset = {
	.num_ces = CFTEST_CONFIG_MAX,
	.ces = {
		[CFTEST_CONFIG_ZEILE] = {
			.key	= "zeile",
			.type	= CONFIG_TYPE_CALLBACK,
			.u.parser = bla,
		},
		[CFTEST_CONFIG_SPALTE] = {
			.key	= "spalte",
			.type	= CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
	},
};

int main(int argc, char *argv[])
{
	if (config_register_file(argv[1])) {
		fprintf(stderr, "failed to config_register_file\n");
		exit(EXIT_FAILURE);
	}

	if (config_parse_file("global", &test_kset)) {
		fprintf(stderr, "failed to config_parse_file\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
