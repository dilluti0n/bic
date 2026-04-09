#define _DEFAULT_SOURCE
#include <stdio.h>
#include <secp256k1.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
#include <errno.h>
#include <assert.h>

const int ofd = 1;
char *cmd = "bic";

#define ELOG(log, ...) fprintf(stderr, "%s: " log, cmd __VA_OPT__(,) __VA_ARGS__)

int cmd_genkey(secp256k1_context *ctx)
{
	unsigned char key[32];
	int ret = 0;

	do {
		if (getrandom(key, sizeof(key), 0) != 32) {
			ret = -errno;
			perror("getrandom");
			goto cleanup;
		}
	} while (!secp256k1_ec_seckey_verify(ctx, key));

	if (write(ofd, key, sizeof(key)) != sizeof(key)) {
		ret = -errno;
		perror("write");
		goto cleanup;
	}

	ret = 0;

cleanup:
	explicit_bzero(key, sizeof(key));
	return ret;
}

int cmd_gentx(secp256k1_context *ctx, int argc, char *argv[])
{
	assert(0 && "unimplemented");
}

int run(int argc, char *argv[])
{
	if (argc < 1) {
		ELOG("give me subcommand\n");
		return 1;
	}

	int ret;
	secp256k1_context *ctx;

	if ((ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)) == NULL) {
		ELOG("failed to create secp256k1_context\n");
		return 2;
	}

	if (!strcmp(argv[0], "genkey")) {
		ret = cmd_genkey(ctx);
	} else if (!strcmp(argv[0], "gentx")) {
		ret = cmd_gentx(ctx, argc - 1, argv + 1);
	} else {
		ELOG("%s: invalid subcommand\n", argv[0]);
		ret = 1;
	}

	secp256k1_context_destroy(ctx);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	cmd = argv[0];
	ret = run(argc - 1, argv + 1);

	return ret;
}
