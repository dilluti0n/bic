#define _DEFAULT_SOURCE

#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <errno.h>
#include <assert.h>

#define SECKEY_LEN 32

const int ofd = 1;
char *cmd = "bic";

#define ELOG(log, ...) fprintf(stderr, "%s: " log, cmd __VA_OPT__(,) __VA_ARGS__)

void *xmalloc(size_t size)
{
	void *p = malloc(size);

	if (p == NULL) {
		int ret = -errno;
		perror("malloc");
		exit(ret);
	}

	return p;
}

int cmd_genkey(secp256k1_context *ctx)
{
	unsigned char key[SECKEY_LEN];
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

int read_key(const secp256k1_context *ctx, int fd, unsigned char key[SECKEY_LEN])
{
	ssize_t nread;
	int ret;

	if ((nread = read(fd, key, SECKEY_LEN)) != SECKEY_LEN) {
		if (errno == EINTR) {
			read_key(ctx, fd, key); /* TODO: use nread */
		} else {
			ret = -errno;
			perror("read");
			return ret;
		}
	}

	if (!secp256k1_ec_seckey_verify(ctx, key)) {
		ELOG("not a valid secret key");
		return 1;
	}

	return 0;
}

int fd_sign_ecdsa(const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig,
		  int fd, const unsigned char *msghash32)
{
	int ret;
	unsigned char key[SECKEY_LEN];

	if ((ret = read_key(ctx, fd, key)) != 0)
		goto cleanup;

	secp256k1_ecdsa_sign(ctx, sig, msghash32, key, NULL, NULL);
	secp256k1_ecdsa_signature_normalize(ctx, sig, sig);

cleanup:
	explicit_bzero(key, SECKEY_LEN);
	return ret;
}

struct input {
	uint8_t txid[32];
	uint32_t vout;
	uint64_t script_sig_size;
	uint8_t *script_sig;
	uint32_t sequence;
};

struct output {
	uint64_t amount;
	uint64_t script_pubkey_len;
	uint8_t *script_pubkey;
};

struct tx {
	uint32_t version;
	uint64_t input_count;
	struct input *inputs;
	uint64_t output_count;
	struct output *outputs;
	uint32_t locktime;
};

int cmd_gentx(secp256k1_context *ctx, int argc, char *argv[])
{
	int input_cnt = 0;
	int output_cnt = 0;
	struct input *inputs = NULL;
	struct output *outputs = NULL;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp(&argv[i][1], "i"))
				input_cnt++;
			else if (!strcmp(&argv[i][1], "o"))
				output_cnt++;
		}
	}

	if (input_cnt <= 0 || output_cnt <= 0) {
		ELOG("There should be at least one -o and -i each.\n");
		return 1;
	}

	printf("%d %d\n", input_cnt, output_cnt);

	inputs = xmalloc(input_cnt);
	outputs = xmalloc(output_cnt);



	return 0;
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
		ret = cmd_gentx(ctx, argc, argv);
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
