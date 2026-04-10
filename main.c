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
#define TXID_LEN 32
#define P2PKH_LEN 25

const int ofd = 1;
char *cmd = "bic";

#define ELOG(log, ...) fprintf(stderr, "%s: " log, cmd __VA_OPT__(,) __VA_ARGS__)

static void *xmalloc(size_t size)
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

struct input {
	uint8_t txid[TXID_LEN];
	uint32_t vout;
	uint64_t script_sig_size;
	uint8_t *script_sig;
	uint32_t sequence;
};

struct output {
	uint64_t amount;
	uint64_t script_pubkey_len;
	uint8_t script_pubkey[P2PKH_LEN];
};

struct tx {
	uint32_t version;
	uint64_t input_count;
	struct input *inputs;
	uint64_t output_count;
	struct output *outputs;
	uint32_t locktime;
};

struct vector {
	uint64_t len;
	uint8_t data[];
};

static inline int hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Decode a hex string into bytes.
 *
 * hex:     null-terminated hex string (must have even length)
 * out:     destination buffer
 * out_cap: capacity of out in bytes
 *
 * Returns the number of bytes written on success, -1 on error
 */
static ssize_t decode_hex(const char *hex, uint8_t *out, size_t out_cap)
{
	size_t hlen = strlen(hex);
	if (hlen % 2 != 0)
		return -1;

	size_t blen = hlen / 2;
	if (blen > out_cap)
		return -1;

	for (size_t i = 0; i < blen; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return (ssize_t)blen;
}

static struct vector *decode_hex_vector(const char *hex)
{
	size_t hlen = strlen(hex);
	if (hlen % 2 != 0)
		return NULL;

	size_t blen = hlen / 2;

	struct vector *v = xmalloc(sizeof(*v) + blen);

	if (decode_hex(hex, v->data, blen) < 0) {
		free(v);
		return NULL;
	}
	v->len = blen;
	return v;
}

static int parse_txid(const char *hex, uint8_t out[TXID_LEN])
{
	uint8_t tmp[TXID_LEN];

	if (decode_hex(hex, tmp, TXID_LEN) != TXID_LEN)
		return 1;

	for (size_t i = 0; i < TXID_LEN; i++)
		out[i] = tmp[TXID_LEN - 1 - i];

	return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
	if (s == NULL || *s == '\0' || s[0] == '-')
		return -1;

	errno = 0;
	char *end;
	unsigned long long v = strtoull(s, &end, 10);

	if (*end != '\0')
		return 1;
	if (errno == ERANGE)
		return 1;

	*out = (uint64_t)v;
	return 0;
}

static int parse_u32(const char *s, uint32_t *out)
{
	uint64_t v;
	if (parse_u64(s, &v) < 0 || v > UINT32_MAX)
		return 1;
	*out = (uint32_t)v;
	return 0;
}

int cmd_gentx(secp256k1_context *ctx, int argc, char *argv[])
{
	int input_cnt = 0;
	int output_cnt = 0;
	int opt;

	optind = 0;
	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			input_cnt++;
			break;
		case 'o':
			output_cnt++;
			break;
		case '?':
		default:
			return 1;
		}
	}

	if (input_cnt <= 0 || output_cnt <= 0) {
		ELOG("There should be at least one -o and -i each.\n");
		return 1;
	}

	struct input inputs[input_cnt] = {};
	struct vector *input_script_pubkeys[input_cnt] = {};
	struct output outputs[output_cnt] = {};

	int ip = 0;
	int op = 0;
	int ret;

	optind = 0;
	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			char *txid_hex;
			char *vout;
			char *script_pubkey_hex;

			if ((txid_hex = strtok(optarg, ":")) == NULL ||
			    (vout = strtok(NULL, ":")) == NULL ||
			    (script_pubkey_hex = strtok(NULL, ":")) == NULL ||
			    parse_txid(txid_hex, inputs[ip].txid) != 0 ||
			    parse_u32(vout, &inputs[ip].vout) != 0 ||
			    (input_script_pubkeys[ip] = decode_hex_vector(script_pubkey_hex)) == NULL) {
				ELOG("Invalid format: %s\n", optarg);
				ret = 1;
				goto cleanup;
			}

			ip++;
			break;
		case 'o':
			char *amount;
			char *pubkey_hash_hex;
			uint8_t pkh[20];

			if ((amount = strtok(optarg, ":")) == NULL ||
			    (pubkey_hash_hex = strtok(NULL, ":")) == NULL ||
			    parse_u64(amount, &outputs[op].amount) != 0 ||
			    decode_hex(pubkey_hash_hex, pkh, sizeof(pkh)) != sizeof(pkh)) {
				ELOG("Invalid format: %s\n", optarg);
				ret = 1;
				goto cleanup;
			}

			/* build Legacy P2PKH scriptPubKey: 76 a9 14 <20-byte pkh> 88 ac */
			outputs[op].script_pubkey[0] = 0x76;  /* OP_DUP */
			outputs[op].script_pubkey[1] = 0xa9;  /* OP_HASH160 */
			outputs[op].script_pubkey[2] = 0x14;  /* push 20 */
			memcpy(&outputs[op].script_pubkey[3], pkh, 20);
			outputs[op].script_pubkey[23] = 0x88; /* OP_EQUALVERIFY */
			outputs[op].script_pubkey[24] = 0xac; /* OP_CHECKSIG */
			outputs[op].script_pubkey_len = P2PKH_LEN;

			op++;
			break;
		}
	}

	assert(ip == input_cnt && op == output_cnt);
	assert(0 && "unimplemented");

	ret = 0;

cleanup:
	for (int i = 0; i < ip; i++)
		free(input_script_pubkeys[i]);

	return ret;
}

static int run(int argc, char *argv[])
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
