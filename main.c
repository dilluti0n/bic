#include <stdio.h>
#include <secp256k1.h>
#include <assert.h>

int main()
{
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	assert(ctx);
	printf("hello, world\n");
	secp256k1_context_destroy(ctx);

	return 0;
}
