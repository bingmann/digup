/*****************************************************************************
 * Class-like structures to easily switch between message digests.           *
 *                                                                           *
 * Copyright (C) 2009 Timo Bingmann                                          *
 *                                                                           *
 * This program is free software; you can redistribute it and/or modify it   *
 * under the terms of the GNU General Public License as published by the     *
 * Free Software Foundation; either version 3, or (at your option) any       *
 * later version.                                                            *
 *                                                                           *
 * This program is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 * GNU General Public License for more details.                              *
 *                                                                           *
 * You should have received a copy of the GNU General Public License         *
 * along with this program; if not, write to the Free Software Foundation,   *
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.        *
 *****************************************************************************/

#include "digest.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*** Helpers ***/

static struct digest_result*
malloc_result(unsigned int size)
{
    struct digest_result* resbuf = malloc(1 + size);
    resbuf->size = size;
    return resbuf;
}

/*** MD5 ***/

static size_t
__md5_digest_size(void)
{
    return MD5_DIGEST_SIZE;
}

static void
__md5_init(struct digest_ctx *ctx)
{
    md5_init_ctx(&ctx->ctx.md5);
}

static void
__md5_process(struct digest_ctx *ctx,
	      const void *buffer, size_t len)
{
    md5_process_bytes(buffer, len, &ctx->ctx.md5);
}

static struct digest_result*
__md5_finish(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(MD5_DIGEST_SIZE);
    md5_finish_ctx(&ctx->ctx.md5, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__md5_read(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(MD5_DIGEST_SIZE);
    md5_read_ctx(&ctx->ctx.md5, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__md5_process_buffer(const char *buffer, size_t len)
{
    struct digest_result* resbuf = malloc_result(MD5_DIGEST_SIZE);
    md5_buffer(buffer, len, (char*)resbuf + 1);
    return resbuf;
}

void digest_init_md5(struct digest_ctx* ctx)
{
    ctx->digest_size = __md5_digest_size;
    ctx->init = __md5_init;
    ctx->process = __md5_process;
    ctx->finish = __md5_finish;
    ctx->read = __md5_read;
    ctx->process_buffer = __md5_process_buffer;

    ctx->init(ctx);
}

/*** SHA1 ***/

static size_t
__sha1_digest_size(void)
{
    return SHA1_DIGEST_SIZE;
}

static void
__sha1_init(struct digest_ctx *ctx)
{
    sha1_init_ctx(&ctx->ctx.sha1);
}

static void
__sha1_process(struct digest_ctx *ctx,
	      const void *buffer, size_t len)
{
    sha1_process_bytes(buffer, len, &ctx->ctx.sha1);
}

static struct digest_result*
__sha1_finish(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA1_DIGEST_SIZE);
    sha1_finish_ctx(&ctx->ctx.sha1, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha1_read(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA1_DIGEST_SIZE);
    sha1_read_ctx(&ctx->ctx.sha1, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha1_process_buffer(const char *buffer, size_t len)
{
    struct digest_result* resbuf = malloc_result(SHA1_DIGEST_SIZE);
    sha1_buffer(buffer, len, (char*)resbuf + 1);
    return resbuf;
}

void digest_init_sha1(struct digest_ctx* ctx)
{
    ctx->digest_size = __sha1_digest_size;
    ctx->init = __sha1_init;
    ctx->process = __sha1_process;
    ctx->finish = __sha1_finish;
    ctx->read = __sha1_read;
    ctx->process_buffer = __sha1_process_buffer;

    ctx->init(ctx);
}

/*** SHA256 ***/

static size_t
__sha256_digest_size(void)
{
    return SHA256_DIGEST_SIZE;
}

static void
__sha256_init(struct digest_ctx *ctx)
{
    sha256_init_ctx(&ctx->ctx.sha256);
}

static void
__sha256_process(struct digest_ctx *ctx,
	      const void *buffer, size_t len)
{
    sha256_process_bytes(buffer, len, &ctx->ctx.sha256);
}

static struct digest_result*
__sha256_finish(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA256_DIGEST_SIZE);
    sha256_finish_ctx(&ctx->ctx.sha256, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha256_read(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA256_DIGEST_SIZE);
    sha256_read_ctx(&ctx->ctx.sha256, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha256_process_buffer(const char *buffer, size_t len)
{
    struct digest_result* resbuf = malloc_result(SHA256_DIGEST_SIZE);
    sha256_buffer(buffer, len, (char*)resbuf + 1);
    return resbuf;
}

void digest_init_sha256(struct digest_ctx* ctx)
{
    ctx->digest_size = __sha256_digest_size;
    ctx->init = __sha256_init;
    ctx->process = __sha256_process;
    ctx->finish = __sha256_finish;
    ctx->read = __sha256_read;
    ctx->process_buffer = __sha256_process_buffer;

    ctx->init(ctx);
}

/*** SHA512 ***/

static size_t
__sha512_digest_size(void)
{
    return SHA512_DIGEST_SIZE;
}

static void
__sha512_init(struct digest_ctx *ctx)
{
    sha512_init_ctx(&ctx->ctx.sha512);
}

static void
__sha512_process(struct digest_ctx *ctx,
	      const void *buffer, size_t len)
{
    sha512_process_bytes(buffer, len, &ctx->ctx.sha512);
}

static struct digest_result*
__sha512_finish(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA512_DIGEST_SIZE);
    sha512_finish_ctx(&ctx->ctx.sha512, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha512_read(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(SHA512_DIGEST_SIZE);
    sha512_read_ctx(&ctx->ctx.sha512, (char*)resbuf + 1);
    return resbuf;
}

static struct digest_result*
__sha512_process_buffer(const char *buffer, size_t len)
{
    struct digest_result* resbuf = malloc_result(SHA512_DIGEST_SIZE);
    sha512_buffer(buffer, len, (char*)resbuf + 1);
    return resbuf;
}

void digest_init_sha512(struct digest_ctx* ctx)
{
    ctx->digest_size = __sha512_digest_size;
    ctx->init = __sha512_init;
    ctx->process = __sha512_process;
    ctx->finish = __sha512_finish;
    ctx->read = __sha512_read;
    ctx->process_buffer = __sha512_process_buffer;

    ctx->init(ctx);
}

/*** CRC32 ***/

static size_t
__crc32_digest_size(void)
{
    return CRC32_DIGEST_SIZE;
}

static void
__crc32_init(struct digest_ctx *ctx)
{
    ctx->ctx.crc32 = 0;
}

static void
__crc32_process(struct digest_ctx *ctx,
	      const void *buffer, size_t len)
{
    ctx->ctx.crc32 = crc32(ctx->ctx.crc32, buffer, len);
}

static struct digest_result*
__crc32_finish(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(CRC32_DIGEST_SIZE);
    *(uint32_t*)((char*)resbuf+1) = ctx->ctx.crc32;
    return resbuf;
}

static struct digest_result*
__crc32_read(struct digest_ctx *ctx)
{
    struct digest_result* resbuf = malloc_result(CRC32_DIGEST_SIZE);
    *(uint32_t*)((char*)resbuf+1) = ctx->ctx.crc32;
    return resbuf;
}

static struct digest_result*
__crc32_process_buffer(const char *buffer, size_t len)
{
    struct digest_result* resbuf = malloc_result(CRC32_DIGEST_SIZE);
    uint32_t crc = crc32(0, (const unsigned char*)buffer, len);
    *(uint32_t*)((char*)resbuf+1) = crc;
    return resbuf;
}

void digest_init_crc32(struct digest_ctx* ctx)
{
    ctx->digest_size = __crc32_digest_size;
    ctx->init = __crc32_init;
    ctx->process = __crc32_process;
    ctx->finish = __crc32_finish;
    ctx->read = __crc32_read;
    ctx->process_buffer = __crc32_process_buffer;

    ctx->init(ctx);
}

/*** Utilities ***/

struct digest_result*
digest_dup(const struct digest_result* res)
{
    struct digest_result* newres = malloc_result(res->size);
    memcpy((char*)newres+1, (char*)res+1, res->size);
    return newres;
}

char* digest_bin2hex(const struct digest_result* res, char* out)
{
    unsigned int i;
    unsigned char *cbin = (unsigned char*)res+1;

    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
				  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    for (i = 0; i < res->size; ++i)
    {
	out[2*i+0] = hex[ (cbin[i] >> 4) & 0x0F ];
	out[2*i+1] = hex[ (cbin[i] >> 0) & 0x0F ];
    }

    out[2*res->size] = 0;

    return out;
}

char* digest_bin2hex_dup(const struct digest_result* res)
{
    char* out = malloc(2 * res->size + 1);
    return digest_bin2hex(res, out);
}

struct digest_result* digest_hex2bin(const char* str, int len)
{
    static const char hexval[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    struct digest_result* resbuf;
    int i;

    if (len < 0) len = strlen(str);

    if (len % 2 != 0)
	return NULL;

    resbuf = malloc_result(len / 2);

    for (i = 0; i < len; i += 2)
    {
	if (hexval[(unsigned char)str[i]] < 0)
	{
	    free(resbuf);
	    return NULL;
	}
	if (hexval[(unsigned char)str[i+1]] < 0)
	{
	    free(resbuf);
	    return NULL;
	}

	((unsigned char*)resbuf+1)[i/2] =
	    hexval[(unsigned char)str[i]] * 16 +
	    hexval[(unsigned char)str[i+1]];
    }
    
    return resbuf;

}

int digest_equal(const struct digest_result* a, const struct digest_result* b)
{
    if (a->size != b->size) return 0;

    return memcmp((unsigned char*)a+1, (unsigned char*)b+1, a->size) == 0;
}

int digest_cmp(const struct digest_result* a, const struct digest_result* b)
{
    if (a->size != b->size) return a->size - b->size;

    return memcmp((unsigned char*)a+1, (unsigned char*)b+1, a->size);
}

/*****************************************************************************/
