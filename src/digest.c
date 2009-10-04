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

/* $Id$ */

#include "digest.h"

#include <ctype.h>

/*** MD5 ***/

static size_t
__md5_digest_size()
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

static void*
__md5_finish(struct digest_ctx *ctx, void *resbuf)
{
    return md5_finish_ctx(&ctx->ctx.md5, resbuf);
}

static void*
__md5_read(struct digest_ctx *ctx, void *resbuf)
{
    return md5_read_ctx(&ctx->ctx.md5, resbuf);
}

static void*
__md5_process_buffer(const char *buffer, size_t len, void *resblock)
{
    return md5_buffer(buffer, len, resblock);
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
__sha1_digest_size()
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

static void*
__sha1_finish(struct digest_ctx *ctx, void *resbuf)
{
    return sha1_finish_ctx(&ctx->ctx.sha1, resbuf);
}

static void*
__sha1_read(struct digest_ctx *ctx, void *resbuf)
{
    return sha1_read_ctx(&ctx->ctx.sha1, resbuf);
}

static void*
__sha1_process_buffer(const char *buffer, size_t len, void *resblock)
{
    return sha1_buffer(buffer, len, resblock);
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
__sha256_digest_size()
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

static void*
__sha256_finish(struct digest_ctx *ctx, void *resbuf)
{
    return sha256_finish_ctx(&ctx->ctx.sha256, resbuf);
}

static void*
__sha256_read(struct digest_ctx *ctx, void *resbuf)
{
    return sha256_read_ctx(&ctx->ctx.sha256, resbuf);
}

static void*
__sha256_process_buffer(const char *buffer, size_t len, void *resblock)
{
    return sha256_buffer(buffer, len, resblock);
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
__sha512_digest_size()
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

static void*
__sha512_finish(struct digest_ctx *ctx, void *resbuf)
{
    return sha512_finish_ctx(&ctx->ctx.sha512, resbuf);
}

static void*
__sha512_read(struct digest_ctx *ctx, void *resbuf)
{
    return sha512_read_ctx(&ctx->ctx.sha512, resbuf);
}

static void*
__sha512_process_buffer(const char *buffer, size_t len, void *resblock)
{
    return sha512_buffer(buffer, len, resblock);
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

/*** Utilities ***/

void digest_bin2hex(const void* bin, size_t len, char* out)
{
    unsigned int i;
    unsigned char *cbin = (unsigned char*)bin;

    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
				  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    for (i = 0; i < len; ++i)
    {
	out[2*i+0] = hex[ (cbin[i] >> 4) & 0x0F ];
	out[2*i+1] = hex[ (cbin[i] >> 0) & 0x0F ];
    }

    out[2*len] = 0;
}

char* digest_bin2hex_dup(const void* bin, size_t len)
{
    char* out = malloc(2 * len + 1);

    digest_bin2hex(bin, len, out);

    return out;
}

int digest_equal(const char* a, const char* b)
{
    size_t i;

    for (i = 0; a[i] && b[i]; ++i)
    {
	if (tolower(a[i]) != tolower(b[i])) return 0;
    }

    return (a[i] == 0) && (b[i] == 0);
}

/*****************************************************************************/
