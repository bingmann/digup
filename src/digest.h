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

#ifndef _DIGEST_H
#define _DIGEST_H 1

#include <inttypes.h>
#include <stddef.h>

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "crc32.h"

/**
 * variable sized structure to hold binary digest results of different
 * algorithms.
 */
typedef struct digest_result
{
    unsigned char	size;
    /* variable length of bytes follows:
    unsigned char	data[];
    */
} digest_result;

/**
 * class-like structure with function pointers and integrated digest
 * algorithm context.
 */
typedef struct digest_ctx
{
    union
    {
	struct md5_ctx		md5;
	struct sha1_ctx		sha1;
	struct sha256_ctx	sha256;
	struct sha512_ctx	sha512;
	uint32_t		crc32;
    } ctx;

    size_t (*digest_size)(void);

    void (*init)(struct digest_ctx *ctx);

    void (*process)(struct digest_ctx *ctx,
		    const void *buffer, size_t len);

    struct digest_result* (*finish)(struct digest_ctx *ctx);

    struct digest_result* (*read)(struct digest_ctx *ctx);

    struct digest_result* (*process_buffer)(const char *buffer, size_t len);
} digest_ctx;

/* initialize the structure with function pointers for specific digest
 * type */
 
extern void digest_init_md5(struct digest_ctx* ctx);

extern void digest_init_sha1(struct digest_ctx* ctx);

extern void digest_init_sha256(struct digest_ctx* ctx);

extern void digest_init_sha512(struct digest_ctx* ctx);

extern void digest_init_crc32(struct digest_ctx* ctx);

/* miscellaneous utilities */

extern struct digest_result* digest_dup(const struct digest_result* res);

extern char* digest_bin2hex(const struct digest_result*, char* out);

extern char* digest_bin2hex_dup(const struct digest_result* res);

extern struct digest_result* digest_hex2bin(const char* str, int len);

extern int digest_equal(const struct digest_result* a, const struct digest_result* b);

extern int digest_cmp(const struct digest_result* a, const struct digest_result* b);

#endif /* _DIGEST_H */

/*****************************************************************************/
