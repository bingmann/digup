/*****************************************************************************
 * Message Digest Functions Tests                                            *
 *                                                                           *
 * Test cases: two sets of precalculated message digest results.             *
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

#include <assert.h>
#include <stdio.h>
#include <string.h>

void check(const void* str, unsigned int slen, struct digest_ctx* digctx,
	   const char* refhex)
{
    struct digest_result *digres, *digref;

    digctx->init(digctx);
    digctx->process(digctx, str, slen);
    digres = digctx->finish(digctx);

    digref = digest_hex2bin(refhex, -1);
    
    if ( !digest_equal(digres, digref) )
    {
	fprintf(stderr, "Digest result mismatches: %s != %s\n",
		digest_bin2hex_dup(digres),
		digest_bin2hex_dup(digref));
    }
    assert( digest_equal(digres, digref) );
    free(digres);

    /* redo test with process_buffer() function */
    digres = digctx->process_buffer(str, slen);
    assert( digest_equal(digres, digref) );

    free(digres);
    free(digref);
}

int main(void)
{
    struct digest_ctx digest_md5;
    struct digest_ctx digest_sha1;
    struct digest_ctx digest_sha256;
    struct digest_ctx digest_sha512;
    struct digest_ctx digest_crc32;

    digest_init_md5(&digest_md5);
    digest_init_sha1(&digest_sha1);
    digest_init_sha256(&digest_sha256);
    digest_init_sha512(&digest_sha512);
    digest_init_crc32(&digest_crc32);

    {
	const char *str1 = "test string";

	check(str1, strlen(str1), &digest_md5,
	      "6f8db599de986fab7a21625b7916589c");

	check(str1, strlen(str1), &digest_sha1,
	      "661295c9cbf9d6b2f6428414504a8deed3020641");

	check(str1, strlen(str1), &digest_sha256,
	      "d5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b");

	check(str1, strlen(str1), &digest_sha512,
	      "10e6d647af44624442f388c2c14a787ff8b17e6165b83d767ec047768d8cbcb7"
	      "1a1a3226e7cc7816bc79c0427d94a9da688c41a3992c7bf5e4d7cc3e0be5dbac");

	check(str1, strlen(str1), &digest_crc32,
	      "45154713");
    }

    {
	size_t i;
	unsigned char str2[65536];

	for (i = 0; i < sizeof(str2); ++i)
	{
	    str2[i] = i & 0xFF;
	}

	check(str2, sizeof(str2), &digest_md5,
	      "8f1445bafe2c2095044af7789462f475");

	check(str2, sizeof(str2), &digest_sha1,
	      "f04977267a391b2c8f7ad8e070f149bc19b0fc25");

	check(str2, sizeof(str2), &digest_sha256,
	      "7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2");

	check(str2, sizeof(str2), &digest_sha512,
	      "76a59ba2dd234dfb4136e2e33a7e3b344d82f4885a17e3b297eab9a5ded81043"
	      "292217b8126b1cfba29170dce2780259dc68ab4f382efe91aa4bb404912741f4");

	check(str2, sizeof(str2), &digest_crc32,
	      "a1e61db1");
    }

    return 0;
}

/*****************************************************************************/
