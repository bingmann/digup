/*****************************************************************************
 * Declaration of functions and data types used for MD5 sum computing.       *
 *                                                                           *
 * Copyright (C) 1995-1997,1999-2001,2004-2006,2008                          *
 *     by Free Software Foundation, Inc.                                     *
 *                                                                           *
 * This file was taken from coreutils-7.4 and adapted for digup.             *
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

#ifndef _MD5_H
#define _MD5_H 1

#include <stdlib.h>
#include <inttypes.h>

enum { MD5_DIGEST_SIZE = 16 };

/* Structure to save state of computation between the single steps. */
struct md5_ctx
{
    uint32_t A, B, C, D;

    uint32_t total[2];
    uint32_t buflen;
    uint32_t buffer[32];
};

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
extern void md5_init_ctx (struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
extern void md5_process_block (const void *buffer, size_t len,
			       struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
extern void md5_process_bytes (const void *buffer, size_t len,
			       struct md5_ctx *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */
extern void *md5_finish_ctx (struct md5_ctx *ctx, void *resbuf);

/* Put result from CTX in first 16 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.  */
extern void *md5_read_ctx (const struct md5_ctx *ctx, void *resbuf);

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
extern void *md5_buffer (const char *buffer, size_t len, void *resblock);

#endif /* _MD5_H */

/*****************************************************************************/
