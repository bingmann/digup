/*****************************************************************************
 * Compute the CRC-32 of a data stream.                                      *
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

#ifndef _CRC32_H
#define _CRC32_H 1

#include <inttypes.h>

enum { CRC32_DIGEST_SIZE = 4 };

/**
 * Calculate the updated CRC32 value after shifting in a buffer of len
 * size. Start with crc = 0.
 */
extern uint32_t crc32(uint32_t crc, const unsigned char* buf, unsigned int len);

#endif /* _CRC32_H */

/*****************************************************************************/
