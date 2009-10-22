/*****************************************************************************
 * test_digup - Tests within Digest File Update Program                      *
 *                                                                           *
 * Test cases: TODO                                                          *
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

/* evil but simple way to include the main program to run tests on it */
#define main __mainx
#include "digup.c"
#undef main

void test_filename_escaping(void)
{
    char* str1 = strdup("test-file-name");
    char* str2 = strdup("test-file\\nname\\\\");
    char* str3 = strdup("illegal escaping \\a test");
    char* str4 = strdup("illegal escaping at end \\");

    /* unescape examples */

    assert( unescape_filename(str1) == TRUE );
    assert( strcmp(str1, "test-file-name") == 0 );

    assert( unescape_filename(str2) == TRUE );
    assert( strcmp(str2, "test-file\nname\\") == 0 );

    assert( unescape_filename(str3) == FALSE );

    assert( unescape_filename(str4) == FALSE );

    /* escape examples again */

    assert( needescape_filename(&str1) == FALSE );

    assert( needescape_filename(&str2) == TRUE );
    assert( strcmp(str2, "test-file\\nname\\\\") == 0 );

    assert( needescape_filename(&str3) == TRUE );
    assert( strcmp(str3, "illegal escaping \\\\a test") == 0 );

    assert( needescape_filename(&str4) == TRUE );
    assert( strcmp(str4, "illegal escaping at end \\\\") == 0 );

    free(str1);
    free(str2);
    free(str3);
    free(str4);
}

int main(void)
{
    test_filename_escaping();

    return 0;
}

/*****************************************************************************/
