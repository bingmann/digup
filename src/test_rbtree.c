/*****************************************************************************
 * Tests for the Red-Black Balanced Binary Tree Implementation in Plain C    *
 *                                                                           *
 * Test cases: strings, integer keys and multiple integer keys.              *
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

#include "rbtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void string_free(void *a)
{
    free((char*)a);
}

int string_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

void string_print(const void *a)
{
    printf("%s", (char*)a);
}

void test_strings(void)
{
    int i;
    char str[512];
    struct rb_node *node;

    struct rb_tree *tree = rb_create(string_cmp,
				     string_free, string_free,
				     string_print, string_print);

    assert( rb_isempty(tree) == 1 );

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	snprintf(str, sizeof(str), "test%d", rand() % 1000000);

	rb_insert(tree, strdup(str), strdup("value"));
    }

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	snprintf(str, sizeof(str), "test%d", rand() % 1000000);

	node = rb_find(tree, str);
	assert(node);
    }    

    {
	node = rb_find(tree, "test46554A");
	assert(node == NULL);
    }

    assert( rb_isempty(tree) == 0 );
    assert( rb_size(tree) == 10000 );

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	snprintf(str, sizeof(str), "test%d", rand() % 1000000);

	node = rb_find(tree, str);
	assert(node);

	rb_delete(tree, node);
    }

    assert( rb_isempty(tree) == 1 );
    assert( rb_size(tree) == 0 );

    rb_destroy(tree);
}

void integer_free(void *a)
{
    (void)a;
}

int integer_cmp(const void *a, const void *b)
{
    if ((intptr_t)a < (intptr_t)b) return -1;
    if ((intptr_t)a > (intptr_t)b) return +1;
    return 0;
}

void integer_print(const void *a)
{
    printf("%d", (int)(intptr_t)a);
}

void test_integers(void)
{
    int i;
    intptr_t val;
    struct rb_node *node;

    struct rb_tree *tree = rb_create(integer_cmp,
				     integer_free, integer_free,
				     integer_print, integer_print);

    assert( rb_isempty(tree) == 1 );

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	val = rand() % 1000000;

	rb_insert(tree, (void*)val, (void*)val);
    }

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	val = rand() % 1000000;

	node = rb_find(tree, (void*)val);
	assert(node);
    }    

    {
	node = rb_find(tree, (void*)234324);
	assert(node == NULL);
    }

    assert( rb_isempty(tree) == 0 );
    assert( rb_size(tree) == 10000 );

    srand(4545);
    for (i = 0; i < 10000; i++)
    {
	val = rand() % 1000000;

	node = rb_find(tree, (void*)val);
	assert(node);

	rb_delete(tree, node);
    }

    assert( rb_isempty(tree) == 1 );
    assert( rb_size(tree) == 0 );

    rb_destroy(tree);
}

void test_integers_multi(int factor)
{
    int i;
    intptr_t val;
    unsigned int count;
    struct rb_node *node;

    struct rb_tree *tree = rb_create(integer_cmp,
				     integer_free, integer_free,
				     integer_print, integer_print);

    assert( rb_isempty(tree) == 1 );

    for (i = 0; i < 100 * factor; i++)
    {
	val = i % factor;
	rb_insert(tree, (void*)val, (void*)val);
    }

    assert( rb_isempty(tree) == 0 );
    assert( rb_size(tree) == (unsigned int)100 * factor);

    for (i = 0; i < factor; i++)
    {
	val = i;
	node = rb_find(tree, (void*)val);
	assert(node);

	count = 0;
	while (node != rb_end(tree) && (intptr_t)node->key == i)
	{
	    ++count;
	    node = rb_successor(tree, node);
	}

	assert(count == 100);
    }

    {
	count = 0;

	for(node = rb_begin(tree); node != rb_end(tree);
	    node = rb_successor(tree, node))
	{
	    assert((intptr_t)node->key == (count++ / 100));
	}
    }

    for (i = 0; i < 100 * factor; i++)
    {
	val = i % factor;

	node = rb_find(tree, (void*)val);
	assert(node);

	rb_delete(tree, node);
    }

    assert( rb_isempty(tree) == 1 );

    rb_destroy(tree);
}

int main(void)
{
    int i;

    test_strings();

    test_integers();

    for (i = 10; i < 100; ++i)
	test_integers_multi(i);

    return 0;
}

/*****************************************************************************/
