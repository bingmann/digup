/*****************************************************************************
 * Red-Black Balanced Binary Tree Implementation in Plain C                  *
 *                                                                           *
 * Copyright (C) 2001,2005 Emin Martinian                                    *
 *                                                                           *
 * Redistribution and use in source and binary forms, with or without        *
 * modification, are permitted provided that neither the name of Emin        *
 * Martinian nor the names of any contributors are be used to endorse        *
 * or promote products derived from this software without specific           *
 * prior written permission.                                                 *
 *                                                                           *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,     *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT          *
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,     *
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY     *
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT       *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE     *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.      *
 *                                                                           *
 * Modifications 2009 by Timo Bingmann for duplicate key trees, opaque       *
 *   pointers, invariant testing and general code cleanup.                   *
 *                                                                           *
 *****************************************************************************/

/* $Id$ */

#ifndef _RBTREE_H
#define _RBTREE_H 1

/**
 * Node structure of the red-black binary tree.
 */
struct rb_node
{
    void *key, *value;
    int red; /* if red==0 then the node is black */
    struct rb_node *left, *right, *parent;
};

/** opaque structure declaration */
struct rb_tree;

/**
 * Create a new red-black tree object. Function pointers to all
 * necessary callbacks must be provided. Returns a new tree object.
 *
 * - compare_keys(a,b) should return >0 if *a > *b, <0 if *a < *b, and
 *   0 otherwise.
 * - destroy_xyz(a) takes a pointer to either key or value object and
 *   must free it accordingly.
 * - print_xyz(a) is used by rb_print() to dump the tree.
 */
struct rb_tree *rb_create(int (*compare_keys_func)(const void*, const void*),
			  void (*destroy_key_func)(void*),
			  void (*destroy_value_func)(void*),
			  void (*print_key_func)(const void*),
			  void (*print_value_func)(const void*));

/**
 * Returns true if the tree is empty.
 */
int rb_isempty(struct rb_tree *tree);

/**
 * Returns the number of elements in the tree.
 */
unsigned int rb_size(struct rb_tree *tree);

/**
 * Returns first node or nil in the tree. Similar to STL's begin().
 */
struct rb_node *rb_begin(struct rb_tree *tree);

/**
 * Returns the nil node in the tree. Similar to STL's end().
 */
struct rb_node *rb_end(struct rb_tree *tree);

/**
 * Insert function to place a new key, value pair into the tree,
 * taking ownership of key and value object.. First inserts a new node
 * and then applies iterative rotations to rebalance the tree.
 */
struct rb_node *rb_insert(struct rb_tree *tree, void *key, void *value);

/**
 * Return the successor node of x in the tree or tree->nil if there is
 * none.
 */
struct rb_node *rb_successor(struct rb_tree *tree, struct rb_node *x);

/**
 * Return the predecessor node of x in the tree or tree->nil if there
 * is none.
 */
struct rb_node *rb_predecessor(struct rb_tree *tree, struct rb_node *x);

/**
 * Destory the tree and destroy all associated key and value objects
 * via the appropriate callbacks.
 */
void rb_destroy(struct rb_tree *tree);

/**
 * Print the whole tree using the print_xyz() callbacks.
 */
void rb_print(struct rb_tree *tree);

/**
 * Find the first node matching the key in the tree. If multiple equal
 * keys are contained in the tree, the first one in-order is returned.
 * Returns NULL if the key was not found.
 */
struct rb_node *rb_find(struct rb_tree *tree, const void *key);

/**
 * Delete a node from the tree and rebalance it.
 */
void rb_delete(struct rb_tree *tree, struct rb_node *z);

/**
 * Verify red-black tree invariants: the root is black, both children
 * of a red node are black and every path from root to leaf has the
 * same number of black nodes.
 */
int rb_verify(struct rb_tree *tree);

#endif /* _RBTREE_H */

/*****************************************************************************/
