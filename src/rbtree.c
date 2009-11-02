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

#include "rbtree.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

/**
 * Tree object struct holding top-level information and function
 * pointers.
 *
 * - compare_keys(a,b) should return >0 if *a > *b, <0 if *a < *b, and
 *   0 otherwise.
 * - destroy_xyz(a) takes a pointer to either key or value object and
 *   must free it accordingly.
 * - print_xyz(a) is used by rb_print() to dump the tree.
 */
struct rb_tree
{
    int (*compare_keys)(const void *a, const void *b); 
    void (*destroy_key)(void *a);
    void (*destroy_value)(void *a);
    void (*print_key)(const void *a);
    void (*print_value)(const void *a);
    struct rb_node *root, *nil;
    unsigned int size;
};

/**
 * Create a new red-black tree object. Function pointers to all
 * necessary callbacks must be provided. Returns a new tree object.
 */
struct rb_tree *rb_create(int (*compare_keys_func)(const void*, const void*),
			  void (*destroy_key_func)(void*),
			  void (*destroy_value_func)(void*),
			  void (*print_key_func)(const void*),
			  void (*print_value_func)(const void*))
{
    struct rb_tree *tree;
    struct rb_node *temp;

    tree = (struct rb_tree*)malloc(sizeof(struct rb_tree));
    if (tree == NULL) return NULL;

    tree->compare_keys =  compare_keys_func;
    tree->destroy_key = destroy_key_func;
    tree->destroy_value = destroy_value_func;
    tree->print_key = print_key_func;
    tree->print_value = print_value_func;
    tree->size = 0;

    /* initialize nil and root nodes */
    temp = tree->nil = (struct rb_node*)malloc(sizeof(struct rb_node));
    temp->parent = temp->left = temp->right = temp;
    temp->red = 0;
    temp->key = 0;

    temp = tree->root = (struct rb_node*)malloc(sizeof(struct rb_node));
    temp->parent = temp->left = temp->right = tree->nil;
    temp->red = 0;
    temp->key = 0;

    return tree;
}

/**
 * Returns true if the tree is empty.
 */
int rb_isempty(struct rb_tree *tree)
{
    return (tree->root->left == tree->nil);
}

/**
 * Returns the number of elements in the tree.
 */
unsigned int rb_size(struct rb_tree *tree)
{
    return tree->size;
}

/**
 * Returns first node or nil in the tree.
 */
struct rb_node *rb_begin(struct rb_tree *tree)
{
    struct rb_node *x = tree->root->left;

    while (x->left != tree->nil)
	x = x->left;

    return x;
}

/**
 * Returns first node or nil in the tree.
 */
struct rb_node *rb_end(struct rb_tree *tree)
{
    return tree->nil;
}

/**
 * Internal function. Applies the left rotation as described in
 * Introduction to Algorithms by Cormen, Leiserson and Rivest.
 */
static void rb_rotate_left(struct rb_tree *tree, struct rb_node *x)
{
    struct rb_node *y, *nil = tree->nil;

    y = x->right;
    x->right = y->left;

    if (y->left != nil) y->left->parent = x;

    y->parent = x->parent;   

    if (x == x->parent->left) {
	x->parent->left = y;
    }
    else {
	x->parent->right = y;
    }

    y->left = x;
    x->parent = y;

    assert(!tree->nil->red); /* nil not red in LeftRotate */
}

/**
 * Internal function. Applies the right rotation as described in
 * Introduction to Algorithms by Cormen, Leiserson and Rivest.
 */
static void rb_rotate_right(struct rb_tree *tree, struct rb_node *y)
{
    struct rb_node *x, *nil = tree->nil;

    x = y->left;
    y->left = x->right;

    if (nil != x->right) x->right->parent = y;

    x->parent = y->parent;

    if (y == y->parent->left) {
	y->parent->left = x;
    }
    else {
	y->parent->right = x;
    }

    x->right=y;
    y->parent=x;

    assert(!tree->nil->red); /* nil not red in RightRotate */
}

/**
 * Internal function used by rb_insert(). Inserts z into the binary
 * tree as usual.  Described in Introduction to Algorithms by Cormen,
 * Leiserson and Rivest.
 */
static void rb_insert_helper(struct rb_tree *tree, struct rb_node *z)
{
    struct rb_node *x, *y, *nil = tree->nil;
  
    z->left = z->right = nil;
    y = tree->root;
    x = tree->root->left;

    while (x != nil)
    {
	y = x;
	if (tree->compare_keys(x->key, z->key) > 0) { /* x.key > z.key */
	    x = x->left;
	}
	else { /* x,key <= z.key */
	    x = x->right;
	}
    }
    z->parent = y;
    if ( (y == tree->root) ||
	 (tree->compare_keys(y->key, z->key) > 0) ) { /* y.key > z.key */
	y->left = z;
    }
    else {
	y->right = z;
    }

    assert(!tree->nil->red); /* nil not red in TreeInsertHelp */
}

/**
 * Insert function to place a new key, value pair into the tree,
 * taking ownership of key and value object.. First inserts a new node
 * and then applies iterative rotations to rebalance the tree.
 */
struct rb_node *rb_insert(struct rb_tree *tree, void *key, void *value)
{
    struct rb_node *x, *y, *newnode;

    x = (struct rb_node*)malloc(sizeof(struct rb_node));
    x->key = key;
    x->value = value;

    rb_insert_helper(tree, x);
    newnode = x;
    x->red = 1;

    while (x->parent->red) /* use sentinel instead of checking for root */
    {
	if (x->parent == x->parent->parent->left)
	{
	    y = x->parent->parent->right;
	    if (y->red)
	    {
		x->parent->red = 0;
		y->red = 0;
		x->parent->parent->red = 1;
		x = x->parent->parent;
	    }
	    else
	    {
		if (x == x->parent->right) {
		    x = x->parent;
		    rb_rotate_left(tree, x);
		}
		x->parent->red = 0;
		x->parent->parent->red = 1;
		rb_rotate_right(tree, x->parent->parent);
	    } 
	}
	else /* case for x->parent == x->parent->parent->right */
	{
	    y = x->parent->parent->left;
	    if (y->red)
	    {
		x->parent->red = 0;
		y->red = 0;
		x->parent->parent->red = 1;
		x = x->parent->parent;
	    }
	    else
	    {
		if (x == x->parent->left) {
		    x = x->parent;
		    rb_rotate_right(tree, x);
		}
		x->parent->red = 0;
		x->parent->parent->red = 1;
		rb_rotate_left(tree, x->parent->parent);
	    } 
	}
    }

    tree->root->left->red = 0;

    ++tree->size;

#ifdef RBTREE_VERIFY
    assert(rb_verify(tree));
#endif

    return newnode;
}

/**
 * Return the successor node of x in the tree or tree->nil if there is
 * none.
 */
struct rb_node *rb_successor(struct rb_tree *tree, struct rb_node *x)
{ 
    struct rb_node *y, *nil = tree->nil;
    struct rb_node *root = tree->root;

    if (nil != (y = x->right)) /* assignment to y is intentional */
    {
	while (y->left != nil) { /* returns the minium of the right subtree of x */
	    y = y->left;
	}
	return y;
    }
    else
    {
	y = x->parent;
	while (x == y->right) { /* sentinel used instead of checking for nil */
	    x = y;
	    y = y->parent;
	}
	if (y == root) return nil;
	return y;
    }
}

/**
 * Return the predecessor node of x in the tree or tree->nil if there
 * is none.
 */
struct rb_node *rb_predecessor(struct rb_tree *tree, struct rb_node *x)
{
    struct rb_node *y, *nil = tree->nil;
    struct rb_node *root = tree->root;

    if (nil != (y = x->left)) /* assignment to y is intentional */
    {
	while (y->right != nil) { /* returns the maximum of the left subtree of x */
	    y = y->right;
	}
	return y;
    }
    else
    {
	y = x->parent;
	while (x == y->left) { 
	    if (y == root) return nil; 
	    x = y;
	    y = y->parent;
	}
	return y;
    }
}

/**
 * Internal function to recursively destroy all nodes in the tree.
 */
static void rb_destroy_helper(struct rb_tree *tree, struct rb_node *x)
{
    if (x != tree->nil)
    {
	rb_destroy_helper(tree, x->left);
	rb_destroy_helper(tree, x->right);
	tree->destroy_key(x->key);
	tree->destroy_value(x->value);
	free(x);
    }
}

/**
 * Destory the tree and destroy all associated key and value objects
 * via the appropriate callbacks.
 */
void rb_destroy(struct rb_tree *tree)
{
    rb_destroy_helper(tree, tree->root->left);
    free(tree->root);
    free(tree->nil);
    free(tree);
}

/**
 * Internal function to recursively print the whole tree in order.
 */
static void rb_print_inorder(struct rb_tree *tree, struct rb_node *x)
{
    struct rb_node *nil = tree->nil;
    struct rb_node *root = tree->root;

    if (x != tree->nil)
    {
	rb_print_inorder(tree, x->left);

	printf("value=");
	tree->print_value(x->value);

	printf("  key="); 
	tree->print_key(x->key);

	printf("  l->key=");
	if (x->left == nil) printf("NULL");
	else tree->print_key(x->left->key);

	printf("  r->key=");
	if (x->right == nil) printf("NULL");
	else tree->print_key(x->right->key);

	printf("  p->key=");
	if (x->parent == root) printf("NULL");
	else tree->print_key(x->parent->key);

	printf("  red=%i\n", x->red);
	rb_print_inorder(tree, x->right);
    }
}

/**
 * Print the whole tree using the print_xyz() callbacks.
 */
void rb_print(struct rb_tree *tree)
{
    assert(tree->print_key != NULL);
    assert(tree->print_value != NULL);

    rb_print_inorder(tree, tree->root->left);
}

/**
 * Find the first node matching the key in the tree. If multiple equal
 * keys are contained in the tree, the first one in-order is returned.
 * Returns NULL if the key was not found.
 */
struct rb_node *rb_find(struct rb_tree *tree, const void *key)
{
    struct rb_node *x = tree->root->left;
    struct rb_node *nil = tree->nil;
    int cmpval;

    if (x == nil) return NULL;

    cmpval = tree->compare_keys(x->key, key);

    while (cmpval != 0)
    {
	if (cmpval > 0) { /* x->key > q */
	    x = x->left;
	}
	else {
	    x = x->right;
	}
	if (x == nil) return NULL;

	cmpval = tree->compare_keys(x->key, key);
    }

    while (x->left != nil && tree->compare_keys(key, x->left->key) == 0) {
	x = x->left;
    }

    return x;
}

/**
 * Internal function to rebalance the tree after a node is deleted.
 */
static void rb_delete_fixup(struct rb_tree *tree, struct rb_node *x)
{
    struct rb_node *root = tree->root->left;
    struct rb_node *w;

    while ( (!x->red) && (root != x) )
    {
	if (x == x->parent->left)
	{
	    w = x->parent->right;
	    if (w->red) {
		w->red = 0;
		x->parent->red = 1;
		rb_rotate_left(tree, x->parent);
		w = x->parent->right;
	    }
	    if ( (!w->right->red) && (!w->left->red) ) { 
		w->red = 1;
		x = x->parent;
	    }
	    else {
		if (!w->right->red) {
		    w->left->red = 0;
		    w->red = 1;
		    rb_rotate_right(tree, w);
		    w = x->parent->right;
		}
		w->red = x->parent->red;
		x->parent->red = 0;
		w->right->red = 0;
		rb_rotate_left(tree, x->parent);
		x = root; /* this is to exit while loop */
	    }
	}
	else /* the code below is has left and right switched from above */
	{
	    w = x->parent->left;
	    if (w->red) {
		w->red = 0;
		x->parent->red = 1;
		rb_rotate_right(tree, x->parent);
		w = x->parent->left;
	    }
	    if ( (!w->right->red) && (!w->left->red) ) { 
		w->red = 1;
		x = x->parent;
	    }
	    else {
		if (!w->left->red) {
		    w->right->red = 0;
		    w->red = 1;
		    rb_rotate_left(tree, w);
		    w = x->parent->left;
		}
		w->red = x->parent->red;
		x->parent->red = 0;
		w->left->red = 0;
		rb_rotate_right(tree, x->parent);
		x = root; /* this is to exit while loop */
	    }
	}
    }
    x->red = 0;

    assert(!tree->nil->red); /* nil not black in RBDeleteFixUp */
}

/**
 * Delete a node from the tree and rebalance it.
 */
void rb_delete(struct rb_tree *tree, struct rb_node *z)
{
    struct rb_node *x, *y, *nil = tree->nil;
    struct rb_node *root = tree->root;

    y = ((z->left == nil) || (z->right == nil)) ? z : rb_successor(tree, z);
    x = (y->left == nil) ? y->right : y->left;

    if (root == (x->parent = y->parent)) { /* assignment of y->p to x->p is intentional */
	root->left = x;
    }
    else {
	if (y == y->parent->left) {
	    y->parent->left = x;
	}
	else {
	    y->parent->right = x;
	}
    }

    if (y != z) /* y should not be nil in this case */
    {
	assert( (y!=tree->nil) ); /* y is nil in RBDelete */

	/* y is the node to splice out and x is its child */

	if (!(y->red)) rb_delete_fixup(tree, x);
  
	tree->destroy_key(z->key);
	tree->destroy_value(z->value);

	y->left = z->left;
	y->right = z->right;
	y->parent = z->parent;
	y->red = z->red;
	z->left->parent = z->right->parent = y;

	if (z == z->parent->left) {
	    z->parent->left = y; 
	}
	else {
	    z->parent->right = y;
	}
	free(z); 
    }
    else
    {
	tree->destroy_key(y->key);
	tree->destroy_value(y->value);

	if (!(y->red)) rb_delete_fixup(tree, x);
	free(y);
    }
  
    --tree->size;

#ifdef RBTREE_VERIFY
    assert(rb_verify(tree));
#endif
}

/**
 * Verify red-black tree invariants: the root is black, both children
 * of a red node are black and every path from root to leaf has the
 * same number of black nodes.
 */
static int rb_verify_helper(struct rb_tree *tree, struct rb_node *z, int blacks, int *blackmatch, unsigned int *count)
{
    if (z->red)
    {
	/* both children of a red node must be black */
	if (z->left->red) return 0;
	if (z->right->red) return 0;
    }

    if (!z->red) ++blacks;

    if (++(*count) > tree->size)
	return 0;

    if (z->left != tree->nil) {
	if (!rb_verify_helper(tree, z->left, blacks, blackmatch, count))
	    return 0;
    }
    else {
	if (*blackmatch < 0)
	    *blackmatch = blacks;
	else if (*blackmatch != blacks)
	    return 0;
    }

    if (z->right != tree->nil) {
	if (!rb_verify_helper(tree, z->right, blacks, blackmatch, count))
	    return 0;
    }
    else {
	if (*blackmatch < 0)
	    *blackmatch = blacks;
	else if (*blackmatch != blacks)
	    return 0;
    }

    return 1;
}

/**
 * Verify red-black tree invariants: the root is black, both children
 * of a red node are black and every path from root to leaf has the
 * same number of black nodes.
 */
int rb_verify(struct rb_tree *tree)
{
    int blackmatch = -1;
    unsigned int count = 0;

    /* nil must be black. */
    if (tree->nil->red) return 0;

    /* the root must always be black */
    if (tree->root->left->red) return 0;

    if (tree->root->left != tree->nil) {
	if (!rb_verify_helper(tree, tree->root->left, 0, &blackmatch, &count))
	    return 0;
    }

    if (count != tree->size) return 0;

    return 1;
}

/*****************************************************************************/
