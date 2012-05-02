#include "ldpd.h"


struct mpls_tree_node {
	RB_ENTRY(mpls_tree_node)	node;
	uint32_t					key;
	int							length;
	void						*info;
};


static int mpls_tree_node_compare(struct mpls_tree_node *a, struct mpls_tree_node *b)
{
	if(ntohl(a->key) < ntohl(b->key))
		return (-1);
	if(ntohl(a->key) > ntohl(b->key))
		return (1);
	if(a->length < b->length)
		return (-1);
	if(a->length > b->length)
		return (1);
	return (0);
}


typedef RB_HEAD(mpls_tree, mpls_tree_node) mpls_tree;
RB_PROTOTYPE(mpls_tree, mpls_tree_node, node, mpls_tree_node_compare)
RB_GENERATE(mpls_tree, mpls_tree_node, node, mpls_tree_node_compare)


mpls_tree_handle mpls_tree_create(int depth)
{
	struct mpls_tree *tree;

	tree = mpls_malloc(sizeof(struct mpls_tree));
	if(tree)
		RB_INIT(tree);

	return tree;
}


mpls_return_enum mpls_tree_insert(mpls_tree_handle tree, uint32_t key, int length, void *info)
{
	struct mpls_tree_node *node;

	node = mpls_malloc(sizeof(struct mpls_tree_node));
	node->key = key;
	node->length = length;
	node->info = info;
	if(RB_INSERT(mpls_tree, tree, node) != NULL)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


static struct mpls_tree_node *mpls_tree_find(struct mpls_tree *tree, uint32_t key, int length)
{
	struct mpls_tree_node query;

	query.key = key;
	query.length = length;
	return RB_FIND(mpls_tree, tree, &query);
}


mpls_return_enum mpls_tree_remove(mpls_tree_handle tree, uint32_t key, int length, void **info)
{
	struct mpls_tree_node *node;

	node = mpls_tree_find(tree, key, length);
	if(!node)
		return MPLS_FAILURE;
	*info = node->info;
	RB_REMOVE(mpls_tree, tree, node);
	mpls_free(node);
	
	return MPLS_SUCCESS;
}


mpls_return_enum mpls_tree_replace(mpls_tree_handle tree, uint32_t key, int length, void *new, void **old)
{
	struct mpls_tree_node *node;

	node = mpls_tree_find(tree, key, length);
	if(!node)
		return MPLS_FAILURE;

	*old = node->info;
	node->info = new;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_tree_get(mpls_tree_handle tree, uint32_t key, int length, void **info)
{
	struct mpls_tree_node *node;

	node = mpls_tree_find(tree, key, length);
	if(!node)
		return MPLS_FAILURE;

	*info = node->info;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_tree_get_longest(mpls_tree_handle tree, uint32_t key, void **info)
{
	struct mpls_tree_node *node;

	/* is it right? */
	node = mpls_tree_find(tree, key, 0);
	if(!node)
		return MPLS_FAILURE;

	*info = node->info;

	return MPLS_SUCCESS;
}


void mpls_tree_dump(const mpls_tree_handle tree, mpls_tree_dump_callback callback)
{
	struct mpls_tree_node *node;

	RB_FOREACH(node, mpls_tree, tree) {
		if(callback)
			callback(&node->key);
	}
}


void mpls_tree_delete(mpls_tree_handle tree)
{
	struct mpls_tree_node *node, *next;

	for(node = RB_MIN(mpls_tree, tree); node != NULL; node = next) {
		next = RB_NEXT(mpls_tree, tree, node);
		RB_REMOVE(mpls_tree, tree, node);
		mpls_free(node);
	}
}


mpls_return_enum mpls_tree_getfirst(mpls_tree_handle tree, uint32_t *key, int *length, void **info)
{
	struct mpls_tree_node *node;

	node = RB_MIN(mpls_tree, tree);
	if(!node)
		return MPLS_FAILURE;

	*key = node->key;
	*length = node->length;
	*info = node->info;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_tree_getnext(mpls_tree_handle tree, uint32_t *key, int *length, void **info)
{
	struct mpls_tree_node *node;

	node = mpls_tree_find(tree, *key, *length);
	if(!node)
		return MPLS_FAILURE;

	node = RB_NEXT(mpls_tree, tree, node);
	if(!node)
		return MPLS_FAILURE;

	*key = node->key;
	*length = node->length;
	*info = node->info;

	return MPLS_SUCCESS;
}
