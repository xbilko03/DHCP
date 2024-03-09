/*
* Name		: dhcp-stats.c
* Project	: Monitorovani DHCP komunikace (Matej Gregr)
* Author	: Jozef Bilko (xbilko03)
*/
#include "btree.h"

struct node* TreeInsert(struct node* root, u_int32_t ip)
{
    if (root == NULL)
        root = CreateNode(ip);
    else if (root->content < ip)
    {
        if (root->left == NULL)
            root->left = CreateNode(ip);
        else
            root->left = TreeInsert(root->left, ip);
    }
    else if (root->content > ip)
    {
        if (root->right == NULL)
            root->right = CreateNode(ip);
        else
            root->right = TreeInsert(root->right, ip);
    }

    return root;
}
struct node* CreateNode(u_int32_t ip) {
    struct node* newNode = malloc(sizeof(struct node));
    newNode->content = ip;
    newNode->left = NULL;
    newNode->right = NULL;

    return newNode;
}
bool TreeContains(struct node* root, u_int32_t ip)
{
    if (root == NULL)
        return false;
    bool retval = false;
    if (root->content < ip)
        retval = TreeContains(root->left, ip);
    else if (root->content > ip)
        retval = TreeContains(root->right, ip);
    else if (root->content == ip)
        retval = true;

    return retval;
}
void DestroyTree(struct node* root)
{
    if (root == NULL)
        return;

    if (root->left != NULL)
        DestroyTree(root->left);
    if (root->right != NULL)
        DestroyTree(root->right);

    free(root);
    return;
}