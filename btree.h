/*
* Name		: dhcp-stats.c
* Project	: Monitorovani DHCP komunikace (Matej Gregr)
* Author	: Jozef Bilko (xbilko03)
*/
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#define maxPrefixes 512

struct ip_range {
    char* range;
    u_int32_t maxhosts;
    u_int32_t allocated;
    char* suffix;
    bool logged;
};
struct node {
    u_int32_t content;
    struct node* left;
    struct node* right;
};

struct node* TreeInsert(struct node* root, u_int32_t ip);
struct node* CreateNode(u_int32_t ip);
bool TreeContains(struct node* root, u_int32_t ip);
void DestroyTree(struct node* root);