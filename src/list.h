/* SPDX-License-Identifier: Apache-2.0 */

/* Intrusive lists: embed a node in a struct, get the struct back with
 * vg_list_entry. The objects must not move while linked.
 *
 * struct vg_list       circular doubly linked list; the head is a sentinel
 *                      node of the same type
 * struct vg_hlist_head hash bucket: one pointer, NULL when empty
 * struct vg_hlist_node next, plus pprev pointing at whatever points to
 *                      this node, so it unlinks in O(1) without knowing
 *                      its bucket or its predecessor
 */

#ifndef _VG_LIST_H_INCLUDED_
#define _VG_LIST_H_INCLUDED_

#include <stddef.h>


struct vg_list {
    struct vg_list  *prev;
    struct vg_list  *next;
};


struct vg_hlist_node {
    struct vg_hlist_node   *next;
    struct vg_hlist_node  **pprev;
};


struct vg_hlist_head {
    struct vg_hlist_node   *first;
};


#define vg_list_entry(ptr, type, member)                                     \
    ((type *) (void *) ((char *) (ptr) - offsetof(type, member)))

/* pos may be unlinked in the body: n already holds its successor. */
#define vg_list_for_each_safe(pos, n, head)                                  \
    for ((pos) = (head)->next, (n) = (pos)->next; (pos) != (head);          \
         (pos) = (n), (n) = (pos)->next)


static inline void
vg_list_init(struct vg_list *head)
{
    head->prev = head;
    head->next = head;
}


static inline int
vg_list_empty(const struct vg_list *head)
{
    return head->next == head;
}


static inline void
vg_list_add_tail(struct vg_list *node, struct vg_list *head)
{
    node->prev = head->prev;
    node->next = head;
    head->prev->next = node;
    head->prev = node;
}


static inline void
vg_list_del(struct vg_list *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
}


static inline void
vg_hlist_add_head(struct vg_hlist_node *node, struct vg_hlist_head *head)
{
    node->next = head->first;

    if (node->next != NULL) {
        node->next->pprev = &node->next;
    }

    head->first = node;
    node->pprev = &head->first;
}


static inline void
vg_hlist_del(struct vg_hlist_node *node)
{
    *node->pprev = node->next;

    if (node->next != NULL) {
        node->next->pprev = node->pprev;
    }

    node->next = NULL;
    node->pprev = NULL;
}

#endif /* _VG_LIST_H_INCLUDED_ */
