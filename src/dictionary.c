#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dictionary.h"


Node *append_node(Dict *list, char *name, Data *password) {
    /* allocate new Node */
    Node *new_node = (Node *)sodium_malloc(sizeof(Node));
    if (new_node == NULL) return NULL;

    /* initializing the new Node */
    strcpy(new_node->name, name);
    new_node->password.len = password->len;
    memcpy(new_node->password.npub, password->npub, crypto_aead_aes256gcm_NPUBBYTES);
    new_node->password.data = sodium_malloc(MAX_PASSWORD_LENGTH + crypto_aead_aes256gcm_ABYTES);
    if (new_node->password.data == NULL) return NULL;
    memcpy(new_node->password.data, password->data, MAX_PASSWORD_LENGTH + crypto_aead_aes256gcm_ABYTES);
    new_node->next = NULL;

    /* attaching the new node to the list */
    if (list->head == NULL) { /*if the list is empty */
        list->head = new_node;
        list->tail = new_node;
        new_node->prev = NULL;
    } else {
        list->tail->next = new_node;
        new_node->prev = list->tail;
        list->tail = new_node;
    }
    
    return new_node;
}

void delete_node(Dict *list, Node *node) {
    /* deattaching the new node to the list */
    if (node->prev == NULL && node->next == NULL) { //node is the only node
        list->head = NULL;
        list->tail = NULL;
    }
    else if (node->prev == NULL) { // node is first
        list->head = node->next;
        node->next->prev = NULL;
    }
    else if (node->next == NULL) { // node is last
        list->tail = node->prev;
        node->prev->next = NULL;
    }
    else node->prev->next = node->next;

    // freeing the node
    sodium_free(node->password.data);
    sodium_free(node);
}

Node *search(Dict *list, char *name) {
    Node *curr = list->head;

    /* iterate until a match is found or list ends */
    while (curr != NULL && strcmp(curr->name, name)) {
        curr = curr->next;
    }

    return curr;
}



void empty_dict(Dict *list) {
    Node *temp, *current = list->head;

    /* iterate over the list and free the nodes */
    while (current != NULL) {
        temp = current->next; /* temp will hold the next while the current is deleted */
        sodium_free(current->password.data);
        sodium_free(current);
        current = temp; /* current hold the next now */
    }
    
    /* reset the head and tail */
    list->head = NULL;
    list->tail = NULL;
}