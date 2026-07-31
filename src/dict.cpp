#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dict.hpp"


Node *Dict::append_node(char *name, SafeVar&& password) {
    /* allocate new Node */
    auto new_node = std::make_unique<Node>(std::move(password), name);

    /* attaching the new node to the list */
    if (this->head == nullptr) { /*if the list is empty */
        this->head = std::move(new_node);
        this->tail = new_node.get();
        new_node->prev = nullptr;
    } else {
        this->tail->next = std::move(new_node);
        new_node->prev = this->tail;
        this->tail = new_node.get();
    }
    
    return new_node.get();
}

void Dict::delete_node(Node *node) {
    if (node->prev == nullptr && node->next == nullptr) { //node is the only node
        this->head = nullptr;
        this->tail = nullptr;
    }
    else if (node->prev == nullptr) { // node is first
        node->next->prev = nullptr;
        this->head = std::move(node->next);
    }
    else if (node->next == nullptr) { // node is last
        this->tail = node->prev;
        node->prev->next = nullptr;
    }
    else { // node is in the middle
        node->next->prev = node->prev;
        node->prev->next = std::move(node->next);
    } 
}

Node *Dict::search(char *name) {
    Node *curr = this->head.get();

    /* iterate until a match is found or list ends */
    while (curr != nullptr && strcmp(curr->name, name)) {
        curr = curr->next.get();
    }

    return curr;
}