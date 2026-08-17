#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dict.hpp"


Dict::Node *Dict::append_node_raw(std::unique_ptr<Node> new_node) {
    /* attaching the new node to the list */
    if (head == nullptr) { /*if the list is empty */
        tail = new_node.get();
        new_node->prev = nullptr;
        head = std::move(new_node);
    } else {
        new_node->prev = tail;
        tail->next = std::move(new_node);
        tail = tail->next.get();
    }
    
    return tail;
}

std::unique_ptr<Dict::Node> Dict::delete_node(Node *node, bool catch_) {
    std::unique_ptr<Dict::Node> ret;

    if (node->prev != nullptr) {
        ret = std::move(node->prev->next);
    }
    else ret = std::move(head);

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

    return catch_ ? std::move(ret) : nullptr;
}


Dict::Node *Dict::search(char *name) {
    Node *curr = this->head.get();

    /* iterate until a match is found or list ends */
    while (curr != nullptr && std::strcmp((char *)(curr->name).get(), name)) {
        curr = curr->next.get();
    }

    return curr;
}