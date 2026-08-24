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
    node_count++;
    
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
    node_count--;

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

crypto::SafeVar Dict::pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key) {
    size_t write_len = get_count() * (config::max_name_len + config::max_password_len);
    crypto::SafeVar vault_data(write_len);
    int j = 0;
    
    // load the buffer
    for (Dict::Node *i = get_head(); i != nullptr; i = i->get_next()) {
        crypto::SafeVar& password = i->password;

        // write the name
        std::memcpy(vault_data.get() + j, i->name.get(), config::max_name_len);
        j += config::max_name_len;

        // write the password
        password.decrypto(session_key.get(), false);
        std::memcpy(vault_data.get() + j, password.get(), config::max_password_len);
        j += config::max_password_len;
        password.encrypto(session_key.get());
    }
    vault_data.encrypto(master_key.get());

    return vault_data;
}