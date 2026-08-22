#pragma once

#include <memory>
#include <cstring>
#include "configs.hpp"
#include "crypt.hpp"


class Dict {
    public:
        class Node;
        
    private:
        std::unique_ptr<Node> head;
        Node *tail;
        unsigned int node_count = 0;
    
    public:
        Dict() { tail = nullptr; } // head init to nullptr by default as unique pointer

        Node *append_node(crypto::SafeVar &&name, crypto::SafeVar&& password) {
            auto new_node = std::make_unique<Node>(std::move(password), std::move(name));
            return append_node_raw(std::move(new_node));
        }

        Node *append_node_raw(std::unique_ptr<Node> new_node);

        std::unique_ptr<Node> delete_node(Node *node, bool catch_);

        Node *search(char *name);

        Node *get_head() { return head.get(); }

        unsigned int get_count() { return node_count; }

        void empty() { head.reset(); tail = nullptr; node_count = 0; } // must not except
};




class Dict::Node {
    private:
        std::unique_ptr<Node> next;
        Node *prev;
        crypto::SafeVar password;
        crypto::SafeVar name;

    public:
        friend class Dict;

        Node(crypto::SafeVar &&password, crypto::SafeVar &&name) {
            this->password = std::move(password);
            this->name = std::move(name);
            this->next = nullptr;
            this->prev = nullptr;
        }

        crypto::SafeVar& get_name() { return this->name; }

        crypto::SafeVar& get_password() { return this->password; }

        void change_password(crypto::SafeVar& new_password) {
            this->password = std::move(new_password);
        }

        Node *get_next() { return (this->next).get(); }
};
