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
    
    public:
        Dict() { tail = nullptr; } // head init to nullptr by default as unique pointer

        Node *append_node(crypto::SafeVar &&name, crypto::SafeVar&& password);

        void delete_node(Node *node);

        Node *search(char *name);

        Node *get_head() { return head.get(); }

        void empty() { head.reset(); }
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
        }

        crypto::SafeVar& get_name() { return this->name; }

        crypto::SafeVar& get_password() { return this->password; }

        void change_password(crypto::SafeVar& new_password) {
            this->password = std::move(new_password);
        }

        Node *get_next() { return (this->next).get(); }
};