#pragma once

#include <memory>
#include <cstring>
#include "configs.hpp"
#include "crypt.hpp"



class Node {
    private:
        std::unique_ptr<Node> next;
        Node *prev;
        SafeVar password;
        SafeVar name;

    public:
        friend class Dict;

        Node(SafeVar &&password, SafeVar &&name) {
            this->password = std::move(password);
            this->name = std::move(name);
            this->next = nullptr;
        }

        SafeVar& get_name() { return this->name; }

        SafeVar& get_password() { return this->password; }

        void change_password(SafeVar& new_password) {
            this->password = std::move(new_password);
        }

        Node *get_next() { return (this->next).get(); }
};

class Dict {
    private:
        std::unique_ptr<Node> head;
        Node *tail;
    
    public:

        Dict() { this->tail = nullptr; } // head init to nullptr by default as unique pointer

        Node *append_node(SafeVar &&name, SafeVar&& password);

        void delete_node(Node *node);

        Node *search(char *name);

        Node *get_head() { return (this->head).get(); }
};