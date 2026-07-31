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
        char name[MAX_NAME_LENGTH];

    public:
        friend class Dict;

        Node(SafeVar &&password, char *name) {
            this->password = std::move(password);
            this->next = nullptr;
            std::strcpy(this->name, name);
        }

        char *get_name() { return this->name; }

        SafeVar& get_password() { return this->password; }

        void change_password(SafeVar& new_password) {
            this->password = std::move(new_password);
        }
};

class Dict {
    private:
        std::unique_ptr<Node> head;
        Node *tail;
    
    public:

        Dict() { this->tail = nullptr; } // head init to nullptr by default as unique pointer

        Node *append_node(char *name, SafeVar&& password);

        void delete_node(Node *node);

        Node *search(char *name);
};