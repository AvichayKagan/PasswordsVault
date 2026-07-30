#pragma once

#include "configs.h"
#include "encryption.h"



class Node {
    private:
        struct Node *next;
        struct Node *prev;
        Data password;
        char name[MAX_NAME_LENGTH];

    public:
        char* get_name() { return this->name; }

        Data* get_password() { return &this->password; }

        void change_password(Data *new_password) {
            this->password.data = new_password->data;
            this->password.len = new_password->len;
            memccpy(this->password.npub, new_password->npub);
        }
};

class Dict {
    private:
        Node *head;
        Node *tail;
    
    public:
        Node *append_node(Dict *list, char *name, Data *password);

        void delete_node(Dict *list, Node *node);

        Node *search(Dict *list, char *name);

        void empty_dict(Dict *list);
};