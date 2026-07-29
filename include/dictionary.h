#ifndef DICTIONARY_H
#define DICTIONARY_H

#include "configs.h"
#include "encryption.h"

typedef struct Node {
    struct Node *next;
    struct Node *prev;
    Data password;
    unsigned char name[MAX_NAME_LENGTH];
} Node;

typedef struct Dict {
    Node *head;
    Node *tail;
} Dict;



Node *append_node(Dict *list, char *name, Data *password);

void delete_node(Dict *list, Node *node);

Node *search(Dict *list, char *name);

void empty_dict(Dict *list);



#endif /* DICTIONARY_H */