#ifndef ENCRYPTION_H
#define ENCRYPTION_H


#include <stdlib.h>
#include <stdio.h>
#include "sodium.h"

typedef unsigned char Salt[crypto_pwhash_SALTBYTES];

typedef unsigned char Key[crypto_aead_aes256gcm_KEYBYTES];

typedef struct Data {
    unsigned char *data;
    unsigned long long len;
    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES];
} Data;

int crypto_init(void);

void encrypt(Data* data, Key key);

int decrypt(Data* data, Key key, int no_corrupt);

int hash_password(char* password, unsigned char *dest, Salt salt);



#endif /* ENCRYPTION_H */