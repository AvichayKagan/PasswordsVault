#ifndef CONFIGS_H
#define CONFIGS_H

#define MAX_NAME_LENGTH 128 // must be greater than max passwrord length
#define MAX_PASSWORD_LENGTH (128 - crypto_aead_aes256gcm_ABYTES) // including null terminator



#endif /* CONFIGS_H */