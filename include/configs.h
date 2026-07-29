#ifndef CONFIGS_H
#define CONFIGS_H

#define MAX_NAME_LENGTH 128
#define MAX_PASSWORD_LENGTH (128 - crypto_aead_aes256gcm_ABYTES) // including null terminator
#define MAX_DIR_LENGTH 1024


#endif /* CONFIGS_H */