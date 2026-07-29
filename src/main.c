#include "disk.h"
#include "vault.h"
#include "vault.h"

int main() {
    VaultContext vault;

    if (crypto_init()) return -1;

    open_vault(&vault);

    return 0;
}