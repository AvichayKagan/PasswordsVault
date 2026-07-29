vault: src/vault.c src/dictionary.c src/main.c src/disk.c src/encryption.c src/utilities.c \
	   include/vault.h include/dictionary.h include/disk.h include/encryption.h include/utilities.h \

	gcc -g src/vault.c src/dictionary.c src/main.c src/disk.c src/encryption.c src/utilities.c libs/libsodium.a -DSODIUM_STATIC -pthread -Iinclude -o vault

clean:
	rm -f my_vault