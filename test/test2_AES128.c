#include <stdio.h>
#include <string.h>

#include "../lib/aes.h"
#include "../lib/crypto.h"

int main(int argc, char* argv[]) {
    uint8_t iv[16]; // For AES128 an IV of 16 bytes
    rng(iv, 16);
    
    printf("IV : ");    
    printfh(iv, 16);

    uint8_t text[] = "Ceci est le texte en clair";
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, text, sizeof text);

    printf("Cypher text: ");
    printfh(text, sizeof text);

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, text, sizeof text);

    printf("Clear text: ");    
    printf("%s\n", text);
}