# include<stdio.h>
# include<stdlib.h>
# include<memory.h>
# include"des.h"

extern const uint8_t init_table[];
extern const uint8_t en_step_table[];

int main(int argc, char* argv[])
{
    uint8_t message[] = {0x02, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20};
    uint8_t key[] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59};

    uint8_t result[8];
    uint8_t ciphertext[8];
    uint8_t tmp[4];
    int i;

    en_des(message, key, ciphertext);
    debug_print(ciphertext, 8);

    de_des(result, key, ciphertext);
    debug_print(result, 8);
    return 0;
}
