# include<stdio.h>
# include<stdlib.h>
# include<memory.h>
# include"des.h"

extern const uint8_t init_table[];
extern const uint8_t en_step_table[];

int main(int argc, char* argv[])
{
    uint8_t message[8], key[8], result[8], ciphertext[8];
    uint8_t ch;
    int i;

    printf("message(8 byte): ");
    for (i = 0; i < 8; i++)
    {
        ch = getchar();
        message[i] = ch;
    }
    fflush(stdin);
    printf("key(8 byte): ");
    for (i = 0; i < 8; i++)
    {
        ch = getchar();
        key[i] = ch;
    }

    printf("message is:");
    debug_print(message, 8);

    en_des(message, key, ciphertext);
    printf("ciphertest: ");
    debug_print(ciphertext, 8);

    de_des(result, key, ciphertext);
    printf("original test: ");
    debug_print(result, 8);
    return 0;
}
