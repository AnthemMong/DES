# ifndef DES_H
# define DES_H

# include<stdint.h>

# define HEAD_MASK1 0x80
# define HEAD_MASK2 0xC0
# define MID_MASK1 0x08
# define MID_MASK2 0x0C

int en_des(uint8_t* message, uint8_t* key, uint8_t* ciphertext);

int de_des(uint8_t* message, uint8_t* key, uint8_t* ciphertext);

void print_bin(uint8_t* buff, int len);

void debug_print(uint8_t* buff, int len);

# endif 