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

int bit_exchange(uint8_t*arg, int opos, int npos, uint8_t* result);

int init_perm(uint8_t* message_block, uint8_t* new_block);

int ex_perm(uint8_t* message_block, uint8_t* new_block);

int f_function(uint8_t* right_message, uint8_t* ki, uint8_t* result);

void debug_print(uint8_t* buff, int len);

int left_shift(uint8_t* arg, int len, int step);

int create_subkey(uint8_t* key, const uint8_t* shift_table, uint8_t subkeys[16][6]);

# endif 