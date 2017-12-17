# include<stdio.h>
# include<stdlib.h>
# include<unistd.h>
# include<memory.h>
# include"des.h"

extern const uint8_t bit_table[];
extern const uint8_t init_table[];
extern const uint8_t ex_table[];
extern const uint8_t p[];
extern const uint8_t com_table[];
extern const uint8_t key_table[];
extern const uint8_t de_step_table[];
extern const uint8_t en_step_table[];
extern const uint8_t end_table[];
extern const uint8_t s[32][16];


int long_oxr(uint8_t* arg1, uint8_t* arg2, int len, uint8_t* result);
int s_replace(uint8_t* message_block, uint8_t* new_block);
int p_perm(uint8_t* message_block, uint8_t* new_block);


int en_des(uint8_t* message, uint8_t* key, uint8_t* ciphertext)
{
    uint8_t subkeys[16][6], right[4], left[4], right_tmp[4], end_tmp[4], message_tmp[8];
    int i;

    memcpy(message_tmp, message, 8);
    init_perm(message_tmp, message_tmp);

    memcpy(left, message_tmp, 4);
    memcpy(right, message_tmp + 4, 4);
    
    create_subkey(key, en_step_table, subkeys);

    for (i = 0; i < 16; i++)
    {
        memcpy(right_tmp, right, 4);
        f_function(right, subkeys[i], right);
        long_oxr(left, right, 4, right);
        memcpy(left, right_tmp, 4);
    }
    memcpy(end_tmp, right, 4);
    memcpy(end_tmp + 4, left, 4);
    memset(ciphertext, 0, 8);
    for (i = 0; i < 64; i++)
        bit_exchange(end_tmp, i + 1, end_table[i], ciphertext);
    return 0;
}

int de_des(uint8_t* message, uint8_t* key, uint8_t* ciphertext)
{
    uint8_t subkeys[16][6], right[4], left[4], right_tmp[4], end_tmp[4], ciphertext_tmp[8];
    int i, k;

    memcpy(ciphertext_tmp, ciphertext, 8);
    init_perm(ciphertext_tmp, ciphertext_tmp);

    memcpy(left, ciphertext_tmp, 4);
    memcpy(right, ciphertext_tmp + 4, 4);
    
    create_subkey(key, en_step_table, subkeys);

    for (i = 0, k = 15; i < 16; i++, k--)
    {
        memcpy(right_tmp, right, 4);
        f_function(right, subkeys[k], right);
        long_oxr(left, right, 4, right);
        memcpy(left, right_tmp, 4);
    }
    memcpy(end_tmp, right, 4);
    memcpy(end_tmp + 4, left, 4);
    memset(message, 0, 8);
    for (i = 0; i < 64; i++)
        bit_exchange(end_tmp, i + 1, end_table[i], message);
    return 0;
}

int f_function(uint8_t* right_message, uint8_t* ki, uint8_t* result)//checked
{
    uint8_t right_message_tmp[4], xor_tmp[6], p_perm_tmp[4];

    memcpy(right_message_tmp, right_message, 4);
    ex_perm(right_message_tmp, xor_tmp);
    long_oxr(xor_tmp, ki, 6, xor_tmp);
    s_replace(xor_tmp, p_perm_tmp);
    p_perm(p_perm_tmp, result);
    return 1;
}

int create_subkey(uint8_t* key, const uint8_t* shift_table, uint8_t subkeys[16][6])//checked
{
    int i, j, step, head_tmp, mid_tmp;
    uint8_t key_tmp[8], cm_key[7], cm_key_tmp[7];

    memcpy(key_tmp, key, 8);
    memset(cm_key, 0, 7);
    for (i = 0; i < 56; i++)
        bit_exchange(key_tmp, i + 1, key_table[i], cm_key);//checked

    for (i = 0; i < 16; i++)
    {
        step = shift_table[i];
        if (step == 0)
        {
            memset(subkeys[i], 0 , 6);
            for (j = 0; j < 48; j++)
                bit_exchange(cm_key_tmp, j + 1,  com_table[j], subkeys[i]);
            continue;
        }

        memcpy(cm_key_tmp, cm_key, 7);
        left_shift(cm_key_tmp, 7, step);
        if (step == 1)
        {
            mid_tmp = cm_key[3] & MID_MASK1;
            head_tmp = cm_key[0] & HEAD_MASK1;
            if (mid_tmp == 0)
                cm_key_tmp[6] = cm_key_tmp[6] & (~0x01);
            else
                cm_key_tmp[6] = cm_key_tmp[6] | 0x01;

            if (head_tmp == 0)
                cm_key_tmp[3] = cm_key_tmp[3] & (~0x10);
            else
                cm_key_tmp[3] = cm_key_tmp[3] | 0x10;
        }
        else if (step == 2)
        {
            mid_tmp = cm_key[3] & MID_MASK2;
            head_tmp = cm_key[0] & HEAD_MASK2;
            switch(mid_tmp)
            {
                case 0x00:
                    cm_key_tmp[6] = cm_key_tmp[6] & (~0x03);
                    break;
                case 0x04:
                    cm_key_tmp[6] = cm_key_tmp[6] & (~0x02);
                    cm_key_tmp[6] = cm_key_tmp[6] | 0x01;
                    break;
                case 0x08:
                    cm_key_tmp[6] = cm_key_tmp[6] & (~0x01);
                    cm_key_tmp[6] = cm_key_tmp[6] | 0x02;
                    break;
                case 0x0C:
                    cm_key_tmp[6] = cm_key_tmp[6] | 0x03;
                    break;
            }
    
            switch(head_tmp)
            {
                case 0x00:
                    cm_key_tmp[3] = cm_key_tmp[3] & (~0x30);
                    break;
                case 0x40:
                    cm_key_tmp[3] = cm_key_tmp[3] & (~0x20);
                    cm_key_tmp[3] = cm_key_tmp[3] | 0x10;
                    break;
                case 0x80:
                    cm_key_tmp[3] = cm_key_tmp[3] & (~0x10);
                    cm_key_tmp[3] = cm_key_tmp[3] | 0x20;
                    break;
                case 0xC0:
                    cm_key_tmp[3] = cm_key_tmp[3] | 0x30;
                    break;
            }
        }
        memcpy(cm_key, cm_key_tmp, 7);
        memset(subkeys[i], 0, 6);
        for (j = 0; j < 48; j++)
            bit_exchange(cm_key_tmp, j + 1,  com_table[j], subkeys[i]);
    }
    return 1;
}

int s_replace(uint8_t* message_block, uint8_t* new_block)//checked
{
    int row[8], col[8];
    uint8_t ch, message_tmp[6];
    int i, j;

    memcpy(message_tmp, message_block, 6);
    for (i = 0; i < 8; i++)
    {
        row[i] = (message_tmp[0] & (0x80)) >> 6;
        row[i] = row[i] | ((message_tmp[0] & (0x04)) >> 2);
        col[i] = (message_tmp[0] & (0x78)) >> 3;
        left_shift(message_tmp, 6, 6);
    }

    memset(new_block, 0, 4);
    for (i = 0, j = 0; i < 8; i++)
    {
        ch = s[i * 4 + row[i]][col[i]];
        if (i % 2 == 0)
            ch = ch << 4;
        new_block[j] = new_block[j] | ch;
        if (i % 2 != 0)
            j++;
    }
    return 1;
}

int left_shift(uint8_t* arg, int len, int step)//checked
{
    uint8_t hmask, nmask, bit_tmp;
    int i;

    hmask = 0xFF;
    nmask = 0xFF;

    if (step >= 8)
        return 0;

    hmask = hmask >> (8 - step);
    nmask = nmask << (8 - step);
    for (i = 0; i < len; i++)
    {
        bit_tmp = 0x00;
        arg[i] = arg[i] << step;
        if (i + 1 < len)
            bit_tmp = arg[i + 1] & nmask;
        bit_tmp = bit_tmp >> (8 - step);
        arg[i] = arg[i] | bit_tmp;
    }
    return 1;
}

int long_oxr(uint8_t* arg1, uint8_t* arg2, int len, uint8_t* result)//checked
{
    int i;
    uint8_t* ptr1, *ptr2;
    ptr1 = malloc(sizeof(uint8_t) * len);
    ptr2 = malloc(sizeof(uint8_t) * len);

    memcpy(ptr1, arg1, len * sizeof(uint8_t));
    memcpy(ptr2, arg2, len * sizeof(uint8_t));

    for (i = 0; i < len; i++)
        result[i] = ptr1[i] ^ ptr2[i];

    free(ptr1);
    free(ptr2);
    return 0;
}

int p_perm(uint8_t* message_block, uint8_t* new_block)
{
    int i;
    uint8_t message_tmp[4];
    
    memcpy(message_tmp, message_block, 4);
    memset(new_block, 0, 4);
    for (i = 0; i < 32; i++)
        bit_exchange(message_tmp, i + 1, p[i], new_block);
    return 1;
}

int ex_perm(uint8_t* message_block, uint8_t* new_block)//cheched
{
    int i;
    uint8_t message_tmp[4];
    
    memcpy(message_tmp, message_block, 4);
    memset(new_block, 0, 6);
    for (i = 0; i < 48; i++)
        bit_exchange(message_tmp, i + 1, ex_table[i], new_block);
    return 1;
}

int init_perm(uint8_t* message_block, uint8_t* new_block)//checked
{
    int i;
    uint8_t message_tmp[8];

    memcpy(message_tmp, message_block, 8);
    memset(new_block, 0, 8);
    for (i = 0; i < 64; i++)
        bit_exchange(message_tmp, i + 1, init_table[i], new_block);
    return 1;
}

int bit_exchange(uint8_t*arg, int opos, int npos, uint8_t* result)//checked
{
    int oin, nin, oblock, nblock;

    oin = (opos - 1) % 8;
    nin = (npos - 1) % 8;
    oblock = (opos - 1 ) / 8;
    nblock = (npos - 1) / 8;
   
    if ((arg[nblock] & bit_table[nin]) == bit_table[nin])
        result[oblock] = result[oblock] | (bit_table[oin]);
    return 1;
}

void print_bin(uint8_t* buff, int len)
{
    int i, j;
    uint8_t tmp, flag;

    for (i = 0; i < len; i++)
    {
        tmp = buff[i];
        for (j = 0; j < 8; j++)
        {
            flag = tmp << j;
            if ((flag & 0x80) == 0x80)
                printf("1");
            else
                printf("0");
        }
        printf(" ");
    }
    printf("\n");
}

void debug_print(uint8_t* buff, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", buff[i]);
	}
	printf("\n");
}