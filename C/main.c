// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include "aes.h"
#include "debug.h"

#define TEST_NUM = 0

int main(int argc, char *argv[]) {

  if (argc == 1)
  {
    printf("\nNeed Test Num");
    return -1;
  }

  // --- MAIN AES TEST ---
  if (*argv[1] == '0')
  {
    printf("\n........\nMain AES Test\n........\n");
    // Define sample test case variables
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t data[16];
    size_t  data_len = 16;
    for (int key_idx = 0; key_idx < 16; key_idx++)
      key[key_idx] = 0;
    for (int iv_idx = 0; iv_idx < 12; iv_idx++)
      iv[iv_idx] = 0;
    for (int data_idx = 0; data_idx < 16; data_idx++)
      data[data_idx] = 0;

    // Call the AES function
    int rc = aes(key, iv, data, data_len);
    if (rc == -1)
    {
      printf("Function Failed!!");
      return -1;
    }
  }

  // --- AES Key Expansion test ---
  else if(*argv[1] == '1')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("###################\n128 bit AES Key Expansion Test\n###################\n");
    uint8_t key_in[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    #elif defined(AES192) && (AES192 == 1)
    printf("###################\n192 bit AES Key Expansion Test\n###################\n");
    uint8_t key_in[AES_KEYLEN] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                                  0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    #else
    printf("###################\n256 bit AES Key Expansion Test\n###################\n");
    uint8_t key_in[AES_KEYLEN] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    #endif

    uint8_t round_keys[4*(Nr+1)][WSIZE];
    if (keyExpansion(key_in, round_keys) == -1)
    {
      printf("Function Failed!!");
      return -1;
    }

    for (int r = 0; r < Nr+1; r++)
    {
      printf("round: %d,\t roundKey: ", r);
      for (int kl = 0; kl < AES_KEYLEN/WSIZE; kl++) 
      {
        for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        {
          printf("%02x", round_keys[(4*r)+kl][b_idx]);
        }
      }
      printf("\n");
    }
  }

  // --- AES Cipher test ---
  else if(*argv[1] == '2')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("###################\n128b Key Cipher Test\n###################\n");
    uint8_t in[4][Nb] = {{0x32, 0x43, 0xf6, 0xa8}, {0x88, 0x5a, 0x30, 0x8d}, {0x31, 0x31, 0x98, 0xa2}, {0xe0, 0x37, 0x07, 0x34}};
    uint8_t key_in[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t round_keys[4*(Nr+1)][WSIZE];
    
    printf("---------------------Check key expansion---------------------\n");
    if (keyExpansion(key_in, round_keys) == -1)
    {
      printf("Function Failed!!");
      return -1;
    }
    for (int r = 0; r < Nr+1; r++)
    {
      printf("round: %d,\t roundKey: ", r);
      for (int kl = 0; kl < AES_KEYLEN/WSIZE; kl++) 
      {
        for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        {
          printf("%02x", round_keys[(4*r)+kl][b_idx]);
        }
      }
      printf("\n");
    }
    printf("---------------------\n");
    
    if (cipher(in, round_keys) == -1)
    {
      printf("Function Failed!!");
      return -1;
    }
    #else
    printf("Cipher test only works with 128b keys\n");
    #endif
  }

  // --- AES Cipher ShiftRows Test ---
  else if(*argv[1] == '3')
  {
    uint8_t in_state[4][Nb] = {{0x00, 0x01, 0x02, 0x03}, {0x04, 0x05, 0x06, 0x07}, {0x08, 0x09, 0x0A, 0x0B}, {0x0C, 0x0D, 0x0E, 0x0F}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    shiftRows(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }
}
