// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include <aes.h>

#define TEST_NUM = 0

int main(int argc, char *argv[]) {

  if (argc == 1)
  {
    printf("\nNeed Test Num");
    return -1;
  }

  // --- MAIN AES TEST ---
  if (argv[1] == 0)
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
  else
  {
    #if defined(AES256) && (AES256 == 1)
    #elif defined(AES192) && (AES192 == 1)
    #else
    printf("\n........\n128 bit AES Key Expansion Test\n........\n");
    uint8_t key_in[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t round_keys[AES_keyExpSize];
    int rc = keyExpansion(key_in, round_keys);
    if (rc == -1)
    {
      printf("Function Failed!!");
      return -1;
    }
    for (int r = 0; r < Nr; r++)
    {
      printf("round : %d\t, roundKey :", r);
      for (int kl = 0; kl < AES_KEYLEN; kl++) 
      {
        printf("%x", round_keys[(Nr*r) + kl]);
      }
      printf("\n");
    }
    #endif
  }
}