// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
#include "debug.h"
#include "ecb.h"

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
    #if defined(AES128) && (AES128 == 1)
    printf("############################\nMain 128-bit AES Test\n############################\n");
    // Define sample test case variables
    uint8_t key[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    block_t data = {{0x32, 0x88, 0x31, 0xe0}, {0x43, 0x5a, 0x31, 0x37}, {0xf6, 0x30, 0x98, 0x07}, {0xa8, 0x8d, 0xa2, 0x34}};

    // Call the AES function for encryption
    printf("---------------------Before Encryption:---------------------\n");
    printState(data);
    int rc = aes(key, data, 1);
    if (rc == -1)
    {
      printf("Encryption Failed!!");
      return -1;
    }
    printf("---------------------After Encryption & Before Decryption:---------------------\n");
    printState(data);

    // Call the AES function for decryption
    rc = aes(key, data, 0);
    if (rc == -1)
    {
      printf("Decryption Failed!!");
      return -1;
    }
    printf("---------------------After Decryption:---------------------\n");
    printState(data);
    #else
    printf("Test only works with 128b keys\n");
    #endif
  }

  // --- AES Key Expansion Test ---
  else if(*argv[1] == '1')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("############################\n128 bit AES Key Expansion Test\n############################\n");
    uint8_t key_in[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    //uint8_t key_in[AES_KEYLEN] = {0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c};
    #elif defined(AES192) && (AES192 == 1)
    printf("############################\n192 bit AES Key Expansion Test\n############################\n");
    uint8_t key_in[AES_KEYLEN] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                                  0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    #else
    printf("############################\n256 bit AES Key Expansion Test\n############################\n");
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

  // --- AES Cipher Test ---
  else if(*argv[1] == '2')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("############################\n128b Key Cipher Test\n############################\n");
    block_t in = {{0x32, 0x88, 0x31, 0xe0}, {0x43, 0x5a, 0x31, 0x37}, {0xf6, 0x30, 0x98, 0x07}, {0xa8, 0x8d, 0xa2, 0x34}};
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
    
    printf("---------------------Before:---------------------\n");
    printState(in);
    if (cipher(in, round_keys) == -1)
    {
      printf("Function Failed!!");
      return -1;
    }
    printf("---------------------After:---------------------\n");
    printState(in);
    #else
    printf("Cipher test only works with 128b keys\n");
    #endif
  }

    // --- AES Inverse Cipher Test ---
  else if(*argv[1] == '3')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("############################\n128b Key InvCipher Test\n############################\n");
    block_t in = {{0x39, 0x02, 0xdc, 0x19}, {0x25, 0xdc, 0x11, 0x6a}, {0x84, 0x09, 0x85, 0x0b}, {0x1d, 0xfb, 0x97, 0x32}};
    uint8_t key_in[AES_KEYLEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t round_keys[4*(Nr+1)][WSIZE];
    
    printf("---------------------Check key expansion---------------------\n");
    if (keyExpansion(key_in, round_keys) == -1)
    {
      printf("Key Expansion Failed!!");
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
    
    if (invCipher(in, round_keys) == -1)
    {
      printf("Inverse Cipher Failed!!");
      return -1;
    }
    #else
    printf("Cipher test only works with 128b keys\n");
    #endif
  }

  // --- AES ShiftRows Test ---
  else if(*argv[1] == '4')
  {
    printf("############################\nAES ShiftRows Test\n############################\n");
    block_t in_state = {{0x00, 0x01, 0x02, 0x03}, {0x04, 0x05, 0x06, 0x07}, {0x08, 0x09, 0x0A, 0x0B}, {0x0C, 0x0D, 0x0E, 0x0F}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    shiftRows(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }
  
  // --- AES MixColumns Test ---
  else if(*argv[1] == '5')
  {
    printf("############################\nAES MixColumns Test\n############################\n");
    block_t in_state = {{0x00, 0x01, 0x02, 0x03}, {0x04, 0x05, 0x06, 0x07}, {0x08, 0x09, 0x0A, 0x0B}, {0x0C, 0x0D, 0x0E, 0x0F}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    mixColumns(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }

  // --- AES AddRoundKey Test ---
  else if(*argv[1] == '6')
  {
    printf("############################\nAES AddRoundKey Test\n############################\n");
    block_t in_state = {{0x00, 0x01, 0x02, 0x03}, {0x04, 0x05, 0x06, 0x07}, {0x08, 0x09, 0x0A, 0x0B}, {0x0C, 0x0D, 0x0E, 0x0F}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    addRoundKey(in_state, in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }
  // --- GF Mult Test ---
  else if(*argv[1] == '7')
  {
    printf("############################\nGalois Field Multiplication Test\n############################\n");
    uint8_t b = 0x57;
    uint8_t c = 0x13;
    uint8_t out;
    out = gfMult(b,c);
    printf("b : %02x \t c : %02x \t out : %02x\n", b, c, out);
  }

  // --- AES InvShiftRows Test ---
  else if(*argv[1] == '8')
  {
    printf("############################\nAES InvShiftRows Test\n############################\n");
    block_t in_state = {{0x00, 0x01, 0x02, 0x03}, {0x05, 0x06, 0x07, 0x04}, {0x0A, 0x0B, 0x08, 0x09}, {0x0F, 0x0C, 0x0D, 0x0E}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    invShiftRows(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }
  
  // --- AES InvMixColumns Test ---
  else if(*argv[1] == '9')
  {
    printf("############################\nAES InvMixColumns Test\n############################\n");
    block_t in_state = {{0x08, 0x09, 0x0a, 0x0b}, {0x1c, 0x1d, 0x1e, 0x1f}, {0x00, 0x01, 0x02, 0x03}, {0x14, 0x15, 0x16, 0x17}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    invMixColumns(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }

  // --- AES SubBytes Test ---
  else if(*argv[1] == 'A')
  {
    printf("############################\nAES SubBytes Test\n############################\n");
    block_t in_state = {{0x00, 0x01, 0x02, 0x03}, {0x04, 0x05, 0x06, 0x07}, {0x08, 0x09, 0x0A, 0x0B}, {0x0C, 0x0D, 0x0E, 0x0F}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    subBytes(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }

  // --- AES InvSubBytes Test ---
  else if(*argv[1] == 'B')
  {
    printf("############################\nAES InvSubBytes Test\n############################\n");
    block_t in_state = {{0x63, 0x7c, 0x77, 0x7b}, {0xf2, 0x6b, 0x6f, 0xc5}, {0x30, 0x01, 0x67, 0x2b}, {0xfe, 0xd7, 0xab, 0x76}};
    printf("---------------------Before:---------------------\n");
    printState(in_state);
    invSubBytes(in_state);
    printf("---------------------After:---------------------\n");
    printState(in_state);
  }
  // --- AES ECB Mode Test ---
  else if(*argv[1] == 'C')
  {
    #if defined(AES128) && (AES128 == 1)
    printf("############################\n128-bit AES-ECB Test\n############################\n");

    // KEY = 00000000000000000000000000000000
    uint8_t key[AES_KEYLEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    printf("Key = ");
    printData(key, AES_KEYLEN);

    // PLAINTEXT = 80000000000000000000000000000000 
    size_t data_size = 16;
    uint8_t* data_in = malloc(data_size);
    data_in[0] = 0x80;
    for (int i = 1; i < data_size; i++)
      data_in[i] = 0x00;
    printf("Plaintext = ");
    printData(data_in, data_size);

    // Call the AES_ECB function for encryption
    int rc = aes_ecb(key, data_in, 1, data_size);
    if (rc == -1)
    {
      printf("Encryption Failed!!");
      free(data_in);
      return -1;
    }

    // CIPHERTEXT = 3ad78e726c1ec02b7ebfe92b23d9ec34
    printf("Ciphertext = "); 
    printData(data_in, data_size);
    free(data_in);

    #else
    printf("Test only works with 128b keys\n");
    #endif
  }
}
