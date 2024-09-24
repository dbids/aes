// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include "aes.h"
#include "debug.h"

// ------------------------------------------ AES Top ------------------------------------------
// TODO
int aes(const uint8_t* key, const uint8_t* iv, uint8_t* data, size_t data_len)
{
  // Check inputs
  if (data_len % AES_BLOCKLEN) {
    return -1; // data length not a multiple of AES_BLOCKLEN
  }

  // Setup state
  uint8_t state [4][4];
  



  return 0;
}

// ------------------------------------------ Key Expansion ------------------------------------------ 
// Key is expanded using the AES key schedule into round+1 keys
// See FIPS PUB 197 Section 5.2
int keyExpansion(const uint8_t key[AES_KEYLEN], uint8_t w[4*(Nr+1)][WSIZE])
{
  // Round constant, left fixed though could be computed
  static const uint8_t Rcon[10][WSIZE]= {
    {0x01, 0x00, 0x00, 0x00}, 
    {0x02, 0x00, 0x00, 0x00}, 
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}
  };

  // First Nk words are generated from the key itself
  for (int i = 0; i < Nk; i++)
  {
    for (int b_idx = 0; b_idx < WSIZE; b_idx++)
    {
      w[i][b_idx] = key[(i*WSIZE) + b_idx];
    }
    printf("w[%d], ", i);
    printWord(w[i]);
    printf("\n");
  }

  // Every subsequent word w[i] is generated recursively from the
  // preceding word, w[i−1], and the word Nk positions earlier, w[i−Nk] as follows
  // • If i is a multiple of Nk, then w[i] = w[i−Nk] ⊕ subWord(rotWord(w[i−1])) ⊕ Rcon[i/Nk].
  // • For AES-256, if i + 4 is a multiple of 8, then w[i] = w[i−Nk] ⊕ subWord(w[i−1]).
  // • For all other cases, w[i] = w[i−Nk] ⊕ w[i−1].
  uint8_t sub_rot_word [WSIZE];
  printf("i\ttemp\t\tAf Rw\t\tAf Sw\t\tRcon\t\tAf XOR\t\tw[i-Nk]\t\tw[i]\n........\n");
  for (int i = Nk; i < (4*(Nr+1)); i++)
  {
    printf("%d\t", i);
    for (int b_idx = 0; b_idx < WSIZE; b_idx++)
      sub_rot_word[b_idx] = w[i-1][b_idx];
    printWord(sub_rot_word);
    printf("\t");
    if (i % Nk == 0)
    {
      rotWord(sub_rot_word);
      printWord(sub_rot_word);
      printf("\t");
      subWord(sub_rot_word);
      printWord(sub_rot_word);
      printf("\t");
      printf("%d,", (i/Nk)-1);
      printWord(Rcon[(i/Nk)-1]);
      printf("\t");
      for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        w[i][b_idx] = (sub_rot_word[b_idx]) ^ (Rcon[(i/Nk)-1][b_idx]);
      printWord(w[i]);
      printf("\t");
    }
    #if defined(AES256) && (AES256 == 1)
    else if ((i+4) % 8 == 0)
    {
      subWord(sub_rot_word);
      for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        w[i][b_idx] = (sub_rot_word[b_idx]);
    }
    #endif
    else
    {
      printf("\t\t\t\t\t\t\t\t");
      for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        w[i][b_idx] = (w[i-1][b_idx]);
    }
    printWord(w[i-Nk]);
    printf("\t");
    for (int b_idx = 0; b_idx < WSIZE; b_idx++)
        w[i][b_idx] = (w[i-Nk][b_idx]) ^ (w[i][b_idx]);
    printWord(w[i]);
    printf("\n");
  }

  // TEMP
  // printf("i\t\tw\n........\n");
  // for (int w_idx = 0; w_idx < (4*(Nr+1)); w_idx++)
  // {
  //   printf("%d\t\t", w_idx);
  //   printWord(w[w_idx]);
  //   printf("\n");
  // }

  return 0;
}

// ROTWORD for key expansion
// [a0, a1, a2, a3] --> [a1, a2, a3, a0]
void rotWord (uint8_t word_in[WSIZE])
{
  uint8_t temp_byte = word_in[0];
  for (int i = 0; i < 3; i++)
  {
    word_in[i] = word_in[i+1];
  }
  word_in[3] = temp_byte;
  return;
}

// SUBWORD for key expansion
// Takes the SBox of all of the elements of the word
void subWord (uint8_t word_in[WSIZE])
{
  for (int i = 0; i < 4; i++)
  {
    word_in[i] = sBox(word_in[i]);
  }
  return;
}

// ------------------------------------------ Cipher ------------------------------------------ 
// subBytes()
// Equivalent to an SBox lookup
uint8_t subBytes(uint8_t byte_in)
{
  return sBox(byte_in);
}


// ------------------------------------------ Inverse Cipher ------------------------------------------ 
  


// ------------------------------------------ Common Functions ------------------------------------------ 

// S-box
// A substitution table used by AES over many of its constituent functions
// Derivation from the constants is given in FIPS PUB 197 Section 5.1.1
static const uint8_t sbox[256] = {
  //0     1    2      3     4     5    6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
};
uint8_t sBox(uint8_t byte_in)
{
  return sbox[byte_in];
}
