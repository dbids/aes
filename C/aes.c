// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include "aes.h"
#include "debug.h"

// ------------------------------------------ AES Top ------------------------------------------
// Takes in key, dervies round keys, and then either decrypts or encrypts
int aes(const uint8_t key[AES_KEYLEN], uint8_t data[WSIZE][Nb], bool is_encrypt)
{
  // Generate round keys
  uint8_t round_keys[4*(Nr+1)][WSIZE];  
  if (keyExpansion(key, round_keys) == -1)
  {
    printf("Key Expansion Failed!!");
    return -1;
  }

  // Perform encrypt / decrypt
  if (is_encrypt)
  {
    if (cipher(data, round_keys) == -1)
    {
      printf("Cipher Failed!!");
      return -1;
    }
  }
  else
  {
    if(invCipher(data, round_keys) == -1)
    {
      printf("Inverse Cipher Failed!!");
    }
  }

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
    for (int w_idx = 0; w_idx < WSIZE; w_idx++)
    {
      w[i][w_idx] = key[(i*WSIZE) + w_idx];
    }
//    printf("w[%d], ", i);
//    printWord(w[i]);
//    printf("\n");
  }

  // Every subsequent word w[i] is generated recursively from the
  // preceding word, w[i−1], and the word Nk positions earlier, w[i−Nk] as follows
  // • If i is a multiple of Nk, then w[i] = w[i−Nk] ⊕ subWord(rotWord(w[i−1])) ⊕ Rcon[i/Nk].
  // • For AES-256, if i + 4 is a multiple of 8, then w[i] = w[i−Nk] ⊕ subWord(w[i−1]).
  // • For all other cases, w[i] = w[i−Nk] ⊕ w[i−1].
  uint8_t sub_rot_word [WSIZE];
//  printf("i\ttemp\t\tAf Rw\t\tAf Sw\t\tRcon\t\tAf XOR\t\tw[i-Nk]\t\tw[i]\n........\n");
  for (int i = Nk; i < (4*(Nr+1)); i++)
  {
//    printf("%d\t", i);
    for (int w_idx = 0; w_idx < WSIZE; w_idx++)
      sub_rot_word[w_idx] = w[i-1][w_idx];
//    printWord(sub_rot_word);
//    printf("\t");
    if (i%Nk == 0)
    {
      rotWord(sub_rot_word);
//      printWord(sub_rot_word);
//      printf("\t");
      subWord(sub_rot_word);
//      printWord(sub_rot_word);
//      printf("\t");
//      printf("%d,", (i/Nk)-1);
//      printWord(Rcon[(i/Nk)-1]);
//      printf("\t");
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        w[i][w_idx] = (sub_rot_word[w_idx]) ^ (Rcon[(i/Nk)-1][w_idx]);
//      printWord(w[i]);
//      printf("\t");
    }
    else if ((Nk > 6) && (i%Nk == 4))
    {
//      printf("\t\t");
      subWord(sub_rot_word); 
//      printWord(sub_rot_word);
//      printf("\t\t\t\t\t");
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        w[i][w_idx] = (sub_rot_word[w_idx]);
    }
    else
    {
//      printf("\t\t\t\t\t\t\t\t");
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        w[i][w_idx] = (w[i-1][w_idx]);
    }
//    printWord(w[i-Nk]);
//    printf("\t");
    for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        w[i][w_idx] = (w[i-Nk][w_idx]) ^ (w[i][w_idx]);
//    printWord(w[i]);
//    printf("\n");
  }

  // TEMP
  // printf("i\t\tw\n........\n");
  // for (int i = 0; i < (4*(Nr+1)); i++)
  // {
  //   printf("%d\t\t", i);
  //   printWord(w[i]);
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
// Forward Cipher (Encryption)
// Takes in initial state and round keys... outputs final state by ref.
int cipher(uint8_t state[WSIZE][Nb], uint8_t w[4*(Nr+1)][WSIZE])
{
  // Setup four word variable to handle round key
  uint8_t round_key[4][WSIZE]; 
  for (int k_idx = 0; k_idx < 4; k_idx++)
    for (int w_idx = 0; w_idx < WSIZE; w_idx++)
      round_key[k_idx][w_idx] = w[k_idx][w_idx];

  addRoundKey(state, round_key);
  for (int r = 1; r < Nr; r++)
  {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    for (int k_idx = 0; k_idx < 4; k_idx++)
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        round_key[k_idx][w_idx] = w[(4*r) + k_idx][w_idx];
    addRoundKey(state, round_key);
  }
    subBytes(state);
    shiftRows(state);
    for (int k_idx = 0; k_idx < 4; k_idx++)
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        round_key[k_idx][w_idx] = w[(4*Nr) + k_idx][w_idx];
    addRoundKey(state, round_key);

  return 0;
}

// SubBytes()
// Equivalent to an SBox lookup of every byte in the state
void subBytes(uint8_t state[WSIZE][Nb])
{
  // printf("---------------subBytes-----------------\n");
  // printf("Before:\n");
  // printState(state);
  for (int row = 0; row < WSIZE; row++)
  {
    for (int col = 0; col < Nb; col++)
    {
      state[row][col] = sBox(state[row][col]);
    }
  }
  // printf("After:\n");
  // printState(state);
  return;
}

// ShiftRows()
// Bytes in the last three rows of the state are cyclically shifted
void shiftRows(uint8_t state[WSIZE][Nb]) 
{
  // printf("--------------------shiftRows-------------------\n");
  // printf("Before:\n");
  // printState(state);
  uint8_t temp_byte;
  for (int row = 1; row < WSIZE; row++)
  {
    // Shift start to end once in row 1, twice in row 2, and thrice in row 3
    for (int shift_idx = 0; shift_idx < row; shift_idx++)
    {
      temp_byte = state[row][0];
      for (int col = 0; col < Nb-1; col++)
      {
        state[row][col] = state[row][col+1];
      }
      state[row][Nb-1] = temp_byte;
    }
  }
  // printf("After:\n");
  // printState(state);
  return;
}

// MixColumns()
// Multiplies each of the columns of the state by a fixed matrix
// [s'_0c] = [02 03 01 01] [s_0c]
// [s'_1c] = [01 02 03 01] [s_1c]
// [s'_2c] = [01 01 02 03] [s_2c]
// [s'_3c] = [03 01 01 02] [s_3c]
// This is Galois Field Matrix Multiplication, so the result is non-obvious.
void mixColumns(uint8_t state[WSIZE][Nb]) 
{
  // printf("--------------------MixColumns-------------------\n");
  // printf("Before:\n");
  // printState(state);
  uint8_t temp_col[4];
  for (int col = 0; col < Nb; col++)
  {
    // printf("col : %d\n", col);
    for (int row = 0; row < WSIZE; row++)
    {
      temp_col[row] = state[row][col];
      // printf("%02x\n", temp_col[row]);
    }
    state[0][col] = gfMult(2,temp_col[0]) ^ gfMult(3,temp_col[1]) ^ temp_col[2]           ^ temp_col[3];
    state[1][col] = temp_col[0]           ^ gfMult(2,temp_col[1]) ^ gfMult(3,temp_col[2]) ^ temp_col[3];
    state[2][col] = temp_col[0]           ^ temp_col[1]           ^ gfMult(2,temp_col[2]) ^ gfMult(3,temp_col[3]);
    state[3][col] = gfMult(3,temp_col[0]) ^ temp_col[1]           ^ temp_col[2]           ^ gfMult(2,temp_col[3]);
  } 
  // printf("After:\n");
  // printState(state);
  return;
}

// AddRoundKey()
// A Round Key is applied to the state by applying a bitwise XOR operation.
// Each round key consists of four words, each of which is applied to a column of the state as follows:
// [s'_0c, s'_1c, s'_2c, s'_3c] = [s_0c, s_1c, s_2c, s_3c] ⊕ [w_(4*round+c)]
void addRoundKey(uint8_t state[WSIZE][Nb], uint8_t round_key[4][WSIZE]) 
{
  // printf("--------------------addRoundKey--------------------\n");
  // printf("roundkey: \n");
  // for (int r = 0; r < 4; r++)
  //   for (int c = 0; c < WSIZE; c++)
  //     printf("%02x", round_key[r][c]);
  // printf("\n");

  // printf("Before:\n");
  // printState(state);
  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < 4; j++)
    {
      state[j][i] = state[j][i] ^ round_key[i][j]; // Need to interpret row/col differently because of inconsistencies
    }
  }
  // printf("After:\n");
  // printState(state);
  return;
}


// ------------------------------------------ Inverse Cipher ------------------------------------------ 
// inverse Cipher (Decryption)
// Takes in initial state and round keys... outputs final state by ref.
int invCipher(uint8_t state[WSIZE][Nb], uint8_t w[4*(Nr+1)][WSIZE])
{
  // Setup four word variable to handle round key
  uint8_t round_key[4][WSIZE]; 
  for (int k_idx = 0; k_idx < 4; k_idx++)
    for (int w_idx = 0; w_idx < WSIZE; w_idx++)
      round_key[k_idx][w_idx] = w[(4*Nr) + k_idx][w_idx];

  addRoundKey(state, round_key);
  for (int r = Nr-1; r > 0; r--)
  {
    invShiftRows(state);
    invSubBytes(state);
    for (int k_idx = 0; k_idx < 4; k_idx++)
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        round_key[k_idx][w_idx] = w[(4*r) + k_idx][w_idx];
    addRoundKey(state, round_key);
    invMixColumns(state);
  }
    invShiftRows(state);
    invSubBytes(state);
    for (int k_idx = 0; k_idx < 4; k_idx++)
      for (int w_idx = 0; w_idx < WSIZE; w_idx++)
        round_key[k_idx][w_idx] = w[k_idx][w_idx];
    addRoundKey(state, round_key);

  return 0;
}

// InvSubBytes()
// Equivalent to an invSBox lookup of every byte in the state
void invSubBytes(uint8_t state[WSIZE][Nb])
{
  // printf("---------------invSubBytes-----------------\n");
  // printf("Before:\n");
  // printState(state);
  for (int row = 0; row < WSIZE; row++)
  {
    for (int col = 0; col < Nb; col++)
    {
      state[row][col] = invSBox(state[row][col]);
    }
  }
  // printf("After:\n");
  // printState(state);
  return;
}

// InvShiftRows()
// Bytes in the last three rows of the state are cyclically shifted in the opposite direction
void invShiftRows(uint8_t state[WSIZE][Nb]) 
{
  // printf("--------------------invShiftRows-------------------\n");
  // printf("Before:\n");
  // printState(state);
  uint8_t temp_byte;
  for (int row = 1; row < WSIZE; row++)
  {
    // Shift start to end once in row 1, twice in row 2, and thrice in row 3
    for (int shift_idx = 0; shift_idx < row; shift_idx++)
    {
      temp_byte = state[row][Nb-1];
      for (int col = Nb-1; col > 0; col--)
      {
        state[row][col] = state[row][col-1];
      }
      state[row][0] = temp_byte;
    }
  }
  // printf("After:\n");
  // printState(state);
  return;
}

// InvMixColumns()
// Multiplies each of the columns of the state by a fixed matrix
// [s'_0c] = [02 03 01 01] [s_0c]
// [s'_1c] = [01 02 03 01] [s_1c]
// [s'_2c] = [01 01 02 03] [s_2c]
// [s'_3c] = [03 01 01 02] [s_3c]
// This is Galois Field Matrix Multiplication, so the result is non-obvious.
void invMixColumns(uint8_t state[WSIZE][Nb]) 
{
  // printf("--------------------invMixColumns-------------------\n");
  // printf("Before:\n");
  // printState(state);
  uint8_t temp_col[4];
  for (int col = 0; col < Nb; col++)
  {
    // printf("col : %d\n", col);
    for (int row = 0; row < WSIZE; row++)
    {
      temp_col[row] = state[row][col];
      // printf("%02x\n", temp_col[row]);
    }
    state[0][col] = gfMult(0x0e,temp_col[0]) ^ gfMult(0x0b,temp_col[1]) ^ gfMult(0x0d,temp_col[2]) ^ gfMult(0x09,temp_col[3]);
    state[1][col] = gfMult(0x09,temp_col[0]) ^ gfMult(0x0e,temp_col[1]) ^ gfMult(0x0b,temp_col[2]) ^ gfMult(0x0d,temp_col[3]);
    state[2][col] = gfMult(0x0d,temp_col[0]) ^ gfMult(0x09,temp_col[1]) ^ gfMult(0x0e,temp_col[2]) ^ gfMult(0x0b,temp_col[3]);
    state[3][col] = gfMult(0x0b,temp_col[0]) ^ gfMult(0x0d,temp_col[1]) ^ gfMult(0x09,temp_col[2]) ^ gfMult(0x0e,temp_col[3]);
  } 
  // printf("After:\n");
  // printState(state);
  return;
}


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

// Inverse S-box
static const uint8_t inv_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
uint8_t invSBox(uint8_t byte_in)
{
  return inv_sbox[byte_in];
}

// GF Primer
// The bytes in Galois Fields represent the coefficients of polynomials, for example 01010101b = x^6 + x^4 + x^2 + 1
// Any operation on a GF, really operates on a polynomial, so special functions are required for the operations

// GF Addition
// The coefficients of the elements are added and then reduced modulo 2.
//  (0+0)mod2 = 0
//  (0+1)mod2 = 1
//  (1+0)mod2 = 1
//  (1+1)mod2 = 0
// Resulting in the bitwise XOR of the bytes
inline uint8_t gfAdd(uint8_t a, uint8_t b)
{
  return a ^ b;
}

// GF Mult or •
// The bytes in Galois Fields represent the coefficients of polynomials, for example 01010101b = x^6 + x^4 + x^2 + 1
// GF Mult of two bytes results in two steps
// 1) The two polynomials are multiplied as polynomials (multiplication occurs and then coefficients are reduced modulo 2).
// 2) The resulting polynomial is reduced modulo the following polynomial (x^8 + x^4 + x^3 + x + 1).
// If one considers the case where the second polynomial, c, is x the following equation can be used to compute the result
//   xTimes(b) = {{b6,b5,b4,b3,b2,b1,b0,0}                     if b7=0
//               {{b6,b5,b4,b3,b2,b1,b0,0} ⊕ {0,0,0,1,1,0,1,1} if b7=1 
// Then we can calculate any power of 2^n by repeating that function x times
// Finally, we can use that to compute the multiplication of any number, by splitting that number into the gf addition of any bit set in the byte
inline uint8_t xTimes(uint8_t b)
{
  return ((b >> 7) == 0x00) ? 
         (b << 1) :
         ((b << 1) ^ (0x1b));
}
uint8_t gfMult(uint8_t b, uint8_t c)
{
  uint8_t out = 0x00;

  // Setup mask to extract the bit that we are working on
  uint8_t temp_mask = 0x01;

  // Setup byte to hold the result as we iterate xTimes
  uint8_t temp_byte;

  // Loop through every bit in c
  for (int c_idx = 0; c_idx < 8; c_idx++)
  {
    // Check if that bit is set
    if (c & temp_mask)
    {
      // printf("c_idx %02x\t", c_idx);
      // Run xTimes based on the log of the current bit index that we are extracting
      temp_byte = b;
      for (int x = 0; x < c_idx; x++)
      {
        temp_byte = xTimes(temp_byte);
      }
      // printf("temp_byte: %02x\n", temp_byte);

      // GF add the result to the output
      out = gfAdd(out, temp_byte);
    }

    // Shift mask to grab next bit
    temp_mask = temp_mask << 1;
  }
  return out;
}

// UNUSED
// GF Matrix Mult with fixed matrix widths:
// IN:
// [d0] = [a00 a01 a02 a03] [b0]
// [d1] = [a10 a11 a12 a13] [b1]
// [d2] = [a20 a21 a22 a23] [b2]
// [d3] = [a30 a31 a32 a33] [b3]
// OUT:
// d0 = (a00•b0)⊕(a01•b1)⊕(a02•b2)⊕(a03•b3)
// d1 = (a10•b0)⊕(a11•b1)⊕(a12•b2)⊕(a13•b3)
// d2 = (a20•b0)⊕(a21•b1)⊕(a22•b2)⊕(a23•b3)
// d3 = (a30•b0)⊕(a31•b1)⊕(a32•b2)⊕(a33•b3)
// where ⊕ is bitwise XOR and • is GF multiplication represented by the gfMult function. 
// void gfFixedMatrixMult(uint8_t a[4][4], uint8_t b[4], uint8_t d[4])
// {
//   uint8_t temp_byte;
//   for (int row = 0; row < 4; row++)
//   {
//     temp_byte = 0x00;
//     for (int col = 0; col < 4; col++)
//     {
//       temp_byte = temp_byte ^ gfMult(a[row][col], b[col]);
//     }
//     d[row] = temp_byte;
//   }
//   return;
// }
