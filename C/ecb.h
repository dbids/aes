// Devin Bidstrup
// Created : 10/04/24

#ifndef _ECB_H_
#define _ECB_H_

#include "aes.h"

// Important Excerpts from FIPS 800-38a:
// - For the ECB and CBC modes, the total number of bits in the plaintext must be a multiple of the block size
// - In ECB encryption, the forward cipher function is applied directly and independently to each
//   block of the plaintext. The resulting sequence of output blocks is the ciphertext.
// - In ECB decryption, the inverse cipher function is applied directly and independently to each
//   block of the ciphertext. The resulting sequence of output blocks is the plaintext.
// - In ECB encryption and ECB decryption, multiple forward cipher functions and inverse cipher
//   functions can be computed in parallel.

#endif

