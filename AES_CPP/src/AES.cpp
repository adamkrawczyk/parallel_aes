#include "AES.h"

AES::AES(AESType aes_type)
: Nb(aes_type.Nb), Nk(aes_type.Nk), Nr(aes_type.Nr)
{
}

void AES::cipher(state_type * in, state_type * out, w_type * w)
{
  state_type ** state = (state_type **)malloc(Nb * sizeof(state_type *));

  for (int i = 0; i < Nb; i++) {
    state[i] = (state_type *)malloc(Nb * sizeof(state_type));
  }

  AES::arrayTransformOneDim(in, state);

  AES::addRoundKey(state, w);

  for (int round = 1; round <= Nr - 1; round++) {
    AES::subBytes(state);
    AES::shiftRows(state);
    AES::mixColumns(state);
    AES::addRoundKey(state, (w + round * Nb * Nb));
  }

  AES::subBytes(state);
  AES::shiftRows(state);
  AES::addRoundKey(state, (w + Nr * Nb * Nb));

  arrayTransformTwoDim(out, state);

}


void AES::invCipher(state_type * in, state_type * out, w_type * w)
{
  state_type ** state = (state_type **)malloc(Nb * sizeof(state_type *));

  for (int i = 0; i < Nb; i++) {
    state[i] = (state_type *)malloc(Nb * sizeof(state_type));
  }

  addRoundKey(state, (w + (Nr + 1) * Nb - 1 ));
  for (unsigned int round = Nr - 1; round <= 1; round--) {
    invShiftRows(state) // See Sec. 5.3.1
    invSubBytes(state) // See Sec. 5.3.2
    addRoundKey(state, w[round * Nb, (round + 1) * Nb - 1])
    invMixColumns(state) // See Sec. 5.3.3
  }
  invShiftRows(state)
  invSubBytes(state)
  addRoundKey(state, w[0, Nb - 1])
  out = state
}

void AES::keyExpansion(w_type * key, w_type * w)
{
  w_type * temp = (w_type *)malloc(Nb * sizeof(w_type *));

  int i = 0;

  while (i < Nb * Nk) {
    w[i] = key[i];
    i++;
  }

  while (i < Nb * (Nr + 1)) {
    for (int j = 0; j < 4; j++) {
      temp[j] = w[(i - 1) * 4 + j];
    }

    if (i % Nk == 0) {
      state_type tmp = temp[0];
      for (int j = 0; j < Nb - 1; j++) {
        temp[j] = temp[j + 1];
      }

      temp[Nb - 1] = tmp;

      for (int j = 0; j < Nb; j++) {
        temp[j] = sbox[temp[j]];
      }

      temp[0] = temp[0] ^ Rcon[i / Nk];     // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)

    } else if (Nk > 6 && i % Nk == 4) {
      for (int j = 0; j < Nb; j++) {
        temp[j] = sbox[temp[j]];
      }
    }
    for (int j = 0; j < Nb; j++) {
      w[j + i * Nb] = w[(i - Nk) * Nb] ^ temp[j];
    }

    i++;
  }
}

void AES::subBytes(state_type ** state)
{
  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < Nb; j++) {
      state[i][j] = sbox[state[i][j]];
    }
  }

}

void AES::shiftRows(state_type ** state)
{
  for (int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++) {
    for (int j = 0; j < numberOfShifts; j++) {
      state_type tmp = state[numberOfShifts][0];
      for (int i = 0; i < Nb - 1; i++) {
        state[numberOfShifts][i] = state[numberOfShifts][i + 1];
      }
      state[numberOfShifts][Nb - 1] = tmp;
    }
  }
}

void AES::addRoundKey(state_type ** state, w_type * w)
{
  for (int j = 0; j < Nb; j++) {
    for (int i = 0; i < Nb; i++) {
      state[j][i] = state[j][i] ^ w[j + Nb * i];       //"w" pseudo conversion to a 2-dimensional array
    }

  }
}

void AES::mixColumns(state_type ** state)
{

  state_type * r = new state_type[Nb];
  state_type * a = new state_type[Nb];
  state_type * b = new state_type[Nb];
  state_type h;

  for (int i = 0; i < Nb; i++) {
    memcpy(r, state[i], Nb * sizeof(state_type));

    //Rijndael_mixColumns https://en.wikipedia.org/wiki/Rijndael_mixColumns
    for (int c = 0; c < 4; c++) {
      a[c] = r[c];
      h = (state_type)((state_type)r[c] >> 7);
      b[c] = r[c] << 1;
      b[c] ^= 0x1B & h;
    }

    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

    memcpy(state[i], r, Nb * sizeof(state_type));
  }
}


void AES::arrayTransformOneDim(state_type * in, state_type ** state)
{
  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < Nb; j++) {
      state[i][j] = in[i + Nb * j];
    }
  }
}

void AES::arrayTransformTwoDim(state_type * out, state_type ** state)
{
  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < Nb; j++) {
      out[i + Nb * j] = state[i][j];
    }
  }
}
