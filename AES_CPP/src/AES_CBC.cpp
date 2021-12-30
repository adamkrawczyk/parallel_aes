#include "AES_CBC.h"

void AES_CBC::KeyExpansion(w_type *key, w_type *w)
{
    w_type *temp = (w_type*)malloc(Nb * sizeof(w_type*));

    int i = 0;

    while(i < Nb * Nk)
    {
        w[i] = key[i];
        i++;
    }

    while(i < Nb * (Nr+1))
    {
        for(int j = 0; j < 4; j++)
        {
            temp[j] = w[(i-1) * 4 + j];
        }

        if(i % Nk == 0)
        {
            state_type tmp = temp[0];
            for(int j = 0; j < Nb - 1; j++)
            {
                temp[j] = temp[j+1];
            }

            temp[Nb - 1] = tmp;

            for(int j = 0; j < Nb; j++)
            {
                temp[j] = rsbox[temp[j]];
            }

            temp[0] = temp[0] ^ Rcon[i/Nk]; // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)

        }
        else if(Nk > 6 && i % Nk == 4)
        {
            for(int j = 0; j < Nb; j++)
            {
                temp[j] = rsbox[temp[j]];
            }
        }
        for(int j = 0; j < Nb; j++)
        {
            w[j + i*Nb] = w[(i - Nk)*Nb] ^ temp[j];
        }

        i++;
    }
}

void AES_CBC::SubBytes(state_type **state)
{
    for(int i = 0; i < Nb; i++)
    {
        for(int j = 0; j < Nb; j++)
        {
            state[i][j] = rsbox[state[i][j]];
        }
    }

}

void AES_CBC::Cipher(state_type *in, state_type *out, w_type *w)
{
    state_type **state = (state_type**)malloc(Nb * sizeof(state_type*));

    for (int i = 0; i < Nb; i++)
    {
        state[i] = (state_type*)malloc(Nb * sizeof(state_type));
    }

    AES::ArrayTransformOneDim(in, state);

    AES::AddRoundKey(state, w); 

    for(int round = 1; round <= Nr - 1; round++)
    {
        AES_CBC::SubBytes(state);
        AES::ShiftRows(state);
        AES::MixColumns(state);
        AES::AddRoundKey(state, (w + round * Nb * Nb));
    }

    AES::SubBytes(state);
    AES::ShiftRows(state);
    AES::AddRoundKey(state, (w + Nr * Nb * Nb));

    ArrayTransformTwoDim(out, state);

}

void AES_CBC::AES_CBC_encript(state_type *in, state_type *out, w_type *w, int len, state_type *iv)
{

    for (int i = 0; i < len; i += 16)
    {
        for (int e = 0; e < 16; ++e)
        {
            in[i] ^= iv[e];
        }
        AES::Cipher(in, out, w); 

        iv = out;
        in += 16;
    }

}