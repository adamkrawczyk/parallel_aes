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