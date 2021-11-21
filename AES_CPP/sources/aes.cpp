#include "aes.h"

AES::AES(int Nk_tmp, int Nr_tmp, int Nb_tmp)
{
    Nk = Nk_tmp;
    Nr = Nr_tmp;
    Nb = Nb_tmp;
}

void AES::KeyExpansion(w_type *key, w_type *w)
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
                temp[j] = sbox[temp[j]] ^ Rcon[i/Nk];//do poprawy
            }

        }
        else if(Nk > 6 && i % Nk == 4)
        {
            for(int j = 0; j < Nb; j++)
            {
                temp[j] = sbox[temp[j]];
            }
        }
        for(int j = 0; j < Nb; j++)
        {
            w[j + i*Nb] = w[(i - Nk)*Nb] ^ temp[j];
        }

        i++;
    }
}

void AES::SubBytes(state_type **state)
{
    for(int i = 0; i < Nb; i++)
    {
        for(int j = 0; j < Nb; j++)
        {
            state[i][j] = sbox[state[i][j]];
        }
    }

}

void AES::ShiftRows(state_type **state)
{
    for(int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++)
    {
        for(int j = 0; j < numberOfShifts; j++)
        {
            state_type tmp = state[numberOfShifts][0];
            for(int i = 0; i < Nb - 1; i++)
            {
                    state[numberOfShifts][i] = state[numberOfShifts][i+1];
            }
            state[numberOfShifts][Nb - 1] = tmp;
        }
    }
}

void AES::AddRoundKey(state_type  **state, w_type *w)
{
    for(int j = 0; j < Nb; j++)
    {
        for(int i = 0; i < Nb; i++)
        {
            state[j][i] = state[j][i] ^ w[j + Nb * i]; //"w" pseudo conversion to a 2-dimensional array
        }

    }
}

void AES::MixColumns(state_type **state)
{

    state_type r[4];
    state_type a[4];
    state_type b[4];
    state_type h;

    for(int i = 0; i < Nb; i++)
    {
       memcpy(r, state[i], 4*sizeof(state_type));

    //Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
        for(int c=0;c<4;c++)
        {
            a[c] = r[c];
            h = (state_type)((state_type)r[c] >> 7);
            b[c] = r[c] << 1;
            b[c] ^= 0x1B & h;
        }

        r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

        memcpy(state[i], r, 4*sizeof(state_type));
    }
 }



void AES::ArrayTransformOneDim(state_type *in, state_type **state)
{
    for (int i = 0; i < Nb; i++)
    {
        for (int j = 0; j < Nb; j++)
        {
            state[i][j] = in[i + Nb * j];
        }
    }
}

void AES::ArrayTransformTwoDim(state_type *out, state_type **state)
{
    for (int i = 0; i < Nb; i++)
    {
        for (int j = 0; j < Nb; j++)
        {
            out[i + Nb * j] = state[i][j];
        }
    }
}

void AES::Cipher(state_type *in, state_type *out, w_type *w)
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
        AES::SubBytes(state);
        AES::ShiftRows(state);
        AES::MixColumns(state);
        AES::AddRoundKey(state, (w + round * Nb * Nb)); //I don't understand what values mean in pseudocode, I used the description from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    }

    AES::SubBytes(state);
    AES::ShiftRows(state);
    AES::AddRoundKey(state, (w + Nr * Nb * Nb));

    ArrayTransformTwoDim(out, state);

}