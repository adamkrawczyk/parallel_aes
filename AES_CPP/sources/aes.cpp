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