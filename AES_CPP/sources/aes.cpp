#include "aes.h"

AES::AES(int Nk_tmp, int Nr_tmp, int Nb_tmp)
{
    this->Nk = Nk_tmp;
    this->Nr = Nr_tmp;
    this->Nb = Nb_tmp;
}

void AES::SubBytes(state_type **state)
{
    for(int i = 0; i < Nb; i++)
    {
        for(int j = 0; j < Nb; j++)
        {
            state[i][j] = rsbox[state[i][j]];
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