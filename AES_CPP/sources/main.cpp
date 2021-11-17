#include "aes.h"

int main()
{
    AES tmp(8, 14, 4); 

    /* a very simplified ShiftRows test
    int **tab = (int**)malloc(4 * sizeof(int*));
    for (int i = 0; i < 4; i++)
        tab[i] = (int*)malloc(4 * sizeof(int));

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            tab[i][j] =  j;
        }
    }

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            std::cout << tab[i][j] << " ";
        }

        std::cout << "\n";
    }

    std::cout << "\n";
    tmp.ShiftRows(tab);

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            std::cout << tab[i][j] << " ";
        }

        std::cout << "\n";
    }*/
}