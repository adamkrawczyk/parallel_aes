#include "AES_ECB.h"

AES_ECB::AES_ECB(AESType aes_type)
    : AES(aes_type)
{
}

void AES_ECB::AES_ECB_decript(state_type *in, state_type *out, w_type *key, int len)
{
    app_timer_t start, stop;
    w_type *w = (w_type *)malloc(KEY_ROUND * sizeof(w_type));

    KeyExpansion(key, w);

    for (int i = 0; i <= len; i += 16)
    {
        timer(&start);
        AES::invCipher(in + i, out, w);
        timer(&stop);
        elapsed_time(start, stop);
    }
}