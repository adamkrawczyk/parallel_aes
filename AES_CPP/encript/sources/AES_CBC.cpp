#include "AES_CBC.h"

AES_CBC::AES_CBC(AESType aes_type)
    : AES(aes_type)
{
}

void AES_CBC::AES_CBC_encript(state_type *in, state_type *out, w_type *key, int len, state_type *iv)
{

    app_timer_t start, stop;
    w_type *w = (w_type *)malloc(KEY_ROUND * sizeof(w_type));

    KeyExpansion(key, w);

    for (int i = 0; i <= len; i += 16)
    {
        timer(&start);
        for (int e = 0; e < 16; ++e)
        {
            in[e] ^= iv[e];
        }

        Cipher(in + i, out, w);
        timer(&stop);
        elapsed_time(start, stop);

        iv = out;
    }
}