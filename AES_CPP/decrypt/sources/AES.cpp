#include "AES.h"

AES::AES(AESType aes_type)
	: Nb(aes_type.Nb), Nk(aes_type.Nk), Nr(aes_type.Nr)
{
}

void AES::elapsed_time(app_timer_t start, app_timer_t stop)
{
	double etime;
	etime = 1e+3 * (stop.tv_sec - start.tv_sec) +
			1e-6 * (stop.tv_nsec - start.tv_nsec);
	printf("CPU (total!) time = %.3f ns\n", etime * 1e+6);
}

void AES::KeyExpansion(w_type *key, w_type *w)
{
	w_type temp[Nb];

	int i = 0;

	memcpy(w, key, Nb * Nk * sizeof(w_type));

	i = Nk;

	while (i < Nb * (Nr + 1))
	{
		for (int j = 0; j < 4; j++)
		{
			temp[j] = w[(i - 1) * 4 + j];
		}

		if (i % Nk == 0)
		{
			state_type tmp = temp[0];
			for (int j = 0; j < Nb - 1; j++)
			{
				temp[j] = temp[j + 1];
			}

			temp[Nb - 1] = tmp;

			for (int j = 0; j < Nb; j++)
			{
				temp[j] = sbox[temp[j]];
			}

			temp[0] = temp[0] ^ Rcon[i / Nk]; // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			for (int j = 0; j < Nb; j++)
			{
				temp[j] = sbox[temp[j]];
			}
		}
		for (int j = 0; j < Nb; j++)
		{
			w[j + i * Nb] = w[(i - Nk) * Nb + j] ^ temp[j];
		}

		i = i + 1;
	}
}

uint8_t AES::xtime(uint8_t x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void AES::invSubBytes(state_type **state)
{
	for (int i = 0; i < Nb; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			state[j][i] = rsbox[state[j][i]];
		}
	}
}

void AES::invShiftRows(state_type **state)
{
	for (int numberOfShifts = 1; numberOfShifts < Nb; numberOfShifts++)
	{
		for (int j = 0; j < Nb - numberOfShifts; j++)
		{
			state_type tmp = state[0][numberOfShifts];
			for (int i = 0; i < Nb - 1; i++)
			{
				state[i][numberOfShifts] = state[i + 1][numberOfShifts];
			}
			state[Nb - 1][numberOfShifts] = tmp;
		}
	}
}

void AES::AddRoundKey(state_type **state, w_type *w)
{
	for (int j = 0; j < Nb; j++)
	{
		for (int i = 0; i < Nb; i++)
		{
			state[j][i] = state[j][i] ^ w[i + Nb * j]; //"w" pseudo conversion to a 2-dimensional array
		}
	}
}

void AES::invMixColumns(state_type **state)
{
	state_type u;
	state_type v;

	for (int i = 0; i < 4; i++)
	{
		u = xtime(xtime(state[i][0] ^ state[i][2]));
		v = xtime(xtime(state[i][1] ^ state[i][3]));
		state[i][0] ^= u;
		state[i][1] ^= v;
		state[i][2] ^= u;
		state[i][3] ^= v;
	}

	state_type r[Nb];
	state_type a[Nb];
	state_type b[Nb];
	state_type h;

	for (int i = 0; i < Nb; i++)
	{
		memcpy(r, state[i], Nb * sizeof(state_type));

		//Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
		for (int c = 0; c < 4; c++)
		{
			a[c] = r[c];
			b[c] = (r[c] << 1) ^ (0x1B * (1 & (r[c] >> 7)));
		}

		r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

		memcpy(state[i], r, Nb * sizeof(state_type));
	}
}

void AES::ArrayTransformOneDim(state_type *in, state_type **state)
{
	for (int i = 0; i < Nb; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			state[i][j] = in[j + Nb * i];
		}
	}
}

void AES::ArrayTransformTwoDim(state_type *out, state_type **state)
{
	for (int i = 0; i < Nb; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			out[j + Nb * i] = state[i][j];
		}
	}
}

void AES::invCipher(state_type *in, state_type *out, w_type *w)
{
	state_type **state = (state_type **)malloc(Nb * sizeof(state_type *));

	for (int i = 0; i < Nb; i++)
	{
		state[i] = (state_type *)malloc(Nb * sizeof(state_type));
	}

	AES::ArrayTransformOneDim(in, state);

	AES::AddRoundKey(state, w + Nr * Nb * Nb);

	for (int round = (Nr - 1); round > 0; round--)
	{

		AES::invShiftRows(state);
		AES::invSubBytes(state);
		AES::AddRoundKey(state, (w + round * Nb * Nb));
		AES::invMixColumns(state);
	}

	AES::invSubBytes(state);
	AES::invShiftRows(state);
	AES::AddRoundKey(state, w);

	ArrayTransformTwoDim(out, state);
}