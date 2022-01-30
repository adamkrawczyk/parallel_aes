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

void AES::SubBytes(state_type **state)
{
	for (int i = 0; i < Nb; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			state[j][i] = sbox[state[j][i]];
		}
	}
}

void AES::ShiftRows(state_type **state)
{
	for (int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++)
	{
		for (int j = 0; j < numberOfShifts; j++)
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

void AES::MixColumns(state_type **state)
{

	state_type r[Nb];
	state_type a[Nb];
	state_type b[Nb];
	state_type h;

	for (int i = 0; i < Nb; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			r[j] = state[i][j];
		}

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

		for (int j = 0; j < Nb; j++)
		{
			state[i][j] = r[j];
		}
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

void AES::Cipher(state_type *in, state_type *out, w_type *w)
{
	state_type **state = (state_type **)malloc(Nb * sizeof(state_type *));

	for (int i = 0; i < Nb; i++)
	{
		state[i] = (state_type *)malloc(Nb * sizeof(state_type));
	}

	AES::ArrayTransformOneDim(in, state);

	AES::AddRoundKey(state, w);

	for (int round = 1; round <= Nr - 1; round++)
	{

		AES::SubBytes(state);
		AES::ShiftRows(state);
		AES::MixColumns(state);

		AES::AddRoundKey(state, (w + round * Nb * Nb));
	}

	AES::SubBytes(state);
	AES::ShiftRows(state);
	AES::AddRoundKey(state, (w + Nr * Nb * Nb));

	ArrayTransformTwoDim(out, state);
}