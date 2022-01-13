#include "AES.h"

void keyExpansion(w_type key[KEY_LEN], w_type w[KEY_ROUND]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	w_type temp[Nb];
#pragma HLS ARRAY_PARTITION variable=temp complete dim=1

	int i = 0;

	for(i = 0; i < Nb * Nk; i++)
	{
#pragma HLS PIPELINE rewind
		w[i] = key[i];
	}

	i = Nk;

	while (i < Nb * (Nr + 1)) {
#pragma HLS PIPELINE rewind
		for (int j = 0; j < 4; j++) {
			temp[j] = w[(i - 1) * 4 + j];
		}

		if (i % Nk == 0) {
			state_type tmp = temp[0];
			for (int j = 0; j < Nb - 1; j++) {
#pragma HLS PIPELINE rewind
				temp[j] = temp[j + 1];
			}

			temp[Nb - 1] = tmp;

			for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
				temp[j] = sbox[temp[j]];
			}

			temp[0] = temp[0] ^ Rcon[i / Nk]; // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)

		} else if (Nk > 6 && i % Nk == 4) {
			for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
				temp[j] = sbox[temp[j]];
			}
		}
		for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
			w[j + i * Nb] = w[(i - Nk) * Nb + j] ^ temp[j];
		}

		i = i + 1;
	}
}

void subBytes(state_type state[Nb][Nb]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	for (int i = 0; i < Nb; i++) {
#pragma HLS PIPELINE rewind
		for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
			state[j][i] = sbox[state[j][i]];
		}
	}
}

void shiftRows(state_type state[Nb][Nb]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	for (int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++) {
#pragma HLS PIPELINE rewind
		for (int j = 0; j < numberOfShifts; j++) {
#pragma HLS PIPELINE rewind
			state_type tmp = state[0][numberOfShifts];
			for (int i = 0; i < Nb - 1; i++) {
#pragma HLS PIPELINE rewind
				state[i][numberOfShifts] = state[i + 1][numberOfShifts];
			}
			state[Nb - 1][numberOfShifts] = tmp;
		}
	}
}

void addRoundKey(state_type state[Nb][Nb], w_type w[KEY_ROUND]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
		for (int i = 0; i < Nb; i++) {
#pragma HLS PIPELINE rewind
			state[j][i] = state[j][i] ^ w[i + Nb * j]; //"w" pseudo conversion to a 2-dimensional array
		}

	}
}

void mixColumns(state_type state[Nb][Nb]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	state_type r[Nb];
#pragma HLS ARRAY_PARTITION variable=r complete dim=1
	state_type a[Nb];
#pragma HLS ARRAY_PARTITION variable=a complete dim=1
	state_type b[Nb];
#pragma HLS ARRAY_PARTITION variable=b complete dim=1
	state_type h;

	for (int i = 0; i < Nb; i++) {
#pragma HLS PIPELINE rewind
		for(int j = 0; j < Nb; j++)
		{
#pragma HLS PIPELINE rewind
			r[j] = state[i][j];
		}

		//Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
		for (int c = 0; c < 4; c++) {
#pragma HLS PIPELINE rewind
			a[c] = r[c];
			b[c] = (r[c] << 1) ^ (0x1B * (1 & (r[c] >> 7)));
		}

		r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

		for(int j = 0; j < Nb; j++)
		{
#pragma HLS PIPELINE rewind
			state[i][j] = r[j];
		}

	}
}

void arrayTransformOneDim(state_type in[IN_LEN], state_type state[Nb][Nb]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	for (int i = 0; i < Nb; i++) {
#pragma HLS PIPELINE rewind
		for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
			state[i][j] = in[j + Nb * i];
		}
	}
}

void arrayTransformTwoDim(state_type out[OUT_LEN], state_type state[Nb][Nb]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	for (int i = 0; i < Nb; i++) {
#pragma HLS PIPELINE rewind
		for (int j = 0; j < Nb; j++) {
#pragma HLS PIPELINE rewind
			out[j + Nb * i] = state[i][j];
		}
	}
}

void cipher(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type w[KEY_ROUND]) {
#pragma HLS INLINE
#pragma HLS PIPELINE rewind
	state_type state[Nb][Nb];
#pragma HLS ARRAY_PARTITION variable=state complete dim=1

	arrayTransformOneDim(in, state);

	addRoundKey(state, w);

	for (int round = 1; round <= Nr - 1; round++) {
#pragma HLS PIPELINE rewind
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, (w + round * Nb * Nb));
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, (w + Nr * Nb * Nb));

	arrayTransformTwoDim(out, state);

}

void encriptECB(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type key[KEY_LEN]) {
#pragma HLS INTERFACE ap_ctrl_none port=return
#pragma HLS INTERFACE axis register both port=out
#pragma HLS ARRAY_RESHAPE variable=out complete dim=1
#pragma HLS INTERFACE axis register both port=key
#pragma HLS ARRAY_RESHAPE variable=key complete dim=1
#pragma HLS INTERFACE axis register both port=in
#pragma HLS ARRAY_RESHAPE variable=in complete dim=1
#pragma HLS PIPELINE rewind

	w_type w[KEY_ROUND];
#pragma HLS ARRAY_PARTITION variable=w complete dim=1
	keyExpansion(key, w);
	cipher(in, out, w);
}

