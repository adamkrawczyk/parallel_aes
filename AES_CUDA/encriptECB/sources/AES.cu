#include "AES.h"

void keyExpansion(w_type key[KEY_LEN], w_type w[KEY_ROUND]) {
	const uint8_t sbox[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d,
		0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
		0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
		0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a,
		0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
		0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
		0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f,
		0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
		0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
		0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a,
		0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
		0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
		0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66,
		0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
		0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
		0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

	const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
			0x1b, 0x36 };

	w_type temp[Nb];

	int i = 0;

	for(i = 0; i < Nb * Nk; i++)
	{
		w[i] = key[i];
	}

	i = Nk;

	while (i < Nb * (Nr + 1)) {
		for (int j = 0; j < 4; j++) {
			temp[j] = w[(i - 1) * 4 + j];
		}

		if (i % Nk == 0) {
			state_type tmp = temp[0];
			for (int j = 0; j < Nb - 1; j++) {
				temp[j] = temp[j + 1];
			}

			temp[Nb - 1] = tmp;

			for (int j = 0; j < Nb; j++) {
				temp[j] = sbox[temp[j]];
			}

			temp[0] = temp[0] ^ Rcon[i / Nk]; // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)

		} else if (Nk > 6 && i % Nk == 4) {
			for (int j = 0; j < Nb; j++) {
				temp[j] = sbox[temp[j]];
			}
		}

        // __syncthreads();
		for (int j = 0; j < Nb; j++) {
			w[j + i * Nb] = w[(i - Nk) * Nb + j] ^ temp[j];
		}

		i = i + 1;
	}
}

__device__
void subBytes(state_type state[Nb][Nb]) {
	#pragma unroll
	for (int i = 0; i < Nb; i++) {
		#pragma unroll
		for (int j = 0; j < Nb; j++) {
			state[j][i] = sbox[state[j][i]];
		}
	}
}

__device__
void shiftRows(state_type state[Nb][Nb]) {
	#pragma unroll
	for (int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++) {
		#pragma unroll
		for (int j = 0; j < numberOfShifts; j++) {
			state_type tmp = state[0][numberOfShifts];
			#pragma unroll
			for (int i = 0; i < Nb - 1; i++) {
				state[i][numberOfShifts] = state[i + 1][numberOfShifts];
			}
			state[Nb - 1][numberOfShifts] = tmp;
		}
	}
}

__device__
void addRoundKey(state_type state[Nb][Nb], w_type w[KEY_ROUND]) {
	#pragma unroll
	for (int j = 0; j < Nb; j++) {
		#pragma unroll
		for (int i = 0; i < Nb; i++) {
			state[j][i] = state[j][i] ^ w[i + Nb * j]; //"w" pseudo conversion to a 2-dimensional array
		}

	}
}

__device__
void mixColumns(state_type state[Nb][Nb]) {

	state_type r[Nb];
	state_type a[Nb];
	state_type b[Nb];
	// state_type h;

	#pragma unroll
	for (int i = 0; i < Nb; i++) {
		#pragma unroll
		for(int j = 0; j < Nb; j++)
		{
            r[j] = state[i][j];
		}
        // printf("r: %d, %d, %d, %d,\n", r[0], r[1], r[2], r[3]);

		//Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
		#pragma unroll
		for (int c = 0; c < 4; c++) {
			a[c] = r[c];
			b[c] = (r[c] << 1) ^ (0x1B * (1 & (r[c] >> 7)));
            // printf("a= %d, b= %d\n", a[c], b[c]);
		}

		r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

        // printf("r_list: %d, %d, %d, %d\n", r[0], r[1], r[2], r[3]);
		#pragma unroll
		for(int j = 0; j < Nb; j++)
		{
            // printf("mixColumns: %d\n", r[j]);
			state[i][j] = r[j];
		}
        // printf("next i\n");
        // printf("state: ");
        // for (int k = 0; k<Nb; k++)
        // {
        //     for (int l =0; l < Nb; l++)
        //     {
        //         printf("%d ", state[k][l]);
        //     }
        // }
        // printf("\n");

	}
}

__device__
void arrayTransformOneDim(state_type in[IN_LEN], state_type state[Nb][Nb]) {
	#pragma unroll
	for (int i = 0; i < Nb; i++) {
		#pragma unroll
		for (int j = 0; j < Nb; j++) {
			state[i][j] = in[j + Nb * i];
		}
	}
}

__device__
void arrayTransformTwoDim(state_type out[OUT_LEN], state_type state[Nb][Nb]) {
	#pragma unroll
	for (int i = 0; i < Nb; i++) {
		#pragma unroll
		for (int j = 0; j < Nb; j++) {
			out[j + Nb * i] = state[i][j];
		}
	}
}

__device__
void cipher(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type w[KEY_ROUND]) {
	state_type state[Nb][Nb];

	arrayTransformOneDim(in, state);
    
    
	addRoundKey(state, w);


    #pragma unroll
	for (int round = 1; round <= Nr - 1; round++) {
		subBytes(state);
		shiftRows(state);
        // printf("state: ");
        // for (int i = 0; i<Nb; i++)
        // {
        //     for (int j =0; j < Nb; j++)
        //     {
        //         printf("%d ", state[i][j]);
        //     }
        // }
        // printf("\n");
		mixColumns(state);
		addRoundKey(state, (w + round * Nb * Nb));
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, (w + Nr * Nb * Nb));

	arrayTransformTwoDim(out, state);

    // printf(" out: ");
    // for (int i = 0; i<Nb*Nb; i++)
	// {
    //     printf("%d ", out[i]);
	// }
    // printf("\n");

}

__device__
void encriptECB(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type w[KEY_ROUND]) {
// #pragma HLS PIPELINE
	// w_type w[KEY_ROUND];
	// keyExpansion(key, w);
    // printf("Expanded key: ");
    // for (int i = 0; i<KEY_ROUND; i++)
	// {
    //     printf("%d ", w[i]);
	// }
	// printf("\n");
	cipher(in, out, w);
}
