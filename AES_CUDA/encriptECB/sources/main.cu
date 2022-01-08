#include "AES.h"

__device__
void keyExpansion(w_type key[KEY_LEN], w_type w[KEY_ROUND]) {
	w_type temp[Nb];

	int i = 0;

	for(i = 0; i < Nb * Nk; i++)
	{
		w = key;
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
		for (int j = 0; j < Nb; j++) {
			w[j + i * Nb] = w[(i - Nk) * Nb + j] ^ temp[j];
		}

		i = i + 1;
	}
}

__device__
void subBytes(state_type state[Nb][Nb]) {
	for (int i = 0; i < Nb; i++) {
		for (int j = 0; j < Nb; j++) {
			state[j][i] = sbox[state[j][i]];
		}
	}
}

__device__
void shiftRows(state_type state[Nb][Nb]) {
	for (int numberOfShifts = 0; numberOfShifts < Nb; numberOfShifts++) {
		for (int j = 0; j < numberOfShifts; j++) {
			state_type tmp = state[0][numberOfShifts];
			for (int i = 0; i < Nb - 1; i++) {
				state[i][numberOfShifts] = state[i + 1][numberOfShifts];
			}
			state[Nb - 1][numberOfShifts] = tmp;
		}
	}
}

__device__
void addRoundKey(state_type state[Nb][Nb], w_type w[KEY_ROUND]) {
	for (int j = 0; j < Nb; j++) {
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

	for (int i = 0; i < Nb; i++) {
		for(int j = 0; j < Nb; j++)
		{
			r[j] = state[i][j];
		}

		//Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
		for (int c = 0; c < 4; c++) {
			a[c] = r[c];
			b[c] = (r[c] << 1) ^ (0x1B * (1 & (r[c] >> 7)));
		}

		r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

		for(int j = 0; j < Nb; j++)
		{
			state[i][j] = r[j];
		}

	}
}

__device__
void arrayTransformOneDim(state_type in[IN_LEN], state_type state[Nb][Nb]) {
	for (int i = 0; i < Nb; i++) {
		for (int j = 0; j < Nb; j++) {
			state[i][j] = in[j + Nb * i];
		}
	}
}

__device__
void arrayTransformTwoDim(state_type out[OUT_LEN], state_type state[Nb][Nb]) {
	for (int i = 0; i < Nb; i++) {
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

	for (int round = 1; round <= Nr - 1; round++) {
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

__device__
void encriptECB(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type key[KEY_LEN]) {
// #pragma HLS PIPELINE
	w_type w[KEY_ROUND];
	keyExpansion(key, w);
	cipher(in, out, w);
}

__global__
static void ecb_encrypt_kernel(state_type* in, state_type* out, w_type* key)
{
    printf("hello from thread %d\n", threadIdx.x);
    encriptECB(in, out, key);
}

int main() {

	int key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
			0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
			0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
			0xf4 };
	int right[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06,
			0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };

	int plain[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
			0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

	state_type out[OUT_LEN];

    int *key_gpu, *plain_gpu, *out_gpu;

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(int)*32));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(int)*16));
    checkCudaErrors(cudaMalloc(&plain_gpu, sizeof(int)*16));

    checkCudaErrors(cudaMemcpy(key_gpu, key, sizeof(int)*32, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(plain_gpu, plain, sizeof(int)*16, cudaMemcpyHostToDevice));
    
    ecb_encrypt_kernel<<<1, 1>>>(plain_gpu, out_gpu, key_gpu);
    checkCudaErrors(cudaGetLastError());
    
    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(int)*16, cudaMemcpyDeviceToHost));
	for (int i = 0; i < OUT_LEN; i++) {
		printf("%02x ", (unsigned char) out[i]);
	}

	if (0 == memcmp((char*) out, (char*) right, 16)) {
		printf("SUCCESS!\n");
		return (0);
	} else {
		printf("FAILURE!\n");
		return (1);
	}

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(plain_gpu));

    checkCudaErrors(cudaDeviceReset());
}