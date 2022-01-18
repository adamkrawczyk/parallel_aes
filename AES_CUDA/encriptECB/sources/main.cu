#include "AES.h"


// __device__
// void keyExpansion(w_type key[KEY_LEN], w_type w[KEY_ROUND]) {
// 	w_type temp[Nb];

// 	int i = 0;

// 	for(i = 0; i < Nb * Nk; i++)
// 	{
// 		w[i] = key[i];
// 	}

// 	i = Nk;

// 	while (i < Nb * (Nr + 1)) {
// 		for (int j = 0; j < 4; j++) {
// 			temp[j] = w[(i - 1) * 4 + j];
// 		}

// 		if (i % Nk == 0) {
// 			state_type tmp = temp[0];
// 			for (int j = 0; j < Nb - 1; j++) {
// 				temp[j] = temp[j + 1];
// 			}

// 			temp[Nb - 1] = tmp;

// 			for (int j = 0; j < Nb; j++) {
// 				temp[j] = sbox[temp[j]];
// 			}

// 			temp[0] = temp[0] ^ Rcon[i / Nk]; // only the xor operation with Rcon for temp[0] (not as in the documentation) because we are operating on 4 x characters (not 32 bits)

// 		} else if (Nk > 6 && i % Nk == 4) {
// 			for (int j = 0; j < Nb; j++) {
// 				temp[j] = sbox[temp[j]];
// 			}
// 		}

//         __syncthreads();
// 		for (int j = 0; j < Nb; j++) {
// 			w[j + i * Nb] = w[(i - Nk) * Nb + j] ^ temp[j];
// 		}

// 		i = i + 1;
// 	}
// }

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
        // printf("r: %d, %d, %d, %d,\n", r[0], r[1], r[2], r[3]);

		//Rijndael_MixColumns https://en.wikipedia.org/wiki/Rijndael_MixColumns
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
		w_type key[KEY_LEN]) {
// #pragma HLS PIPELINE
	w_type w[KEY_ROUND];
	keyExpansion(key, w);
    // printf("Expanded key: ");
    // for (int i = 0; i<KEY_ROUND; i++)
	// {
    //     printf("%d ", w[i]);
	// }
	// printf("\n");
	cipher(in, out, w);
}

__global__
static void ecb_encrypt_kernel(state_type* in, state_type* out, w_type* key)
{

    // printf("hello from thread %d\n", threadIdx.x);
    encriptECB(in+threadIdx.x*16, out+threadIdx.x*16, key);
}

int main() {

	uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
        0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
        0xf4 };
    uint8_t right_base[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06,
        0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};
    uint8_t plain_base[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
        0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t right[16*BLOCK_SIZE]; 

    uint8_t plain[16*BLOCK_SIZE]; 

    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        memcpy(right+i*16*sizeof(uint8_t), right_base, 16*sizeof(uint8_t));
        memcpy(plain+i*16*sizeof(uint8_t), plain_base, 16*sizeof(uint8_t));
    }



	state_type out[OUT_LEN*BLOCK_SIZE];

    uint8_t *key_gpu, *plain_gpu, *out_gpu;
    float elapsedTime;
    cudaEvent_t start, stop; // pomiar czasu wykonania j?dra

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaEventCreate(&start));
    checkCudaErrors(cudaEventCreate(&stop));
    checkCudaErrors(cudaEventRecord(start, 0));
    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(uint8_t)*32));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(uint8_t)*16*BLOCK_SIZE));
    checkCudaErrors(cudaMalloc(&plain_gpu, sizeof(uint8_t)*16*BLOCK_SIZE));

    checkCudaErrors(cudaMemcpy(key_gpu, key, sizeof(uint8_t)*32, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(plain_gpu, plain, sizeof(uint8_t)*16*BLOCK_SIZE, cudaMemcpyHostToDevice));
    
    ecb_encrypt_kernel<<<1, BLOCK_SIZE>>>(plain_gpu, out_gpu, key_gpu);
    checkCudaErrors(cudaGetLastError());
    
    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*16*BLOCK_SIZE, cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaEventRecord(stop, 0));
    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));


	for (int i = 0; i < OUT_LEN*3; i++) {
		printf("%02x ", (unsigned char) out[i]);
	}

	if (0 == memcmp((char*) out, (char*) right, 16*BLOCK_SIZE)) {
		printf("SUCCESS!\n");
	} else {
		printf("FAILURE!\n");
	}

    printf("GPU (kernel) time = %.3f ms\n", elapsedTime);

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(plain_gpu));

    checkCudaErrors(cudaDeviceReset());
    return (0);
}