#include "AES.h"
#include <stdio.h>

__global__
void decryptECB(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type key[KEY_LEN]) {
    for (int i=0; i< IN_LEN;i++)
        printf("%02x ", (unsigned char) in[i]);

    printf("\n");
	w_type w[KEY_ROUND];
	keyExpansion(key, w);
	invCipher(in, out, w);
}

int main() {

	uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
			0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
			0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
			0xf4 };
	uint8_t right[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06,
			0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };

	uint8_t plain[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
			0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

	state_type out[OUT_LEN];

    uint8_t *key_gpu, *right_gpu, *out_gpu;
    float elapsedTime;
    cudaEvent_t start, stop; // pomiar czasu wykonania j?dra

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaEventCreate(&start));
    checkCudaErrors(cudaEventCreate(&stop));
    checkCudaErrors(cudaEventRecord(start, 0));
    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(uint8_t)*32));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(uint8_t)*(16)));
    checkCudaErrors(cudaMalloc(&right_gpu, sizeof(uint8_t)*(16)));

    checkCudaErrors(cudaMemcpy(key_gpu, key, sizeof(uint8_t)*32, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(right_gpu, right, sizeof(uint8_t)*(16), cudaMemcpyHostToDevice));

	decryptECB<<<1, 1>>>(right_gpu, out_gpu, key_gpu);

    checkCudaErrors(cudaGetLastError());
    
    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*(16), cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaEventRecord(stop, 0));
    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));

    printf("GPU (kernel) time = %.3f ms\n", elapsedTime);

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(out_gpu));
    checkCudaErrors(cudaFree(right_gpu));

    checkCudaErrors(cudaDeviceReset());

	for (int i = 0; i < OUT_LEN; i++) {
		printf("%02x ", (unsigned char) out[i]);
	}

	if (0 == memcmp((char*) out, (char*) plain, 16)) {
		printf("SUCCESS!\n");
		return (0);
	} else {
		printf("FAILURE!\n");
		return (1);
	}
}
