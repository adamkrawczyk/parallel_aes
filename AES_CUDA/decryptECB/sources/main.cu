#include "AES.h"
#include <stdio.h>

__global__
void decryptECB(state_type in[IN_LEN], state_type out[OUT_LEN],
		w_type key[KEY_LEN], int size) {
	w_type w[KEY_ROUND];
	keyExpansion(key, w);
    int idx = threadIdx.x+blockIdx.x*blockDim.x;
    if (idx < size)
    {

	    invCipher(in+idx*16, out+idx*16, w);
    }
}

int main() {
    std::ifstream in_file;
	in_file.open("/home/silver/My-projects/CUDA/samples/0_Simple/aes_project/AES_CUDA/decryptECB/data/encrypted.txt", std::ios::binary);
    std::size_t file_size = std::experimental::filesystem::file_size("/home/silver/My-projects/CUDA/samples/0_Simple/aes_project/AES_CUDA/decryptECB/data/encrypted.txt");
    // int padding = 16-(file_size % 16);
    // std::cout<<"padding is "<<padding<<"\n";
    char encrypted[file_size];
    int N = file_size/16;

	std::string text;
	if(!in_file.is_open())
	{
		std::cout<<"file not open\n";
	}

    std::cout<<"file size: "<<file_size<<"\n";
    in_file.read(encrypted, file_size);
	in_file.close();

    // for(int i = 0; i<padding;i++)
    // {
    //     encrypted[file_size+i] = ' ';
    // }
    // uint8_t encrypted[] = {140, 99, 39, 200, 100, 130, 179, 140, 106, 210, 92, 170, 150, 241, 255, 105};

	uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
			0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
			0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
			0xf4 };

	state_type out[file_size];

    uint8_t *key_gpu, *encrypted_gpu, *out_gpu;
    float elapsedTime;
    cudaEvent_t start, stop; // pomiar czasu wykonania j?dra

    // int pom;
    for(int i=0;i<file_size;i++)
        
        std::cout<<(int)encrypted[i]<<" ";
    std::cout<<"\n";

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaEventCreate(&start));
    checkCudaErrors(cudaEventCreate(&stop));
    checkCudaErrors(cudaEventRecord(start, 0));
    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(uint8_t)*32));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(uint8_t)*(file_size)));
    checkCudaErrors(cudaMalloc(&encrypted_gpu, sizeof(uint8_t)*(file_size)));

    checkCudaErrors(cudaMemcpy(key_gpu, key, sizeof(uint8_t)*32, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(encrypted_gpu, encrypted, sizeof(uint8_t)*(file_size), cudaMemcpyHostToDevice));

	decryptECB<<<(N+63)/64, 64>>>(encrypted_gpu, out_gpu, key_gpu, N);

    checkCudaErrors(cudaGetLastError());
    
    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*(file_size), cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaEventRecord(stop, 0));

    for(int i=0;i<file_size;i++)
    {

        std::cout<<(char)out[i]<<" ";
        // itoa(out[i], encrypted[i], 10);
    }

    std::cout<<"\n";

    int padding = (int)out[file_size-1];
    std::cout<<"padding is "<<padding<<"\n";
    std::ofstream out_file;
    out_file.open("/home/silver/My-projects/CUDA/samples/0_Simple/aes_project/AES_CUDA/decryptECB/data/plain.txt", std::ios::binary);
    out_file.write((char *)out, file_size-padding);
    out_file.close();
    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));

    printf("GPU (kernel) time = %.3f ms\n", elapsedTime);

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(out_gpu));
    checkCudaErrors(cudaFree(encrypted_gpu));

    checkCudaErrors(cudaDeviceReset());
}
