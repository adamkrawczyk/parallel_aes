#include "AES.h"

__global__
static void ecb_encrypt_kernel(state_type* in, state_type* out, w_type* key)
{

    // printf("hello from thread %d\n", threadIdx.x);
    encriptECB(in+threadIdx.x*16, out+threadIdx.x*16, key);
}

int main() {
	std::ifstream in_file;
	in_file.open("./../data/in_str.txt", std::ios::binary);
    std::size_t file_size = std::experimental::filesystem::file_size("./../data/in_str.txt");
    int padding = file_size % 16;
    char plain[file_size+padding];

	std::string text;
	if(!in_file.is_open())
	{
		std::cout<<"file not open\n";
	}

    in_file.read(plain, file_size);
	in_file.close();

	uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
        0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
        0xf4 };
    // uint8_t right_base[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06,
    //     0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};
    // uint8_t plain_base[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
    //     0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    // uint8_t right[file_size+padding]; 

    // uint8_t plain[file_size+padding]; 

    // for (int i = 0; i < BLOCK_SIZE; i++)
    // {
    //     memcpy(right+i*16*sizeof(uint8_t), right_base, 16*sizeof(uint8_t));
    //     memcpy(plain+i*16*sizeof(uint8_t), plain_base, 16*sizeof(uint8_t));
    // }



	state_type out[file_size+padding];

    uint8_t *key_gpu, *plain_gpu, *out_gpu;
    float elapsedTime;
    cudaEvent_t start, stop; // pomiar czasu wykonania j?dra

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaEventCreate(&start));
    checkCudaErrors(cudaEventCreate(&stop));
    checkCudaErrors(cudaEventRecord(start, 0));
    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(uint8_t)*32));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(uint8_t)*(file_size+padding)));
    checkCudaErrors(cudaMalloc(&plain_gpu, sizeof(uint8_t)*(file_size+padding)));

    checkCudaErrors(cudaMemcpy(key_gpu, key, sizeof(uint8_t)*32, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(plain_gpu, plain, sizeof(uint8_t)*(file_size+padding), cudaMemcpyHostToDevice));
    
    ecb_encrypt_kernel<<<1, 1/*file_size/16*/>>>(plain_gpu, out_gpu, key_gpu);
    checkCudaErrors(cudaGetLastError());
    
    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*(file_size+padding), cudaMemcpyDeviceToHost));

	std::ofstream out_file;
    out_file.open("./../data/out_str.txt", std::ios::binary);
    out_file.write((char *)out, file_size);
    out_file.close();

    checkCudaErrors(cudaEventRecord(stop, 0));
    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));


	// for (int i = 0; i < OUT_LEN*3; i++) {
	// 	printf("%02x ", (unsigned char) out[i]);
	// }

	// if (0 == memcmp((char*) out, (char*) right, 16*BLOCK_SIZE)) {
	// 	printf("SUCCESS!\n");
	// } else {
	// 	printf("FAILURE!\n");
	// }

    printf("GPU (kernel) time = %.3f ms\n", elapsedTime);

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(plain_gpu));

    checkCudaErrors(cudaDeviceReset());
    return (0);
}