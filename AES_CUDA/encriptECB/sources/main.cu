#include "AES.h"

__global__
static void ecb_encrypt_kernel(state_type* in, state_type* out, w_type* key)
{
    encriptECB(in+threadIdx.x*16, out+threadIdx.x*16, key);
}

int main() {
	std::ifstream in_file;
	in_file.open("/home/silver/My-projects/CUDA/samples/0_Simple/project/AES_CUDA/encriptECB/data/plain.txt", std::ios::binary);
    std::size_t file_size = std::experimental::filesystem::file_size("/home/silver/My-projects/CUDA/samples/0_Simple/project/AES_CUDA/encriptECB/data/plain.txt");
    int padding = 16 - (file_size % 16);
    char plain[file_size+padding];
    char padding_char[3] = "  ";

	std::string text;
	if(!in_file.is_open())
	{
		std::cout<<"file not open\n";
	}

    in_file.read(plain, file_size);
	in_file.close();

    // fill padding with zeros
    for(int i=0;i<padding-1;i++)
    {
        plain[file_size+i] = 0;
    }
    plain[file_size+padding-1] = padding;

	uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
        0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
        0xf4 };


	state_type out[file_size+padding];

    uint8_t *key_gpu, *plain_gpu, *out_gpu;
    float elapsedTime, kernelTime;
    cudaEvent_t start, kernel_start, kernel_stop, stop; // pomiar czasu wykonania j?dra

    // for(int i=0; i< file_size+padding;i++)
    // {
    //     std::cout<<(int)plain[i]<<" ";

    // }
    // std::cout<<"\n";

    checkCudaErrors(cudaSetDevice(0));

    checkCudaErrors(cudaEventCreate(&start));
    checkCudaErrors(cudaEventCreate(&kernel_start));
    checkCudaErrors(cudaEventCreate(&kernel_stop));
    checkCudaErrors(cudaEventCreate(&stop));
    checkCudaErrors(cudaEventRecord(start, 0));
    w_type w[KEY_ROUND];
    keyExpansion(key, w);

    checkCudaErrors(cudaMalloc(&key_gpu, sizeof(uint8_t)*KEY_ROUND));
    checkCudaErrors(cudaMalloc(&out_gpu, sizeof(uint8_t)*(file_size+padding)));
    checkCudaErrors(cudaMalloc(&plain_gpu, sizeof(uint8_t)*(file_size+padding)));

    checkCudaErrors(cudaMemcpy(key_gpu, w, sizeof(uint8_t)*KEY_ROUND, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(plain_gpu, plain, sizeof(uint8_t)*(file_size+padding), cudaMemcpyHostToDevice));
    
    checkCudaErrors(cudaEventRecord(kernel_start, 0));
    ecb_encrypt_kernel<<<1, (file_size+padding)/16>>>(plain_gpu, out_gpu, key_gpu);
    checkCudaErrors(cudaGetLastError());
    checkCudaErrors(cudaEventRecord(kernel_stop, 0));

    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*(file_size+padding), cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaEventRecord(stop, 0));

    // for(int i=0; i< file_size+padding;i++)
    // {
    //     std::cout<<(int)out[i]<<" ";
    //     // itoa(out[i], plain[i], 10);
    // }
    
	std::ofstream out_file;
    out_file.open("/home/silver/My-projects/CUDA/samples/0_Simple/project/AES_CUDA/encriptECB/data/encrypted.txt", std::ios::binary);

    std::cout<<"\n"<<"padding is "<<padding_char[0]<<padding_char[1]<<", full file size is "<<file_size+padding<<"\n";
    // out_file.write(padding_char, 2);
    out_file.write((char *)out, file_size+padding);
    out_file.close();

    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventElapsedTime(&kernelTime, kernel_start, kernel_stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));

    printf("GPU time = %.3f ms\n", elapsedTime);
    printf("GPU kernel time = %.3f ms\n", kernelTime);

    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(plain_gpu));

    checkCudaErrors(cudaDeviceReset());
    return (0);
}