#include "AES.h"

__global__
static void ecb_encrypt_kernel(state_type* in, state_type* out, w_type* key, int size)
{
    int idx = threadIdx.x+blockIdx.x*blockDim.x;
    if (idx < size){

        encriptECB(in+idx*16, out+idx*16, key);
    }
}

int main() {
	std::ifstream in_file;
    char in_file_path[] = "/home/silver/My-projects/CUDA/samples/0_Simple/aes_project/AES_CUDA/encriptECB/data/sw.png";
	in_file.open(in_file_path, std::ios::binary);
    std::size_t file_size = std::experimental::filesystem::file_size(in_file_path);
    int padding = 16 - (file_size % 16) + 16;
    char plain[file_size+padding];
    int N = (file_size+padding)/16;

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

    ecb_encrypt_kernel<<<(N+255)/256, 256>>>(plain_gpu, out_gpu, key_gpu, N);
    checkCudaErrors(cudaGetLastError());
    checkCudaErrors(cudaEventRecord(kernel_stop, 0));

    checkCudaErrors(cudaMemcpy(out, out_gpu, sizeof(uint8_t)*(file_size+padding), cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaEventRecord(stop, 0));

	std::ofstream out_file;
    out_file.open("/home/silver/My-projects/CUDA/samples/0_Simple/aes_project/AES_CUDA/encriptECB/data/encrypted.txt", std::ios::binary);

    std::cout<<"\n"<<"full file size is "<<file_size+padding<<"\n";
    out_file.write((char *)out, file_size+padding);
    out_file.close();

    checkCudaErrors(cudaEventSynchronize(stop));
    checkCudaErrors(cudaEventElapsedTime(&elapsedTime, start, stop));
    checkCudaErrors(cudaEventElapsedTime(&kernelTime, kernel_start, kernel_stop));
    checkCudaErrors(cudaEventDestroy(start));
    checkCudaErrors(cudaEventDestroy(stop));

    printf("GPU time = %.3f ms\n", elapsedTime);
    printf("GPU kernel time = %.3f ms\n", kernelTime);
    float throughput = 1000/kernelTime*N*16.0f*8.0f/(1024.0f*1024.0f*1024.0f);
    printf("Throughput = %.3f Gb/s\n", throughput);


    checkCudaErrors(cudaFree(key_gpu));
    checkCudaErrors(cudaFree(plain_gpu));

    checkCudaErrors(cudaDeviceReset());
    return (0);
}