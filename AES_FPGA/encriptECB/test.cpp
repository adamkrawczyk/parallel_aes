#include "AES.h"

#ifdef _WIN32

#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>

typedef LARGE_INTEGER app_timer_t;

#define timer(t_ptr) QueryPerformanceCounter(t_ptr)

void elapsed_time(app_timer_t start, app_timer_t stop,
                  double flop)
{
  double etime;
  LARGE_INTEGER clk_freq;
  QueryPerformanceFrequency(&clk_freq);
  etime = (stop.QuadPart - start.QuadPart) /
          (double) clk_freq.QuadPart;
  printf("CPU (total!) time = %.3f ms (%6.3f GFLOP/s)\n",
         etime * 1e3, 1e-9 * flop / etime);
}

#else

#include <time.h> /* requires linking with rt library
                     (command line option -lrt) */

typedef struct timespec app_timer_t;

#define timer(t_ptr) clock_gettime(CLOCK_MONOTONIC, t_ptr)

void elapsed_time(app_timer_t start, app_timer_t stop)
{
  double etime;
  etime = 1e+3 * (stop.tv_sec  - start.tv_sec ) +
          1e-6 * (stop.tv_nsec - start.tv_nsec);
  printf("CPU (total!) time = %.3f ms\n",
         etime);
}

#endif

int main() {
	app_timer_t start, stop;
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

		timer(&start);
	for(int i = 0; i < BLOCK_SIZE; i++)
	{
		encriptECB(plain+i*16, out+i*16, key);
	}

		timer(&stop);
	elapsed_time(start, stop);

	for (int i = 0; i < OUT_LEN*BLOCK_SIZE; i++) {
		printf("%02x ", (unsigned char) out[i]);
	}

	if (0 == memcmp((char*) out, (char*) right, 16*BLOCK_SIZE)) {
		printf("SUCCESS!\n");
	} else {
		printf("FAILURE!\n");
	}
}
