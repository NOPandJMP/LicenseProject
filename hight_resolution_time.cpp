#include "hight_resolution_time.h"


int accumulate_sleep_mks = 0;

auto code_delay_start = std::chrono::high_resolution_clock::now();
int code_delay = 0;


void macro_sleep_ms(register int real_sleep_ms)
{

	code_delay = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - code_delay_start).count();

	auto start = std::chrono::high_resolution_clock::now();

	std::this_thread::sleep_for(std::chrono::milliseconds(real_sleep_ms));
accumulate_sleep_mks = accumulate_sleep_mks % 1000;

	accumulate_sleep_mks += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count() - 1000 * real_sleep_ms + code_delay - 880;


code_delay_start = std::chrono::high_resolution_clock::now();
}

void zero_accumulate_time()
{
	accumulate_sleep_mks = 0;

}

void start_calculate_code_delay()
{
	code_delay_start = std::chrono::high_resolution_clock::now();
}

