
#include <iostream>
#include "Macros.h"


void HEMLOC()
{
	start_calculate_code_delay();
	timeBeginPeriod(1);

	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(30);
	mousemove(0, 4);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	mousemove(0, -18);
	if (should_stop) { zero_accumulation(); zero_accumulate_time(); timeEndPeriod(1); return; }
	macro_sleep_ms(300);


	while (!should_stop)Sleep(1);
	zero_accumulation();
	timeEndPeriod(1);
	return;


}