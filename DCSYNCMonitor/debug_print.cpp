#include "debug_print.h"

mutex debug_print_mutex;

void debug_print(const char* format, ...) {
#ifdef _DEBUG
	lock_guard<mutex> lock(debug_print_mutex);
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	fflush(stderr);
	va_end(args);
#endif
}