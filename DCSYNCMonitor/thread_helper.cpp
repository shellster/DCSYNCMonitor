#include "thread_helper.h"

void join_all(vector<thread>& v)
{
	for_each(v.begin(), v.end(), [](thread & t) {t.join(); });
}