#pragma once

#define WIN32_LEAN_AND_MEAN

#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <fstream>
#include <time.h>
#include <Ws2tcpip.h>
#include <windows.h>

#include "debug_print.h"

#define ALERTWINDOW 5 * 60 //5 Minutes alert window for DC SYNC events from same IP

using namespace std;

struct ip_addr{
	ADDRESS_FAMILY type;
	string address;
};

void get_current_path_exe(string &);
void get_current_path(string &);
void get_dc_list(vector<ip_addr> &);
bool is_from_valid_dc(vector<ip_addr> &, ip_addr);
bool check_for_previous_alert(map<string, time_t> &, ip_addr);
bool is_elevated();
