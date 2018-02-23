#pragma once

#include<vector>
#include<thread>
#include <iostream>
#include <mutex>
#include <fstream>
#include <string>
#include "pcap.h"

#include "thread_helper.h"
#include "packet_dissector.h"
#include "debug_print.h"
#include "event_log.h"
#include "misc_helpers.h"

#define PCAP_NETMASK_UNKNOWN 0xffffffff

using namespace std;

void sniff_interface(pcap_if_t *d);
void end_monitoring();
bool start_monitoring();