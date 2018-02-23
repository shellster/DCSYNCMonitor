#pragma once

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <vector>
#include <windows.h>

#include "event_log_template.h"
#include "misc_helpers.h"
#include "debug_print.h"

using namespace std;

bool install_event_log_source(const string &);
bool log_event_log_message(const string &, const WORD, const string &);
bool uninstall_event_log_source(const string &);
