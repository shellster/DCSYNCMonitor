#include "event_log.h"

//With guidance from: https://stackoverflow.com/questions/8559222/write-an-event-to-the-event-viewer

bool install_event_log_source(const string &name)
{
	const string key_path("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + name);

	HKEY key;

	DWORD last_error = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		key_path.c_str(),
		0,
		0,
		REG_OPTION_NON_VOLATILE,
		KEY_SET_VALUE,
		0,
		&key,
		0);

	if (ERROR_SUCCESS == last_error)
	{
		DWORD last_error;
		string exe_path;

		get_current_path_exe(exe_path);

		const DWORD types_supported = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
		
		last_error = RegSetValueExA(key, "EventMessageFile", 0, REG_SZ, (BYTE *) exe_path.c_str(), (DWORD) exe_path.length());

		if (ERROR_SUCCESS == last_error)
		{
			last_error = RegSetValueEx(key, L"TypesSupported", 0, REG_DWORD, (LPBYTE)&types_supported, sizeof(types_supported));
			
			RegCloseKey(key);
			return true;
		}
		else
		{
			debug_print("Failed to install source values: %d\n", last_error);
			RegCloseKey(key);
			return false;
		}
		
	}
	else
	{
		debug_print("Failed to install source: %d\n", last_error);
		return false;
	}
}

bool log_event_log_message(const string &message, const WORD type, const string &name)
{
	DWORD event_id;

	switch (type)
	{
	case EVENTLOG_ERROR_TYPE:
		event_id = MSG_ERROR_1;
		break;
	case EVENTLOG_WARNING_TYPE:
		event_id = MSG_WARNING_1;
		break;
	case EVENTLOG_INFORMATION_TYPE:
		event_id = MSG_INFO_1;
		break;
	default:
		debug_print("Unrecognised type: %d\n", type);
		event_id = MSG_INFO_1;
		break;
	}

	HANDLE h_event_log = RegisterEventSourceA(0, name.c_str());

	if (0 == h_event_log)
	{
		debug_print("Failed open source '%s': %d\n", name, GetLastError());
		return false;
	}
	else
	{
		LPCSTR message_cstr = message.c_str();

		if (FALSE == ReportEventA(h_event_log, type, 0, event_id, 0, 1, 0, &message_cstr, 0))
		{
			debug_print("Failed to write message: %d\n", GetLastError());
			return false;
		}

		DeregisterEventSource(h_event_log);
		return true;
	}
}

bool uninstall_event_log_source(const string &name)
{
	const string key_path("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + name);

	DWORD last_error = RegDeleteKeyA(HKEY_LOCAL_MACHINE, key_path.c_str());

	if (ERROR_SUCCESS == last_error)
		return true;
	else
	{
		debug_print("Failed to uninstall source: %d\n", last_error);
		return false;
	}
}