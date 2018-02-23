#include "misc_helpers.h"

mutex alertlist_mutex;

void get_current_path_exe(string &path)
{
	vector<char> pathBuf;
	DWORD copied = 0;
	do {
		pathBuf.resize(pathBuf.size() + MAX_PATH);
		copied = GetModuleFileNameA(NULL, &pathBuf.at(0), (DWORD) pathBuf.size());
	} while (copied >= pathBuf.size());

	pathBuf.resize(copied);

	static string full_path(pathBuf.begin(), pathBuf.end());

	path = full_path;
	return;
}

void get_current_path(string &path)
{
	get_current_path_exe(path);

	size_t find = path.find_last_of("/\\");

	if(find != -1)
		path = path.substr(0, find);

	return;
}

void get_dc_list(vector<ip_addr> & list)
{
	string path;

	get_current_path(path);

	path.append("\\dc_ip_list.conf");

	ifstream infile(path);

	if (infile)
	{
		string ip;
		void * temp = malloc(sizeof(IN6_ADDR));
		in_addr * ipv4temp;
		in_addr6 * ipv6temp;
		char tempstring[INET6_ADDRSTRLEN];

		while (getline(infile, ip))
		{
			if (inet_pton(AF_INET, ip.c_str(), temp) == 1)
			{
				ipv4temp = (in_addr *) temp; 

				ip_addr new_ip;
				new_ip.type = AF_INET;

				//We run the ip throug inet_ntop just to normalize it;
				inet_ntop(AF_INET, (void *)ipv4temp, tempstring, INET6_ADDRSTRLEN);
				new_ip.address = string(tempstring);

				debug_print("DC IP FROM LIST: %s\n", new_ip.address.c_str());
				list.push_back(new_ip);
			}
			else if(inet_pton(AF_INET6, ip.c_str(), temp) == 1)
			{
				ipv6temp = (in6_addr *) temp;
				ip_addr new_ip;
				new_ip.type = AF_INET6;

				//We run the ip throug inet_ntop just to normalize it;
				inet_ntop(AF_INET6, (void *)ipv6temp, tempstring, INET6_ADDRSTRLEN);
				new_ip.address = string(tempstring);

				debug_print("DC IP FROM LIST: %s\n", new_ip.address.c_str());
				list.push_back(new_ip);
			}
			else
				debug_print("BAD DC IP FROM LIST: %s\n", ip.c_str());
		}

		free(temp);

		infile.close();
	}
}

bool is_from_valid_dc(vector<ip_addr> & list, ip_addr ip)
{
	if (list.size() == 0)
		return true; //No list so we are going to return true so we get a warning event only.
	
	for (ip_addr dc_ip : list)
	{
		if (ip.type == dc_ip.type) //both IPv4 or IPv6
		{
			if (dc_ip.address.compare(ip.address) == 0)
				return true;
		}
	}

	return false;
}

bool check_for_previous_alert(map<string, time_t> & alerts, ip_addr ip)
{
	time_t now;
	time(&now);

	lock_guard<mutex> lock(alertlist_mutex);

	//Erase any alert records that are outside the alert window
	for (auto alert = alerts.cbegin(); alert != alerts.cend();)
	{
		if (difftime(now, alert->second) > ALERTWINDOW)
			alert = alerts.erase(alert);
		else
			++alert;
	}

	if (alerts.find(ip.address.c_str()) == alerts.end())
	{
		alerts[ip.address] = now;
		return false;
	}

	return true;
}

bool is_elevated() 
{
	bool fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);

		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = (Elevation.TokenIsElevated != 0);
		}
	}

	if (hToken) {
		CloseHandle(hToken);
	}

	return fRet;
}