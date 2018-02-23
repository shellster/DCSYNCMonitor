#include "DCSYNCMonitorService.h"

DCSYNCMonitorService::DCSYNCMonitorService(PWSTR pszServiceName,  BOOL fCanStop, BOOL fCanShutdown, BOOL fCanPauseContinue): CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue){}
DCSYNCMonitorService::~DCSYNCMonitorService(void){}

void DCSYNCMonitorService::OnStart(DWORD dwArgc, PWSTR *lpszArgv)
{
	mainThread = thread(start_monitoring);
}

void DCSYNCMonitorService::OnStop()
{
	end_monitoring();
	mainThread.join();
}

void DCSYNCMonitorService::OnShutdown()
{
	end_monitoring();
	mainThread.join();
}