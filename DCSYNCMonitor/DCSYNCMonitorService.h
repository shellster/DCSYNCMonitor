/****************************** Module Header ******************************\
* Module Name:  SampleService.h
* Project:      CppWindowsService
* Copyright (c) Microsoft Corporation.
* 
* Provides a sample service class that derives from the service base class - 
* CServiceBase. The sample service logs the service start and stop 
* information to the Application event log, and shows how to run the main 
* function of the service in a thread pool worker thread.
* 
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
* All other rights reserved.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

#pragma once

#include <thread>

using namespace std;

#include "ServiceBase.h"
#include "monitor.h"


class DCSYNCMonitorService : public CServiceBase
{
public:

	DCSYNCMonitorService(PWSTR pszServiceName,
        BOOL fCanStop = TRUE, 
        BOOL fCanShutdown = TRUE,
        BOOL fCanPauseContinue = FALSE);
    virtual ~DCSYNCMonitorService(void);

protected:
    virtual void OnStart(DWORD dwArgc, PWSTR *pszArgv);
	virtual void OnStop();
    virtual void OnShutdown();
private:

	thread mainThread;
};