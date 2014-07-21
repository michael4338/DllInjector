/****************************** Module Header ******************************\
* Module Name:  SampleService.cpp
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

#pragma region Includes
#include "SampleService.h"
#include "ThreadPool.h"
#include <tchar.h>  
#include <vector>
#include <string>
#include <windows.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#pragma endregion

#pragma comment(lib, "advapi32.lib")
FILE *stream;

int PrintModules( DWORD processID )
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf( "\nProcess ID: %u\n", processID );
	fprintf(stream, "Process ID: %u\n", processID);

    // Get a handle to the process.

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, processID );
    if (NULL == hProcess)
        return 1;

   // Get a list of all the modules in this process.

    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            wchar_t szModName[MAX_PATH];

            // Get the full path to the module's file.

            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
                                      sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.

               printf( "\t%s (0x%08X)\n", szModName, hMods[i] );
			   fprintf(stream, "\t%ls (0x%08X)\n", szModName, hMods[i]);
            }
        }
    }
    
    // Release the handle to the process.

    CloseHandle( hProcess );

    return 0;
}

void printlog(const char* buf)
{
}

int AddPrivilege() 
{ 
	HANDLE hToken; 
	TOKEN_PRIVILEGES tp; 
	LUID Luid; 

	if (!OpenProcessToken(GetCurrentProcess(), 
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, 
		&hToken)) 
	{ 
		printf("OpenProcessToken error.n"); 
		return 1; 
	} 

	if (!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid)) 
	{ 
		printf("LookupPrivilegeValue error.n"); 
		fprintf(stream, "LookupPrivilegeValue error%d\n", GetLastError());
		return 1; 
	} 

	tp.PrivilegeCount = 1; 
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	tp.Privileges[0].Luid = Luid; 

	if (!AdjustTokenPrivileges(hToken, 
		0, 
		&tp, 
		sizeof(TOKEN_PRIVILEGES), 
		NULL, 
		NULL)) 
	{ 
		printf("AdjustTokenPrivileges error.n"); 
		fprintf(stream, "AdjustTokenPrivileges error%d\n", GetLastError());
		return 1; 
	} 

	return 0; 
} 


BOOL EnablePrivilege()

{

    HANDLE hToken = NULL;

    BOOL bFlag = FALSE;

          

    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))

    {

        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount = 1;

        if (!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid))//

        {

            CloseHandle(hToken);

            return FALSE;

        }

        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken ,FALSE ,&tp, sizeof(tp), NULL, NULL))

        {

            printf("change previlege failed\n");
			fprintf(stream, "change previlege failed\n");
            return FALSE;

        }

    }

    CloseHandle(hToken);

    return TRUE;

}

BOOL IsLaterNT()

{

    OSVERSIONINFO osvi;

    ZeroMemory(&osvi,sizeof(OSVERSIONINFO));

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

          

    GetVersionEx(&osvi);

    if (osvi.dwMajorVersion >= 6)

    {

        return TRUE;

    }

    return FALSE;

}


typedef DWORD (WINAPI *PFNTCREATETHREADEX)

(

        PHANDLE                 ThreadHandle,       

        ACCESS_MASK             DesiredAccess,      

        LPVOID                  ObjectAttributes,       

        HANDLE                  ProcessHandle,      

        LPTHREAD_START_ROUTINE  lpStartAddress,     

        LPVOID                  lpParameter,        

        BOOL                    CreateSuspended,        

        DWORD                   dwStackSize,        

        DWORD                   dw1,     

        DWORD                   dw2,     

        LPVOID                  Unknown

);

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE  lpThreadProc, LPVOID lpDllName )

{

    HANDLE hThread = NULL;

    FARPROC pFunc = NULL;
	/*
    if (IsLaterNT())

    {

        pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

        if (pFunc == NULL)

        {

            printf("Get NtCreateThreadEx Address failed\n");
			fprintf(stream, "Get NtCreateThreadEx Address failed\n");
            return FALSE;

        }

        ((PFNTCREATETHREADEX)pFunc)(&hThread,    

            0x1FFFFF,    

            NULL,    

            hProcess,    

            lpThreadProc,    

            lpDllName,    

            FALSE,    

            NULL,    

            NULL,    

            NULL,    

            NULL);

     

        if (hThread == NULL)

        {

            printf("call NtCreateThreadEx failed %d\n", GetLastError());
			fprintf(stream, "call NtCreateThreadEx failed %d\n", GetLastError());
            return FALSE;

        }

     

    }

    else

    {
		*/
        hThread = CreateRemoteThread(hProcess, NULL, NULL, lpThreadProc, lpDllName, 0, NULL);

        if(hThread == NULL)

        {
			fprintf(stream, "call CreateRemoteThread failed %d\n", GetLastError());
            return FALSE;

        }

    //}

    if (WAIT_TIMEOUT == WaitForSingleObject(hThread, INFINITE))

    {

        printf("wait timeout\n");

        return FALSE;

    }

    CloseHandle(hThread);

    return TRUE;

}


BOOL CreateMyDACL(SECURITY_ATTRIBUTES * pSA)
{
	TCHAR * szSD =  TEXT("(A;OICI;GRGWGX;;;AU)");                                      

	if (NULL == pSA)
		return FALSE;

     return ConvertStringSecurityDescriptorToSecurityDescriptor(
                szSD,
                SDDL_REVISION_1,
                &(pSA->lpSecurityDescriptor),
                NULL);
}


int ServiceFunction()
{
	fopen_s(&stream, "E:\\Detours\\DllInjector\\log.txt", "a+");

	fprintf(stream, "ServiceFunction starting now\n");

    char* buffer = "E:\\Detours\\DllInjector\\DetoursDll.dll";
    /*
     * Get process handle passing in the process ID.
     */
    int procID = 49136;

	// EnablePrivilege();
	AddPrivilege();
	PrintModules(49136);
	// getchar();
	// return 0;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if(process == NULL) {
        printf("Error: the specified process couldn't be found with error %d.\n", GetLastError());
		fprintf(stream, "Error: the specified process couldn't be found with error %d.\n", GetLastError());
		// return -1;
    }
    /*
     * Get address of the LoadLibrary function.
     */
    LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if(addr == NULL) {
        printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
		fprintf(stream, "Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
    }
    /*
     * Allocate new memory region inside the process's address space.
     */
    LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(arg == NULL) {
        printf("Error: the memory could not be allocated inside the chosen process.\n");
		fprintf(stream, "Error: the memory could not be allocated inside the chosen process.\n");
    }
    /*
     * Write the argument to LoadLibraryA to the process's newly allocated memory region.
     */
    int n = WriteProcessMemory(process, arg, buffer, strlen(buffer)+1, NULL);
    if(n == 0) {
        printf("Error: there was no bytes written to the process's address space.\n");
		fprintf(stream, "Error: there was no bytes written to the process's address space\n");
    }
    /*
     * Inject our DLL into the process's address space.
     */
	/*
	 SECURITY_ATTRIBUTES  sa;
      
     sa.nLength = sizeof(SECURITY_ATTRIBUTES);
     sa.bInheritHandle = TRUE;  

     // Call function to set the DACL. The DACL
     // is set in the SECURITY_ATTRIBUTES 
     // lpSecurityDescriptor member.
     if (!CreateMyDACL(&sa))
     {
         // Error encountered; generate message and exit.
         printf("Failed CreateMyDACL\n");
         fprintf(stream, "Error: Failed CreateMyDACL\n");
     }
	 */


    HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
    if(threadID == NULL) {
        printf("Error: the remote thread could not be created with error %d.\n", GetLastError());
    }
	/*
    else {
        printf("Success: the remote thread was successfully created.\n");
    }
	
	if (!MyCreateRemoteThread(process, (LPTHREAD_START_ROUTINE)addr, arg))

    {

        printf("Injection Failed!\n");
		fprintf(stream, "Injection Failed!\n");

        // return FALSE;

    }
	*/
	else
	{
		printf("Success: the remote thread was successfully created.\n");
		fprintf(stream, "Success: the remote thread was successfully created.\n");
	}
    /*
     * Close the handle to the process, becuase we've already injected the DLL.
     */
    CloseHandle(process);
	PrintModules(49136);

    fclose(stream);
    return 0;
}

CSampleService::CSampleService(PWSTR pszServiceName, 
                               BOOL fCanStop, 
                               BOOL fCanShutdown, 
                               BOOL fCanPauseContinue)
: CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
    m_fStopping = FALSE;

    // Create a manual-reset event that is not signaled at first to indicate 
    // the stopped signal of the service.
    m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_hStoppedEvent == NULL)
    {
        throw GetLastError();
    }
}


CSampleService::~CSampleService(void)
{
    if (m_hStoppedEvent)
    {
        CloseHandle(m_hStoppedEvent);
        m_hStoppedEvent = NULL;
    }
}


//
//   FUNCTION: CSampleService::OnStart(DWORD, LPWSTR *)
//
//   PURPOSE: The function is executed when a Start command is sent to the 
//   service by the SCM or when the operating system starts (for a service 
//   that starts automatically). It specifies actions to take when the 
//   service starts. In this code sample, OnStart logs a service-start 
//   message to the Application log, and queues the main service function for 
//   execution in a thread pool worker thread.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
//   NOTE: A service application is designed to be long running. Therefore, 
//   it usually polls or monitors something in the system. The monitoring is 
//   set up in the OnStart method. However, OnStart does not actually do the 
//   monitoring. The OnStart method must return to the operating system after 
//   the service's operation has begun. It must not loop forever or block. To 
//   set up a simple monitoring mechanism, one general solution is to create 
//   a timer in OnStart. The timer would then raise events in your code 
//   periodically, at which time your service could do its monitoring. The 
//   other solution is to spawn a new thread to perform the main service 
//   functions, which is demonstrated in this code sample.
//
void CSampleService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
    // Log a service start message to the Application log.
    WriteEventLogEntry(L"CppWindowsService in OnStart", 
        EVENTLOG_INFORMATION_TYPE);

	printlog("Going to start service");
	
	// Queue the main service function for execution in a worker thread.
    CThreadPool::QueueUserWorkItem(&CSampleService::ServiceWorkerThread, this);
}


//
//   FUNCTION: CSampleService::ServiceWorkerThread(void)
//
//   PURPOSE: The method performs the main function of the service. It runs 
//   on a thread pool worker thread.
//
void CSampleService::ServiceWorkerThread(void)
{
	printlog("About to start service");

    // Periodically check if the service is stopping.
    while (!m_fStopping)
    {
        // Perform main service function here...
		ServiceFunction();
        ::Sleep(2000);  // Simulate some lengthy operations.
    }

    // Signal the stopped event.
    SetEvent(m_hStoppedEvent);
}


//
//   FUNCTION: CSampleService::OnStop(void)
//
//   PURPOSE: The function is executed when a Stop command is sent to the 
//   service by SCM. It specifies actions to take when a service stops 
//   running. In this code sample, OnStop logs a service-stop message to the 
//   Application log, and waits for the finish of the main service function.
//
//   COMMENTS:
//   Be sure to periodically call ReportServiceStatus() with 
//   SERVICE_STOP_PENDING if the procedure is going to take long time. 
//
void CSampleService::OnStop()
{
    // Log a service stop message to the Application log.
    WriteEventLogEntry(L"CppWindowsService in OnStop", 
        EVENTLOG_INFORMATION_TYPE);

    // Indicate that the service is stopping and wait for the finish of the 
    // main service function (ServiceWorkerThread).
    m_fStopping = TRUE;
    if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw GetLastError();
    }
}