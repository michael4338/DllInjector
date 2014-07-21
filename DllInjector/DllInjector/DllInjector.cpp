// DllInjector.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
//#undef UNICODE
#include <vector>
#include <string>
#include <windows.h>
#include <Tlhelp32.h>
#include <psapi.h>

using namespace std;
FILE *stream;

int PrintModules( DWORD processID )
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf( "\nProcess ID: %u\n", processID );

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
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
                                      sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.

                _tprintf( TEXT("\t%s (0x%08X)\n"), szModName, hMods[i] );
            }
        }
    }
    
    // Release the handle to the process.

    CloseHandle( hProcess );

    return 0;
}

void printlog(const char* buf)
{
	fopen_s(&stream, "E:\\Detours\\DllInjector\\log.txt", "a+");
    fprintf(stream, "%s\n", buf);
    fclose(stream);
}

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13

#include <windows.h>
#include <stdio.h>

BOOL SetPrivilege(
    HANDLE hToken,          // token handle
    LPCTSTR Privilege,      // Privilege to enable/disable
    BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
    );

void DisplayError(LPTSTR szAPI);

int CallPrivilege(DWORD pid)
{
    HANDLE hProcess;
    HANDLE hToken;
    int dwRetVal=RTN_OK; // assume success from main()

    if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
        if (GetLastError() == ERROR_NO_TOKEN)
        {
            if (!ImpersonateSelf(SecurityImpersonation))
            return RTN_ERROR;

            if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
                DisplayError(L"OpenThreadToken");
				printf("OpenThreadToken\n");
				return RTN_ERROR;
            }
         }
        else
		{
			printf("OpenThreadToken RTN_ERROR\n");
            return RTN_ERROR;
		}
     }

    // enable SeDebugPrivilege
    if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
    {
        DisplayError(L"SetPrivilege");
		printf("SetPrivilege RTN_ERROR\n");

        // close token handle
        CloseHandle(hToken);

        // indicate failure
        return RTN_ERROR;
    }

	CloseHandle(hToken);
	return 0;

   // open the process
    if((hProcess = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            pid
            )) == NULL)
    {
		printf("OpenProcess error %d\n", GetLastError());
        DisplayError(L"OpenProcess");
        return RTN_ERROR;
    }

    // disable SeDebugPrivilege
    SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);

    if(!TerminateProcess(hProcess, 0xffffffff))
    {
        DisplayError(L"TerminateProcess");
        dwRetVal=RTN_ERROR;
    }

    // close handles
    CloseHandle(hToken);
    CloseHandle(hProcess);
	printf("SetPrivilege successfully\n");

    return dwRetVal;
}

/*
BOOL SetPrivilege(
    HANDLE hToken,          // token handle
    LPCTSTR Privilege,      // Privilege to enable/disable
    BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

    if(!LookupPrivilegeValue( NULL, Privilege, &luid )) return FALSE;

    // 
    // first pass.  get current privilege setting
    // 
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            &tpPrevious,
            &cbPrevious
            );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    // 
    // second pass.  set privilege based on previous setting
    // 
    tpPrevious.PrivilegeCount       = 1;
    tpPrevious.Privileges[0].Luid   = luid;

    if(bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
            tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tpPrevious,
            cbPrevious,
            NULL,
            NULL
            );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    return TRUE;
}
*/

BOOL SetPrivilege( 
	HANDLE hToken,  // token handle 
	LPCTSTR Privilege,  // Privilege to enable/disable 
	BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
) 
{ 
	TOKEN_PRIVILEGES tp = { 0 }; 
	// Initialize everything to zero 
	LUID luid; 
	DWORD cb=sizeof(TOKEN_PRIVILEGES); 
	if(!LookupPrivilegeValue( NULL, Privilege, &luid ))
		return FALSE; 
	tp.PrivilegeCount = 1; 
	tp.Privileges[0].Luid = luid; 
	if(bEnablePrivilege) { 
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	} else { 
		tp.Privileges[0].Attributes = 0; 
	} 
	AdjustTokenPrivileges( hToken, FALSE, &tp, cb, NULL, NULL ); 
	if (GetLastError() != ERROR_SUCCESS) 
		return FALSE; 

	return TRUE;
}

void DisplayError(
    LPTSTR szAPI    // pointer to failed API name
    )
{
    LPTSTR MessageBuffer;
    DWORD dwBufferLength;

    fprintf(stderr,"%s() error!\n", szAPI);

    if(dwBufferLength=FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                GetLastError(),
                GetSystemDefaultLangID(),
                (LPTSTR) &MessageBuffer,
                0,
                NULL
                ))
    {
        DWORD dwBytesWritten;

        // 
        // Output message string on stderr
        // 
        WriteFile(
                GetStdHandle(STD_ERROR_HANDLE),
                MessageBuffer,
                dwBufferLength,
                &dwBytesWritten,
                NULL
                );

        // 
        // free the buffer allocated by the system
        // 
        LocalFree(MessageBuffer);
    }
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

    if (IsLaterNT())

    {

        pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

        if (pFunc == NULL)

        {

            printf("Get NtCreateThreadEx Address failed\n");

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

            return FALSE;

        }

     

    }

    else

    {

        hThread = CreateRemoteThread(hProcess, NULL, NULL, lpThreadProc, lpDllName, 0, NULL);

        if(hThread == NULL)

        {

            return FALSE;

        }

    }

    if (WAIT_TIMEOUT == WaitForSingleObject(hThread, INFINITE))

    {

        printf("wait timeout\n");

        return FALSE;

    }

    CloseHandle(hThread);

    return TRUE;

}

int _tmain(int argc, _TCHAR* argv[]) {
	
    char* buffer = "E:\\Detours\\DllInjector\\DetoursDll.dll";
    /*
     * Get process handle passing in the process ID.
     */
    int procID = 49004;

	CallPrivilege(procID);
	PrintModules(49004);
	// getchar();
	// return 0;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if(process == NULL) {
        printf("Error: the specified process couldn't be found with error %d.\n", GetLastError());
		// return -1;
    }
    /*
     * Get address of the LoadLibrary function.
     */
    LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if(addr == NULL) {
        printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
    }
    /*
     * Allocate new memory region inside the process's address space.
     */
    LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(arg == NULL) {
        printf("Error: the memory could not be allocated inside the chosen process.\n");
    }
    /*
     * Write the argument to LoadLibraryA to the process's newly allocated memory region.
     */
    int n = WriteProcessMemory(process, arg, buffer, strlen(buffer)+1, NULL);
    if(n == 0) {
        printf("Error: there was no bytes written to the process's address space.\n");
    }
    /*
     * Inject our DLL into the process's address space.
     */
	/*
    HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
    if(threadID == NULL) {
        printf("Error: the remote thread could not be created with error %d.\n", GetLastError());
    }
    else {
        printf("Success: the remote thread was successfully created.\n");
    }
	*/
	if (!MyCreateRemoteThread(process, (LPTHREAD_START_ROUTINE)addr, arg))

    {

        printf("Injection Failed!\n");

        // return FALSE;

    }
	else
	{
		printf("Success: the remote thread was successfully created.\n");
	}
    /*
     * Close the handle to the process, becuase we've already injected the DLL.
     */
    CloseHandle(process);
	PrintModules(49004);
    getchar();
    return 0;
}

/*
int main(void)
{
    vector<string> processNames;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    BOOL bProcess = Process32First(hTool32, &pe32);
    if(bProcess == TRUE)
    {
        while((Process32Next(hTool32, &pe32)) == TRUE)
		{
            processNames.push_back(pe32.szExeFile);
			 
			if(strcmp(pe32.szExeFile, "notepad.exe") == 0)
			{
				char* DirPath = new char[MAX_PATH];
				char* FullPath = new char[MAX_PATH];
				GetCurrentDirectory(MAX_PATH, DirPath);
				sprintf_s(FullPath, MAX_PATH, "%s\\DetoursDll.dll", DirPath);
				printlog(FullPath);
				HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD    | PROCESS_VM_OPERATION    |
					PROCESS_VM_WRITE, FALSE, pe32.th32ProcessID);
				LPVOID LoadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"),
					"LoadLibraryA");
				LPVOID LLParam = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(FullPath),
					MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				WriteProcessMemory(hProcess, LLParam, FullPath, strlen(FullPath), NULL);
				CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr,
					LLParam, NULL, NULL);
				CloseHandle(hProcess);
				delete [] DirPath;
				delete [] FullPath;
				printlog("everything good");
			}
		}
    }
    CloseHandle(hTool32);
	printlog("inject succss");
    return 0;
}
*/