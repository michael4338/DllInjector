// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "detours.h"
#include <stdio.h>
#include <windows.h>

#define NTSTATUS LONG

#define IWICBitmapScaler VOID
#define IWICImagingFactory VOID
#define IWICBitmapSource VOID 
#define IWICBitmap VOID

typedef enum WICBitmapInterpolationMode { 
  WICBitmapInterpolationModeNearestNeighbor  = 0x00000000,
  WICBitmapInterpolationModeLinear           = 0x00000001,
  WICBitmapInterpolationModeCubic            = 0x00000002,
  WICBitmapInterpolationModeFant             = 0x00000003
} WICBitmapInterpolationMode;

typedef struct { 
  GUID GUID_WICPixelFormat;
  UINT BitsPerPixel;
  UINT ChanelOrder;
  UINT StorageType;
} REFWICPixelFormatGUID;

typedef enum WICSectionAccessLevel { 
  WICSectionAccessLevelRead       = 0x00000001,
  WICSectionAccessLevelReadWrite  = 0x00000003
} WICSectionAccessLevel;

static LONG dwSlept = 0;

static HRESULT (*TrueThumbnailGenerationFunc) (IWICImagingFactory *pFactory, IWICBitmapScaler **ppIBitmapScaler) = NULL;

static HRESULT (*TrueThumbnailInitializationFunc) (IWICBitmapSource *pISource, UINT uiWidth, UINT uiHeight, WICBitmapInterpolationMode mode) = NULL;

static HRESULT (*TrueCreateBitmapFromSectionEx) (UINT width, UINT height, REFWICPixelFormatGUID pixelFormat, HANDLE hSection, UINT stride, UINT offset, WICSectionAccessLevel desiredAccessLevel, IWICBitmap **pIBitmap) = NULL;

static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

NTSTATUS (NTAPI *Real_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) = NULL;

HDC (*Real_CreateCompatibleDC)(HDC hdc) = NULL;

HDC (WINAPI *True_CreateCompatibleDC)(HDC) = CreateCompatibleDC;

FILE* stream;
void printlog(const char* buf)
{
	fopen_s(&stream, "E:\\Detours\\DllInjector\\dlllog.txt", "a+");
    fprintf(stream, "%s\n", buf);
    fclose(stream);
}


DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();
	
	printf("Fake SLEEP function is executing\n");

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

    return ret;
}

HDC WINAPI Mine_CreateCompatibleDC(HDC hdc)
{
	return True_CreateCompatibleDC(hdc);
	printf("You are calling the fake CreateCompatibleDC function.\n");
	fflush(stdout);
	printlog("You are calling the fake CreateCompatibleDC function.\n");
}

static HRESULT FakeThumbnailGenerationFunc(IWICImagingFactory *pFactory, IWICBitmapScaler **ppIBitmapScaler)
{
	// Do nothing
	printf("You are calling the fake ThumbnailGeneration function.\n");
	fflush(stdout);
	return HRESULT(-1);
}

static HRESULT FakeThumbnailInitializationFunc(IWICBitmapSource *pISource, UINT uiWidth, UINT uiHeight, WICBitmapInterpolationMode mode)
{
	// Do nothing
	printf("You are calling the fake ThumbnailInitializationFunc function.\n");
	fflush(stdout);
	return HRESULT(-1);
}

static HRESULT FakeCreateBitmapFromSectionEx(UINT width, UINT height, REFWICPixelFormatGUID pixelFormat, HANDLE hSection, UINT stride, UINT offset, WICSectionAccessLevel desiredAccessLevel, IWICBitmap **pIBitmap)
{
	// Do nothing
	printf("You are calling the fake CreateBitmapFromSectionEx function.\n");
	fflush(stdout);
	return HRESULT(-1);
}

static HDC Fake_CreateCompatibleDC(HDC hdc)
{
	// Do nothing
	printf("You are calling the fake CreateCompatibleDC function.\n");
	fflush(stdout);
	printlog("You are calling the fake CreateCompatibleDC function.\n");
	return NULL;
}

extern "C" __declspec(dllexport) void DetourAttachCreateCompatibleDCFunc()
{
		DetourRestoreAfterWith();

        printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll Starting.\n");
        fflush(stdout);
		printlog("Detouring CreateCompatibleDCFunc.\n");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)True_CreateCompatibleDC, Mine_CreateCompatibleDC);
        LONG error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("CreateCompatibleDC Detoured \n");
			printlog("CreateCompatibleDC Detoured.\n");
        }
        else {
            printf("CreateCompatibleDC Detoure error: %d\n", error);
			printlog("CreateCompatibleDC Detoure error.\n");
        }

		fflush(stdout);
}

extern "C" __declspec(dllexport) void DetourAttachSleepFunc()
{
		DetourRestoreAfterWith();

        printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        LONG error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll Detoured SleepEx().\n");
        }
        else {
            printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll Error detouring SleepEx(): %d\n", error);
        }

		fflush(stdout);
}

extern "C" __declspec(dllexport) void DetourDetachSleepFunc()
{
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
    LONG error = DetourTransactionCommit();

    printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll: Removed SleepEx() (result=%d), slept %d ticks.\n", error, dwSlept);
    fflush(stdout);
}

extern "C" __declspec(dllexport) void DetourAttachThumbnailGenerationFunc()
{
	printf("looking for the function name: CreateBitmapScaler\n");
	fflush(stdout);
/*
	Real_NtWaitForSingleObject = ((NTSTATUS (NTAPI *)(HANDLE, BOOLEAN, PLARGE_INTEGER))DetourFindFunction("ntdll.dll", "NtWaitForSingleObject"));
	printf("Function name NtWaitForSingleObject found: %d, detouring begin\n", Real_NtWaitForSingleObject);
	fflush(stdout);

	PVOID a = DetourFindFunction("Ws2_32.dll","accept");
	printf("Function name accept found: %u, detouring begin\n", a);
	fflush(stdout);

	PVOID b = ((HRESULT (*)(IWICBitmapScaler **))DetourFindFunction("Windowscodecs.dll", "CreateBitmapScaler"));
	printf("Function name CreateBitmapScaler found: %u, detouring begin\n", b);
	fflush(stdout);
*/

/*
    TrueThumbnailGenerationFunc = ((HRESULT (*)(IWICImagingFactory*, IWICBitmapScaler **))DetourFindFunction("Windowscodecs.dll", "IWICImagingFactory_CreateBitmapScaler_Proxy"));
	printf("Function name IWICImagingFactory_CreateBitmapScaler_Proxy found: %u, detouring begin\n", TrueThumbnailGenerationFunc);
	fflush(stdout);


	TrueThumbnailInitializationFunc = ((HRESULT (*)(IWICBitmapSource *, UINT, UINT, WICBitmapInterpolationMode))DetourFindFunction("Windowscodecs.dll", "Initialize"));
	printf("Function name ThumbnailInitializationFunc found: %u, detouring begin\n", TrueThumbnailInitializationFunc);
	fflush(stdout);

    TrueCreateBitmapFromSectionEx = ((HRESULT (*)(UINT, UINT, REFWICPixelFormatGUID, HANDLE, UINT, UINT, WICSectionAccessLevel, IWICBitmap**))DetourFindFunction("Windowscodecs.dll", "WICCreateBitmapFromSectionEx"));
	printf("Function name CreateBitmapFromSectionEx found: %u, detouring begin\n", TrueCreateBitmapFromSectionEx);
	fflush(stdout);

	Real_CreateCompatibleDC = ((HDC (*)(HDC))DetourFindFunction("Gdi32.dll", "CreateCompatibleDC"));
	printf("Function name CreateCompatibleDC found: %u, detouring begin\n", Real_CreateCompatibleDC);
	fflush(stdout);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	printf("Function name found, detouring attach\n");
	fflush(stdout);
    // LONG error = DetourAttach(&(PVOID&)TrueThumbnailInitializationFunc, FakeThumbnailInitializationFunc);
	// LONG error = DetourAttach(&(PVOID&)TrueCreateBitmapFromSectionEx, FakeCreateBitmapFromSectionEx);
	LONG error = DetourAttach(&(PVOID&)Real_CreateCompatibleDC, Fake_CreateCompatibleDC);
	printf("Attach detouring result: %d\n", error);

	error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        printf("DetoursDll.dll Detoured Initialize() successfully, %d.\n", error);
	}
    else {
        printf("DetoursDll.dll Error detouring Initialize(): %d\n", error);
    }

	fflush(stdout);
*/
	DetourAttachCreateCompatibleDCFunc();

	// Test if detour works in the same process

}

extern "C" __declspec(dllexport) void DetourDetachThumbnailGenerationFunc()
{
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueThumbnailGenerationFunc, FakeThumbnailGenerationFunc);
    LONG error = DetourTransactionCommit();

	if (error == NO_ERROR) {
        printf("DetoursDll.dll Removed detouring CreateBitmapScaler().\n");
	}
    else {
        printf("DetoursDll.dll Error removing detouring CreateBitmapScaler(): %d\n", error);
    }

    fflush(stdout);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		printlog("DllMain process attach");
		DisableThreadLibraryCalls(hModule);
		DetourAttachThumbnailGenerationFunc();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

