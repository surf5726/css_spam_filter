#include <Windows.h>
#include <assert.h>
#include <stdio.h>

typedef int (*LauncherMain_t)(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow);

extern "C" { _declspec(dllexport) DWORD NvOptimusEnablement = 0x00000001; }
extern "C" { __declspec(dllexport) int AmdPowerXpressRequestHighPerformance = 1; }

static char *GetBaseDir(const char *pszBuffer)
{
	static char	basedir[MAX_PATH];
	char szBuffer[MAX_PATH];
	size_t j;
	char *pBuffer = NULL;

	strcpy(szBuffer, pszBuffer);

	pBuffer = strrchr(szBuffer, '\\');
	if (pBuffer)
	{
		*(pBuffer + 1) = '\0';
	}

	strcpy(basedir, szBuffer);

	j = strlen(basedir);
	if (j > 0)
	{
		if ((basedir[j - 1] == '\\') ||
			(basedir[j - 1] == '/'))
		{
			basedir[j - 1] = 0;
		}
	}

	return basedir;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char *pPath = getenv("PATH");

	char moduleName[MAX_PATH];
	char szBuffer[4096];
	if (!GetModuleFileName(hInstance, moduleName, MAX_PATH))
	{
		MessageBox(0, "Failed calling GetModuleFileName", "Launcher Error", MB_OK);
		return 0;
	}

	char *pRootDir = GetBaseDir(moduleName);

#ifdef _DEBUG
	int len =
#endif
		_snprintf(szBuffer, sizeof(szBuffer), "PATH=%s\\bin\\x64\\;%s", pRootDir, pPath);
	szBuffer[sizeof(szBuffer) - 1] = '\0';
	assert(len < sizeof(szBuffer));
	_putenv(szBuffer);

	_snprintf(szBuffer, sizeof(szBuffer), "%s\\bin\\x64\\launcher.dll", pRootDir);
	szBuffer[sizeof(szBuffer) - 1] = '\0';

	HINSTANCE launcher = LoadLibraryEx(szBuffer, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

	if (!launcher)
	{
		char *pszError;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&pszError, 0, NULL);

		char szBuf[1024];
		_snprintf(szBuf, sizeof(szBuf), "Failed to load the launcher DLL:\n\n%s", pszError);
		szBuf[sizeof(szBuf) - 1] = '\0';
		MessageBox(0, szBuf, "Launcher Error", MB_OK);

		LocalFree(pszError);
		return 0;
	}

	if (!LoadLibrary("css_spam_filter.dll"))
	{
		MessageBox(NULL, "Could not load css_spam_filter.dll", "Launcher Error", 0);
		ExitProcess(1);
	}

	LauncherMain_t main = (LauncherMain_t)GetProcAddress(launcher, "LauncherMain");
	return main(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
}