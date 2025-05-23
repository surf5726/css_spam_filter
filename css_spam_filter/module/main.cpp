#include <string>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <Windows.h>
#include "detours.h"

#define PATTERN "TSource Engine Query"
#define PAYLOAD "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF"

int (WSAAPI *pfnsendto)(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR *buf,
	_In_ int len,
	_In_ int flags,
	_In_reads_bytes_(tolen) const struct sockaddr FAR *to,
	_In_ int tolen
	) = sendto;

int WSAAPI mysendto(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR *buf,
	_In_ int len,
	_In_ int flags,
	_In_reads_bytes_(tolen) const struct sockaddr FAR *to,
	_In_ int tolen
)
{
	if (to->sa_family == AF_INET)
	{
		std::string data(buf, len);
		if (data.find(PATTERN) != std::string::npos)
		{
			const sockaddr_in *extract = reinterpret_cast<const sockaddr_in *>(to);
			sockaddr_in check = { 0 };
			check.sin_family = AF_INET;
			check.sin_addr.S_un.S_addr = extract->sin_addr.S_un.S_addr;
			check.sin_port = extract->sin_port;
			int len = sizeof(check);
			sendto(s, PAYLOAD, (int)strlen(PAYLOAD), 0, (sockaddr *)&check, len);
			char result[16] = { 0 };
			recvfrom(s, result, sizeof(result), 0, (sockaddr *)&check, &len);
			if (result[4] != 'A' && result[4] != 'U')
				return 0;
		}
	}
	return pfnsendto(s, buf, len, flags, to, tolen);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((PVOID *)&pfnsendto, mysendto);
			DetourTransactionCommit();
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach((PVOID *)&pfnsendto, mysendto);
			DetourTransactionCommit();
			break;
		}
		default:
			break;
	}
	return TRUE;
}
