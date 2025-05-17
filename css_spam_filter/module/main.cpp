#include <fstream>
#include <string>
#include <vector>
#include <format>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <Windows.h>
#include "detours.h"
#include "json.hpp"
#include "maxminddb.h"

#define TITLE "css_spam_filter"
#define CONF "css_spam_filter.json"
#define DB "IP2LOCATION-LITE-DB1.MMDB"
#define PATTERN "TSource Engine Query"

static nlohmann::json json;
static std::vector<std::string> country;
static std::vector<std::string> white_list_ip;
static MMDB_s mmdb;

void exit_on_failure(const std::string &err)
{
	MessageBox(NULL, err.c_str(), TITLE, 0);
	ExitProcess(1);
}

void load_conf(void)
{
	std::ifstream ifs(CONF);
	if (!ifs.is_open())
		exit_on_failure(std::format("Cannot load {0}", CONF));
	try
	{
		json = nlohmann::json::parse(ifs);
		ifs.close();
		if (json["enable"])
		{
			for (int i = 0; i < json["country"].size(); i++)
				country.emplace_back(json["country"][i]);
			for (int i = 0; i < json["white_list_ip"].size(); i++)
			{
				if (json["white_list_ip"][i] == "x.x.x.x")
					continue;
				white_list_ip.emplace_back(json["white_list_ip"][i]);
			}
		}
	}
	catch (nlohmann::json::exception &ex)
	{
		exit_on_failure(ex.what());
	}
}

void load_database(void)
{
	if (MMDB_open(DB, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS)
		exit_on_failure(std::format("Can't open database: {0}", DB));
}

bool lookup_ip(const char *ip, std::string *country)
{
	int gai_err;
	int mmdb_err;
	MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip, &gai_err, &mmdb_err);
	if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !result.found_entry)
		return false;
	MMDB_entry_data_s entry_data;
	if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS)
	{
		*country = std::string(entry_data.utf8_string, entry_data.data_size);
		return true;
	}
	return false;
}

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
		//puts(data.c_str());
		if (data.find(PATTERN) != std::string::npos)
		{
			//puts("OK");
			char ip[32] = { 0 };
			const sockaddr_in *sa_in = reinterpret_cast<const sockaddr_in *>(to);
			inet_ntop(AF_INET, &(sa_in->sin_addr), ip, sizeof(ip));
			if (std::find(white_list_ip.begin(), white_list_ip.end(), ip) != white_list_ip.end())
				return pfnsendto(s, buf, len, flags, to, tolen);
			//puts(ip);
			std::string s_country;
			//lookup_ip(ip, &s_country);
			//puts(s_country.c_str());
			if (lookup_ip(ip, &s_country) && std::find(country.begin(), country.end(), s_country) != country.end())
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
			load_conf();
			if (json["enable"])
			{
				load_database();
				//AllocConsole();
				//freopen("CONOUT$", "w", stdout);
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach((PVOID *)&pfnsendto, mysendto);
				DetourTransactionCommit();
			}
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			if (json["enable"])
			{
				MMDB_close(&mmdb);
				//FreeConsole();
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourDetach((PVOID *)&pfnsendto, mysendto);
				DetourTransactionCommit();
			}
			break;
		}
		default:
			break;
	}
	return TRUE;
}