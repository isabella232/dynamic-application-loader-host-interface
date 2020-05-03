/*
   Copyright 2010-2016 Intel Corporation

   This software is licensed to you in accordance
   with the agreement between you and Intel Corporation.

   Alternatively, you can use this file in compliance
   with the Apache license, Version 2.


   Apache License, Version 2.0

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/**                                                                            
********************************************************************************
**
**    @file reg.c
**
**    @brief  Defines registry related functions
**
**    @author Niveditha Sundaram
**
********************************************************************************
*/

#include <stdio.h>
#include <memory>
#include "jhi.h"
#include "reg.h"

#ifdef NEW_REG_LOCATION
#include <winsvc.h>

#ifdef SCHANNEL_OVER_SOCKET // emulation mode
#define REGISTRY_PATH  "SYSTEM\\CurrentControlSet\\Services\\jhi_service_emulation"
#else
#define REGISTRY_PATH			"SYSTEM\\CurrentControlSet\\Services\\jhi_service"
#define REGISTRY_PARAMS_PATH	"SYSTEM\\CurrentControlSet\\Services\\jhi_service\\Parameters"
#endif

#else // old reg location

#ifdef SCHANNEL_OVER_SOCKET // emulation mode
#define REGISTRY_PATH  "Software\\Intel\\Services\\DAL_EMULATION"
#else
#define REGISTRY_PATH  "Software\\Intel\\Services\\DAL"
#endif

#endif //NEW_REG_LOCATION

// Changing registry location for emulation mode so the registry values will be writeable with user permissions as well. 
#ifdef SCHANNEL_OVER_SOCKET // emulation mode.
#define REGISTRY_BASE  HKEY_CURRENT_USER
#else
#define REGISTRY_BASE  HKEY_LOCAL_MACHINE
#endif


// jhi registry keys
#define KEY_JHI_FILES_PATH L"FILELOCALE"
#define KEY_JHI_APPLETS_REPOSITORY_PATH L"APPLETSLOCALE"
#define KEY_JHI_SERVICE_PORT L"JHI_SERVICE_PORT"
#define KEY_JHI_ADDRESS_TYPE L"JHI_ADDRESS_TYPE"
#define KEY_JHI_TRANSPORT_TYPE L"JHI_TRANSPORT_TYPE"
#define KEY_JHI_FW_VERSION L"FW_VERSION"
#define KEY_JHI_LOG_FLAG L"JHI_LOG"
#define KEY_JHI_LOG_TARGET L"JHI_LOG_TARGET"


bool readStringFromRegistry(const wchar_t* value, wchar_t* outBuffer, uint32_t outBufferSize)
{
	if (value == NULL || outBuffer == NULL)
		return false;

	DWORD dwType;
	DWORD dwSize = outBufferSize;

	long ret = RegGetValue(REGISTRY_BASE, TEXT(REGISTRY_PATH), value, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, &dwType, outBuffer, &dwSize);
	
	if (ret != ERROR_SUCCESS)
	{
		TRACE1("readStringFromRegistry: RegGetValue failed with error code %ld", ret);
		return false;
	}
	
	return true;
}

bool readIntegerFromRegistry(const wchar_t* key,uint32_t* value)
{
	HKEY hKey;
	DWORD dwType = REG_DWORD;
	DWORD size = sizeof(DWORD);
	LSTATUS status;

	if (key == NULL || value == NULL)
		return false;

	// Check if Module is a valid number
	if ( (status = RegOpenKeyEx(REGISTRY_BASE,
		TEXT(REGISTRY_PATH),
		0,
		KEY_READ | KEY_WOW64_64KEY,
		&hKey)) != ERROR_SUCCESS )
	{
		TRACE1( "Unable to open Registry [0x%x]\n", status);
		return false; 
	}

	// Check for the actual value
	if (RegQueryValueEx(hKey,key,0, &dwType, (LPBYTE)value, (LPDWORD)&size) != ERROR_SUCCESS)
	{
		TRACE1("Registry read integer key '%S' failed.\n",key);
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

#ifdef NEW_REG_LOCATION
/*
	In windows RS3, the function GetServiceRegistryStateKey is not yet implemented in sechost.dll.
	In order to run JHI on windows RS3 as well, we dynamically load the dll and see if we can use this function,
	if not - this is windows RS3 and we read from a known path in registry.
*/
bool openServiceParametersRegistryKey(HKEY* hKey, SERVICE_STATUS_HANDLE srvcHandle)
{
	typedef DWORD (WINAPI *DLLFN) (SERVICE_STATUS_HANDLE, SERVICE_REGISTRY_STATE_TYPE, DWORD, HKEY*);

	LSTATUS status;
	HMODULE hDll;
	DLLFN fnPtrGetRegKey;

	if ((hDll = LoadLibraryEx(L"sechost.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) == NULL)
	{
		TRACE1("LoadLibraryEx with sechost.dll failed. Error: [0x%x]", GetLastError());
		return false;
	}

	if ((fnPtrGetRegKey = (DLLFN) GetProcAddress(hDll, "GetServiceRegistryStateKey")) != NULL) // If the dll contains this function - get path from windows.
	{
		if ((status = fnPtrGetRegKey(srvcHandle, ServiceRegistryStateParameters, KEY_READ, hKey)) != ERROR_SUCCESS)
		{
			TRACE2("GetServiceRegistryStateKey failed [0x%x] handle %p", status, (void *)srvcHandle);
			FreeLibrary(hDll);
			return false;
		}
	}
	else // If not - read from known registry location.
	{
		TRACE0("GetProcAddress with GetServiceRegistryStateKey failed, This is windows RS3 or lower.");
		if ((status = RegOpenKeyEx(REGISTRY_BASE, TEXT(REGISTRY_PARAMS_PATH), 0, KEY_READ | KEY_WOW64_64KEY, hKey)) != ERROR_SUCCESS)
		{
			TRACE2("Registry read failure for %s, RegOpenKeyEx failed [0x%x]\n", REGISTRY_PARAMS_PATH, status);
			FreeLibrary(hDll);
			return false;
		}
	}

	FreeLibrary(hDll);
	return true;
}


bool readStringParameterFromRegistry(SERVICE_STATUS_HANDLE srvcHandle, const wchar_t* value, wchar_t* outBuffer, uint32_t outBufferSize)
{
	HKEY hKey;
	DWORD dwType = REG_SZ | REG_EXPAND_SZ;
	int maxElementSize = -1;
	LSTATUS status;

	if (!openServiceParametersRegistryKey(&hKey, srvcHandle))
	{
		return false;
	}

	// Check for the actual value
	if ((status = RegQueryValueEx(hKey, value, 0, &dwType, (LPBYTE)outBuffer, (LPDWORD)&outBufferSize)) != ERROR_SUCCESS)
	{
		TRACE2("Registry read failure for %S. Error: [0x%x]\n", value, status);
		RegCloseKey(hKey);
		return false;
	}

	maxElementSize = outBufferSize / sizeof(wchar_t);
	if (outBuffer[maxElementSize] != '\0') // RegQueryValueEx does not guarantee that the string returned is null terminated
		outBuffer[maxElementSize] = '\0';

	RegCloseKey(hKey);
	return true;
}
#endif

JHI_RET_I
JhiQueryAppFileLocationFromRegistry (SERVICE_STATUS_HANDLE srvcHandle, wchar_t* outBuffer, uint32_t outBufferSize)
{
	std::unique_ptr<wchar_t> temp{ new wchar_t[outBufferSize] };

#ifdef NEW_REG_LOCATION
	if (!readStringParameterFromRegistry(srvcHandle, KEY_JHI_APPLETS_REPOSITORY_PATH, temp.get(), outBufferSize))
		return JHI_ERROR_REGISTRY;
#else
	if (!readStringFromRegistry(KEY_JHI_APPLETS_REPOSITORY_PATH, temp.get(), outBufferSize))
		return JHI_ERROR_REGISTRY;
#endif
	ExpandEnvironmentStrings(temp.get(), outBuffer, outBufferSize);

	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryServiceFileLocationFromRegistry (SERVICE_STATUS_HANDLE srvcHandle, wchar_t* outBuffer, uint32_t outBufferSize)
{
	std::unique_ptr<wchar_t> temp {new wchar_t[outBufferSize]};

#ifdef NEW_REG_LOCATION
	if (!readStringParameterFromRegistry(srvcHandle, KEY_JHI_FILES_PATH, temp.get(), outBufferSize))
		return JHI_ERROR_REGISTRY;
#else
	if (!readStringFromRegistry(KEY_JHI_FILES_PATH, temp.get(), outBufferSize))
		return JHI_ERROR_REGISTRY;
#endif
	ExpandEnvironmentStrings(temp.get(), outBuffer, outBufferSize);

	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryServicePortFromRegistry(uint32_t* portNumber)
{
	if (!readIntegerFromRegistry(KEY_JHI_SERVICE_PORT,portNumber))
		return JHI_ERROR_REGISTRY;

	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryTransportTypeFromRegistry(uint32_t* transportType)
{
	if (!readIntegerFromRegistry(KEY_JHI_TRANSPORT_TYPE,transportType))
		return JHI_ERROR_REGISTRY;

	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryAddressTypeFromRegistry(uint32_t* addressType)
{
	if (!readIntegerFromRegistry(KEY_JHI_ADDRESS_TYPE,addressType))
		return JHI_ERROR_REGISTRY;

	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryLogLevelFromRegistry(JHI_LOG_LEVEL *loglevel)
{
	uint32_t i_loglevel = 1; // Release logs by default
	*loglevel = JHI_LOG_LEVEL_RELEASE;

	if (!readIntegerFromRegistry(KEY_JHI_LOG_FLAG, &i_loglevel))
	{
		LOG0("LogLevel setting not found. Setting to release prints only.");
	}
	else
	{
		switch (i_loglevel)
		{
		case 0:
			*loglevel = JHI_LOG_LEVEL_OFF;
			break;
		case 1:
			*loglevel = JHI_LOG_LEVEL_RELEASE;
			break;
		case 2:
			*loglevel = JHI_LOG_LEVEL_DEBUG;
			break;
		default:
			*loglevel = JHI_LOG_LEVEL_RELEASE;
			break;
		}
	}
	
	return JHI_SUCCESS;
}

JHI_RET_I
JhiQueryLogTargetFromRegistry(JHI_LOG_TARGET *logTarget)
{
	uint32_t target = 0; // Debugger by default (DebugView)
	*logTarget = JHI_LOG_TARGET_DEBUGGER;

	if (!readIntegerFromRegistry(KEY_JHI_LOG_TARGET, &target))
	{
		TRACE0("Log target setting not found. Defaulting to 'debugger'.");
	}
	else
	{
		switch (target)
		{
		case 0:
			*logTarget = JHI_LOG_TARGET_DEBUGGER;
			break;
		case 1:
			*logTarget = JHI_LOG_TARGET_TXTFILE;
			break;
		default:
			*logTarget = JHI_LOG_TARGET_DEBUGGER;
			break;
		}
	}

	return JHI_SUCCESS;
}

bool WriteStringToRegistry(const wchar_t* key,wchar_t* value, uint32_t value_size)
{
	HKEY hKey;
	LSTATUS status;

	// Check if Module is a valid number
	if ( (status = RegOpenKeyEx( REGISTRY_BASE,
		TEXT(REGISTRY_PATH),
		0,
		KEY_WRITE  | KEY_WOW64_64KEY,
		&hKey)) != ERROR_SUCCESS )
	{
		TRACE1( "Unable to open Registry [0x%x]\n", status);
		return false; 
	}

	if(RegSetValueEx(hKey, key ,0L, REG_SZ, (CONST BYTE*) value, value_size) != ERROR_SUCCESS)
	{
		TRACE2("write key: '%S' value: '%S' to registry falied.\n",key,value);
		RegCloseKey(hKey);
		return false;
	}
	
	TRACE2("write key: '%S' value: '%S' to registry succeeded.\n",key,value);
	RegCloseKey(hKey);
	return true;
}

JHI_RET_I
JhiWritePortNumberToRegistry(uint32_t portNumber)
{
	HKEY hKey;
	LSTATUS status;
	
	// Check if Module is a valid number
	if ( (status = RegOpenKeyEx(REGISTRY_BASE,
		TEXT(REGISTRY_PATH),
		0,
		KEY_WRITE  | KEY_WOW64_64KEY,
		&hKey)) != ERROR_SUCCESS )
	{
		TRACE1( "Unable to open Registry [0x%x]\n", status);
		return JHI_ERROR_REGISTRY; 
	}

	if( RegSetValueEx(hKey, KEY_JHI_SERVICE_PORT ,0L, REG_DWORD, (CONST BYTE*) &portNumber, sizeof(DWORD)) == ERROR_SUCCESS)
	{
		TRACE0("write port number to registry success\n");
	}
	else 
	{
		TRACE0("write port number to registry failed\n");
		RegCloseKey(hKey);
		return JHI_ERROR_REGISTRY;
	}

	RegCloseKey(hKey);
	return JHI_SUCCESS;
}

JHI_RET_I
JhiWriteAddressTypeToRegistry(uint32_t addressType)
{
	HKEY hKey;
	LSTATUS status;

	// Check if Module is a valid number
	if ( (status = RegOpenKeyEx( REGISTRY_BASE,
		TEXT(REGISTRY_PATH),
		0,
		KEY_WRITE  | KEY_WOW64_64KEY,
		&hKey)) != ERROR_SUCCESS )
	{
		TRACE1( "Unable to open Registry [0x%x]\n", GetLastError());
		return JHI_ERROR_REGISTRY; 
	}

	if( RegSetValueEx(hKey, KEY_JHI_ADDRESS_TYPE ,0L, REG_DWORD, (CONST BYTE*) &addressType, sizeof(DWORD)) == ERROR_SUCCESS)
	{
		TRACE0("write address to registry success\n");
	}
	else 
	{
		TRACE0("write address to registry failed\n");
		RegCloseKey(hKey);
		return JHI_ERROR_REGISTRY;
	}

	RegCloseKey(hKey);
	return JHI_SUCCESS;
}