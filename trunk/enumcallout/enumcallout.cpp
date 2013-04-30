// enumcallout.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include <windows.h>
#include <Fwpmu.h>


HMODULE	fwdll = NULL;

typedef DWORD (WINAPI *PFNFWPMENGINEOPEN0)(
  _In_opt_  const wchar_t *serverName,
  _In_      UINT32 authnService,
  _In_opt_  SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
  _In_opt_  const FWPM_SESSION0 *session,
  _Out_     HANDLE *engineHandle
);

typedef DWORD (WINAPI *PFNFWPMENGINECLOSE0)(
  _In_  HANDLE engineHandle
);

typedef DWORD (WINAPI *PFNFWPMCALLOUTCREATEENUMHANDLE0) (
  _In_      HANDLE engineHandle,
  _In_opt_  const FWPM_CALLOUT_ENUM_TEMPLATE0 *enumTemplate,
  _Out_     HANDLE *enumHandle
);

typedef DWORD (WINAPI *PFNFWPMCALLOUTDESTROYENUMHANDLE0) (
  _In_  HANDLE engineHandle,
  _In_  HANDLE enumHandle
);

typedef DWORD (WINAPI *PFNFWPMCALLOUTENUM0) (
  _In_   HANDLE engineHandle,
  _In_   HANDLE enumHandle,
  _In_   UINT32 numEntriesRequested,
  _Out_  FWPM_CALLOUT0 ***entries,
  _Out_  UINT32 *numEntriesReturned
);


PFNFWPMENGINEOPEN0					pfnFwpmEngineOpen0 = NULL;
PFNFWPMENGINECLOSE0					pfnFwpmEngineClose0 = NULL;
PFNFWPMCALLOUTCREATEENUMHANDLE0		pfnFwpmCalloutCreateEnumHandle0 = NULL;
PFNFWPMCALLOUTDESTROYENUMHANDLE0	pfnFwpmCalloutDestroyEnumHandle0 = NULL;
PFNFWPMCALLOUTENUM0					pfnFwpmCalloutEnum0 = NULL;

BOOLEAN LoadAPI()
{
	fwdll = LoadLibrary(_T("Fwpuclnt.dll"));
	if(fwdll) {
		pfnFwpmEngineOpen0 = (PFNFWPMENGINEOPEN0)GetProcAddress(fwdll,"FwpmEngineOpen0");
		pfnFwpmEngineClose0 = (PFNFWPMENGINECLOSE0)GetProcAddress(fwdll,"FwpmEngineClose0");
		pfnFwpmCalloutCreateEnumHandle0 = (PFNFWPMCALLOUTCREATEENUMHANDLE0)GetProcAddress(fwdll,"FwpmCalloutCreateEnumHandle0");
		pfnFwpmCalloutDestroyEnumHandle0 = (PFNFWPMCALLOUTDESTROYENUMHANDLE0)GetProcAddress(fwdll,"FwpmCalloutDestroyEnumHandle0");
		pfnFwpmCalloutEnum0	= (PFNFWPMCALLOUTENUM0)GetProcAddress(fwdll,"FwpmCalloutEnum0");

		if(pfnFwpmEngineOpen0 && pfnFwpmEngineClose0 && pfnFwpmCalloutCreateEnumHandle0 && pfnFwpmCalloutDestroyEnumHandle0 && pfnFwpmCalloutEnum0) {
			return TRUE;
		}
		
	}
	
	
	return FALSE;
}

void UnLoadAPI()
{
	if(fwdll)
		FreeLibrary(fwdll);
	return;
}

HANDLE			engineHandle = NULL;
DWORD			result = ERROR_SUCCESS; 
HANDLE			enumHandle = 0;
FWPM_CALLOUT0**	ppCallouts = 0;
UINT32			numEntries = 0;

BOOLEAN HlprFwpmLayerIsUserMode(_In_ const GUID* pLayerKey)
{
   BOOLEAN isUserMode = FALSE;
   
   if(*pLayerKey == FWPM_LAYER_IPSEC_KM_DEMUX_V4 ||
      *pLayerKey == FWPM_LAYER_IPSEC_KM_DEMUX_V6 ||
      *pLayerKey == FWPM_LAYER_IPSEC_V4 ||
      *pLayerKey == FWPM_LAYER_IPSEC_V6 ||
      *pLayerKey == FWPM_LAYER_IKEEXT_V4 ||
      *pLayerKey == FWPM_LAYER_IKEEXT_V6 ||
      *pLayerKey == FWPM_LAYER_RPC_UM ||
      *pLayerKey == FWPM_LAYER_RPC_EPMAP ||
      *pLayerKey == FWPM_LAYER_RPC_EP_ADD ||
      *pLayerKey == FWPM_LAYER_RPC_PROXY_CONN ||
      *pLayerKey == FWPM_LAYER_RPC_PROXY_IF
#if 0
#if(NTDDI_VERSION >= NTDDI_WIN7)

      ||
      *pLayerKey == FWPM_LAYER_KM_AUTHORIZATION

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
#endif
	) {
     isUserMode = TRUE;
   }

   return isUserMode;
}
#include <locale.h>

int _tmain(int argc, _TCHAR* argv[])
{
	// Is WinVista or Later Version ?

	setlocale(LC_ALL, "");

	if(!LoadAPI()){
		printf("Fwpuclnt.dll load fail\n");
		return 0;
	}

		
	printf("Opening the filter engine.\n");
        
	result = pfnFwpmEngineOpen0(
						NULL, 
						RPC_C_AUTHN_WINNT, 
						NULL,
						NULL, 
						&engineHandle );

	if (result != ERROR_SUCCESS) {
		printf("FwpmEngineOpen0 failed. Return value: %d.\n", result); 
		return 0;
	} else {
		printf("Filter engine opened successfully.\n");
	}

	

	result = pfnFwpmCalloutCreateEnumHandle0(engineHandle,
											NULL,
											&enumHandle);
	if(result != NO_ERROR) {
		enumHandle = 0;
		printf(" FwpmCalloutCreateEnumHandle() [result: %#x]", result);
		pfnFwpmEngineClose0(engineHandle);
		return 0;
	}
	
	result = pfnFwpmCalloutEnum0(engineHandle,
                           enumHandle,
                           0xFFFFFFFF,
                           &ppCallouts,
                           &numEntries);

	if(result != NO_ERROR) {
		enumHandle = 0;
		printf(" FwpmCalloutEnum() [result: %#x]", result);
		pfnFwpmCalloutDestroyEnumHandle0(engineHandle, enumHandle);
		pfnFwpmEngineClose0(engineHandle);
		return 0;
	}

	for(UINT32 calloutIndex = 0 ; calloutIndex < numEntries; calloutIndex++) {
		
		if(HlprFwpmLayerIsUserMode(&(ppCallouts[calloutIndex]->applicableLayer))) {
			continue;
		}
		printf(" Callouts[%d] : %S desc:%S\n", calloutIndex, ppCallouts[calloutIndex]->displayData.name,ppCallouts[calloutIndex]->displayData.description);
		
	}


	pfnFwpmCalloutDestroyEnumHandle0(engineHandle, enumHandle);
	
	printf("enumHandle closed.\n");

	pfnFwpmEngineClose0(engineHandle);
	
	printf("Filter engine Handle closed.\n");

	UnLoadAPI();
	return 1;
}

