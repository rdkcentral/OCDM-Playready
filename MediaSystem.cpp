/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <vector>
#include <iostream>
#include <string.h>

#include <interfaces/IDRM.h>
#include "MediaSession.h"

#include "ScopedMutex2.h"

using namespace std;

std::shared_ptr<DRM_APP_CONTEXT> appContext_;

extern DRM_CONST_STRING g_dstrDrmPath;

WPEFramework::Core::CriticalSection drmAppContextMutex_;

static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = ONE_WCHAR(s[i], '\0');
    w[s.length()] = ONE_WCHAR('\0', '\0');
    return w;
}

static void PackedCharsToNative(DRM_CHAR *f_pPackedString, DRM_DWORD f_cch) {
    DRM_DWORD ich = 0;

    if( f_pPackedString == NULL
     || f_cch == 0 )
    {
        return;
    }
    for( ich = 1; ich <= f_cch; ich++ )
    {
        f_pPackedString[f_cch - ich] = ((DRM_BYTE*)f_pPackedString)[ f_cch - ich ];
    }
}

namespace CDMi {

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

public:
    PlayReady() {
    }

    ~PlayReady(void) {
    }

    CDMi_RESULT CreateMediaKeySession(
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData);
 
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {

        delete f_piMediaKeySession;

        return CDMi_SUCCESS; 
    }

    ////////////////////
    // Ext
    ////////////////////
    time_t GetDrmSystemTime() const override
    {
       fprintf(stderr, "%s:%d: PR is asked for system time\n", __FILE__, __LINE__);
       //return 46;

       ScopedMutex2 lock(drmAppContextMutex_);

       DRM_UINT64 utctime64;
       DRM_RESULT err = Drm_Clock_GetSystemTime(appContext_.get(), &utctime64);
       if (err != DRM_SUCCESS) {
       	fprintf(stderr, "Error: Drm_Clock_GetSystemTime returned 0x%lX\n", (long)err);
           // return invalid time
           return (time_t) -1;
       } else {
           //*time = (time_t)utctime64;
    	   return (time_t)utctime64;
       }

       return 0;

    }

    CDMi_RESULT CreateMediaKeySessionExt(uint32_t sessionId,
            const char contentId[],
            uint32_t contentIdLength,
            LicenseTypeExt licenseType,
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            IMediaKeySessionExt** session) override
	{

        *session = new CDMi::MediaKeySession(sessionId, contentId, contentIdLength, licenseType, drmHeader, drmHeaderLength);

        fprintf(stderr, "%s:%d: PR created a session\n", __FILE__, __LINE__);

        return CDMi_SUCCESS;
	}

    std::string GetVersionExt() const override
    {
		const uint32_t MAXLEN = 64;
		char versionStr[MAXLEN];
		if (g_dstrReqTagPlayReadyClientVersionData.cchString >= MAXLEN)
			return "";
		DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPlayReadyClientVersionData.pwszString,
				versionStr, MAXLEN);
		((DRM_BYTE*)versionStr)[g_dstrReqTagPlayReadyClientVersionData.cchString] = 0;
		PackedCharsToNative(versionStr, g_dstrReqTagPlayReadyClientVersionData.cchString + 1);

		return string(versionStr);
    }

    uint32_t GetLdlSessionLimit() const override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

        uint32_t ldlLimit = 0;
        DRM_RESULT err = Drm_LicenseAcq_GetLdlSessionsLimit_Netflix(appContext_.get(), &ldlLimit);
        if (err != DRM_SUCCESS) {
            fprintf(stderr, "Error: Drm_LicenseAcq_GetLdlSessionsLimit_Netflix returned 0x%lX\n", (long)err);
            return 0;
        }

        return ldlLimit;
    }

    CDMi_RESULT EnableSecureStop(bool enable) override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

        Drm_TurnSecureStop(static_cast<int>(enable));

        return 0;
    }

    CDMi_RESULT CommitSecureStop(
            const unsigned char sessionID[],
            uint32_t sessionIDLength,
            const unsigned char serverResponse[],
            uint32_t serverResponseLength) override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return 0;

        if(!sessionIDLength) {
            // TODO: argument error?
            fprintf(stderr, "Warning: sessionIDLength is zero.");
            return 1;
        }

        // convert our vector to the uuid, sessionID is only supposed to be 16 bytes long
        unsigned char uuid[TEE_SESSION_ID_LEN];
        memcpy(&uuid[0], &sessionID[0], TEE_SESSION_ID_LEN);

        // commit it
        DRM_RESULT err = Drm_CommitSecureStop(appContext_.get(), uuid);
        if (err != DRM_SUCCESS)
        {
        	// TODO: This call now fails sometimes with 0x80004005 (DRM_E_FAIL)
        	//       This seems to be introduced by 86d1dea5db7c4176920b91a50f894bb52039cd70 (Netflix Mutex -> WPEFramework CriticalSection)
            fprintf(stderr, "Drm_CommitSecureStop returned 0x%lx\n", (long)err);
        }

        return 0;
    }

    CDMi_RESULT CreateSystemNetflix(const std::string & readDir, const std::string & storeLocation) override
    {
    	cerr << "CreateSystemNetflix, readDir: " << readDir << endl;
    	cerr << "CreateSystemNetflix, storeLocation: " << storeLocation << endl;

    	// Clear DRM app context.
    	appContext_.reset();

        std::string rdir(readDir);

        // Create wchar strings from the arguments.
        drmdir_ = createDrmWchar(rdir);

        // Initialize Ocdm directory.
        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        // Store store location
    	std::string store(storeLocation);

        drmStore_.pwszString = createDrmWchar(store);
        drmStore_.cchString = store.length();
        drmStoreStr_ = store;

        // Init opaque buffer.
        appContextOpaqueBuffer_ = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

        // Init revocation buffer.
        pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

        return 0;
    }

    CDMi_RESULT InitSystemNetflix() override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

        DRM_RESULT err;

        // DRM Platform Initialization
        err = Drm_Platform_Initialize();
        if(DRM_FAILED(err))
        {
        	appContext_.reset();
            fprintf(stderr, "Error in Drm_Platform_Initialize: 0x%08lX\n", err);
            //return (OpenCDMError)ERROR_FAILED_TO_INIT;
            return 1;
        }

        // TODO: move app context to OpenCDMAccessor
        appContext_.reset(new DRM_APP_CONTEXT);
        memset(appContext_.get(), 0, sizeof(DRM_APP_CONTEXT));
        err  = Drm_Initialize(appContext_.get(), NULL,
                              appContextOpaqueBuffer_,
                              MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                              &drmStore_);
        if(DRM_FAILED(err)) {
        	appContext_.reset();
            fprintf(stderr, "Error in Drm_Initialize: 0x%08lX\n", err);
            //return (OpenCDMError)ERROR_FAILED_TO_INIT;
            return 1;
        }

        err = Drm_Revocation_SetBuffer(appContext_.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        if(DRM_FAILED(err))
        {
            appContext_.reset();
            fprintf(stderr, "Error in Drm_Revocation_SetBuffer: 0x%08lX\n", err);
            //return (OpenCDMError)ERROR_FAILED_TO_INIT;
            return 1;
        }

       //return ERROR_NONE;
        return 0;
    }

    CDMi_RESULT TeardownSystemNetflix() override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

        if(!appContext_.get() ) {
        	fprintf(stderr, "Error, no app context yet\n");
            return 1;
        }

        DRM_RESULT err;
        err = Drm_Reader_Commit(appContext_.get(), NULL, NULL);
        if(DRM_FAILED(err)) {
        	fprintf(stderr, "Warning, Drm_Reader_Commit returned 0x%08lX\n", err);
        }

        err = Drm_StoreMgmt_CleanupStore(appContext_.get(),
                                         DRM_STORE_CLEANUP_DELETE_EXPIRED_LICENSES |
                                         DRM_STORE_CLEANUP_DELETE_REMOVAL_DATE_LICENSES,
                                         NULL, 0, NULL);
        if(DRM_FAILED(err))
        {
        	fprintf(stderr, "Warning, Drm_StoreMgmt_CleanupStore returned 0x%08lX\n", err);
        	appContext_.reset();
        }
        // Uninitialize drm context
        Drm_Uninitialize(appContext_.get());
        appContext_.reset();

        // Unitialize platform
        err = Drm_Platform_Uninitialize();
        if(DRM_FAILED(err))
        {
        	appContext_.reset();
        }

        return 0;
    }

    CDMi_RESULT DeleteSecureStore() override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

    	DRM_RESULT err = Drm_DeleteSecureStore(&drmStore_);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_DeleteSecureStore returned 0x%lX\n", (long)err);
            return 1;
        }

        return 0;
    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) override
    {
        ScopedMutex2 lock(drmAppContextMutex_);

    	if (secureStoreHashLength < 256)
    	{
            fprintf(stderr, "Error: opencdm_get_secure_store_hash needs an array of size 256\n");
            return 1;
    	}

    	DRM_RESULT err = Drm_GetSecureStoreHash(&drmStore_, secureStoreHash);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_GetSecureStoreHash returned 0x%lX\n", (long)err);
            return 1;
        }

        return 0;
    }

private:
	DRM_WCHAR* drmdir_;
	DRM_CONST_STRING drmStore_;

	// TODO: do we need this string?
	std::string drmStoreStr_;

	DRM_BYTE *appContextOpaqueBuffer_ = nullptr;
	DRM_BYTE *pbRevocationBuffer_ = nullptr;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
