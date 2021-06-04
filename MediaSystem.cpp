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

#include "MediaSession.h"
#include <interfaces/IDRM.h>
#include <plugins/plugins.h>

// <plugins/plugins.h> has its own TRACING mechanism. We do not want to use those, undefine it here to avoid a warning.
// with the TRACE macro of the PLAYREADY software.
#undef TRACE

using namespace std;
using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;

extern DRM_CONST_STRING g_dstrDrmPath;

Core::CriticalSection drmAppContextMutex_;

static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
#ifdef PR_3_3
        w[i] = DRM_ONE_WCHAR(s[i], '\0');
    w[s.length()] = DRM_ONE_WCHAR('\0', '\0');
#else
        w[i] = ONE_WCHAR(s[i], '\0');
    w[s.length()] = ONE_WCHAR('\0', '\0');
#endif
    return w;
}

static void PackedCharsToNative(DRM_CHAR *f_pPackedString, DRM_DWORD f_cch) {
    DRM_DWORD ich = 0;

    if( f_pPackedString == nullptr
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
    PlayReady() :
       m_poAppContext(nullptr) {
    }

    ~PlayReady(void) {
        if (m_poAppContext)
            Drm_Uninitialize(m_poAppContext.get());
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string & keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        bool isNetflixPlayready = (strstr(keySystem.c_str(), "netflix") != nullptr);
        if (isNetflixPlayready) {
           // TODO: why is the order different when dealing with netflix?
           *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbCDMData, f_cbCDMData, f_pbInitData, f_cbInitData, m_poAppContext.get(), !isNetflixPlayready);
        } else {
           *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_poAppContext.get(), !isNetflixPlayready);
        }
 
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {
        SafeCriticalSection systemLock(drmAppContextMutex_);
        MediaKeySession * mediaKeySession = dynamic_cast<MediaKeySession *>(f_piMediaKeySession);
        ASSERT((mediaKeySession != nullptr) && "Expected a locally allocated MediaKeySession");

        delete f_piMediaKeySession;
        return CDMi_SUCCESS; 
    }

    ////////////////////
    // Ext
    ////////////////////
    uint64_t GetDrmSystemTime() const override
    {
       fprintf(stderr, "%s:%d: PR is asked for system time\n", __FILE__, __LINE__);

       SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
       DRM_UINT64 utctime64;
       DRM_RESULT err = Drm_Clock_GetSystemTime(m_poAppContext.get(), &utctime64);
       if (err != DRM_SUCCESS) {
           fprintf(stderr, "Error: Drm_Clock_GetSystemTime returned 0x%lX\n", (long)err);
           // return invalid time
           return static_cast<uint64_t>(-1);
       } else {
           return static_cast<uint64_t>(utctime64);
       }
#endif

       return 0;

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
        SafeCriticalSection lock(drmAppContextMutex_);

        ASSERT(m_poAppContext.get() != nullptr);

        uint32_t ldlLimit = 0;
#ifdef NETFLIX
        DRM_RESULT err = Drm_LicenseAcq_GetLdlSessionsLimit_Netflix(m_poAppContext.get(), &ldlLimit);
        if (err != DRM_SUCCESS) {
            fprintf(stderr, "Error: Drm_LicenseAcq_GetLdlSessionsLimit_Netflix returned 0x%lX\n", (long)err);
            return 0;
        }
#endif

        return ldlLimit;
    }

    bool IsSecureStopEnabled() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
#ifdef NETFLIX
        return static_cast<bool>(Drm_SupportSecureStop());
#else
        return false;
#endif
    }

    CDMi_RESULT EnableSecureStop(bool enable) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
#ifdef NETFLIX
        Drm_TurnSecureStop(static_cast<int>(enable));
#endif

        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        // if secure stop is not supported, return
        DRM_WORD numDeleted = 0;
#ifdef NETFLIX
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return 0;

        DRM_RESULT err = Drm_ResetSecureStops(m_poAppContext.get(), &numDeleted);
        if (err != DRM_SUCCESS) {
            fprintf(stderr, "Drm_ResetSecureStops returned 0x%lx\n", (long)err);
        }
#endif
        return numDeleted;
    }

    CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint16_t, uint32_t & count)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return NotAllowed
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        DRM_BYTE sessionIds[TEE_MAX_NUM_SECURE_STOPS][TEE_SESSION_ID_LEN];
        DRM_RESULT err = Drm_GetSecureStopIds(m_poAppContext.get(), sessionIds, &count);
        if (err != DRM_SUCCESS) {
            fprintf(stderr,"Drm_GetSecureStopIds returned 0x%lx\n", (long)err);
            return CDMi_S_FALSE;
        }

        for (int i = 0; i < count; ++i) {
            memcpy(&ids[i * TEE_SESSION_ID_LEN], sessionIds[i], TEE_SESSION_ID_LEN);
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * rawData,
            uint16_t & rawSize)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        if (!sessionIDLength) {
            fprintf(stderr, "Drm_GetSecureStop sessionID length %zu", sessionIDLength);
            return CDMi_S_FALSE;
        }

        // convert our vector to the uuid, sessionID is only supposed to be 16 bytes long
        uint8_t uuid[TEE_SESSION_ID_LEN];
        memcpy(&uuid[0], &sessionID[0], TEE_SESSION_ID_LEN);

        const uint16_t maxRawSize = rawSize;

        DRM_BYTE* passedRawData;

        if ((rawData == nullptr) && (rawSize == 0)) {
            // PlayReady checks against NULL pointer even if size is 0
            uint8_t tmpBuffer;
            rawSize = sizeof(tmpBuffer);
            passedRawData = static_cast<DRM_BYTE*>(&tmpBuffer);
        } else {
            passedRawData = static_cast<DRM_BYTE*>(rawData);
        }

        DRM_RESULT err = Drm_GetSecureStop(m_poAppContext.get(), uuid, passedRawData, &rawSize);
        if (DRM_FAILED(err)) {
            if ((err != DRM_E_BUFFERTOOSMALL) || (maxRawSize != 0)) {
                fprintf(stderr, "Drm_GetSecureStop returned 0x%lx\n", (long)err);
            }
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT CommitSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            const uint8_t serverResponse[],
            uint32_t serverResponseLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        if(!sessionIDLength) {
            fprintf(stderr, "Warning: sessionIDLength is zero.\n");
            return CDMi_INVALID_ARG;
        }


        // convert our vector to the uuid, sessionID is only supposed to be 16 bytes long
        uint8_t uuid[TEE_SESSION_ID_LEN];
        memcpy(&uuid[0], &sessionID[0], TEE_SESSION_ID_LEN);

        // commit it
        DRM_RESULT err = Drm_CommitSecureStop(m_poAppContext.get(), uuid);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Drm_CommitSecureStop returned 0x%lx\n", (long)err);
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteKeyStore() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        DRM_RESULT err = Drm_DeleteKeyStore();
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_DeleteKeyStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteSecureStore() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        DRM_RESULT err = Drm_DeleteSecureStore(&drmStore_);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_DeleteSecureStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetKeyStoreHash(
            uint8_t keyStoreHash[],
            uint32_t keyStoreHashLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        if (keyStoreHashLength < 256)
        {
            fprintf(stderr, "Error: opencdm_get_secure_store_hash needs an array of size 256\n");
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_GetKeyStoreHash(keyStoreHash);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_GetSecureStoreHash returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        if (secureStoreHashLength < 256)
        {
            fprintf(stderr, "Error: opencdm_get_secure_store_hash needs an array of size 256\n");
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_GetSecureStoreHash(&drmStore_, secureStoreHash);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_GetSecureStoreHash returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    void Initialize(const WPEFramework::PluginHost::IShell * shell, const std::string& /* configline */)
    {
        string persistentPath = shell->PersistentPath();
        string statePath = persistentPath + "/state"; // To store rollback clock state etc
        m_readDir = persistentPath + "/playready";
        m_storeLocation = persistentPath + "/playready/storage/drmstore";

        Core::Directory stateDir(statePath.c_str());
        stateDir.Create();

        Core::SystemInfo::SetEnvironment(_T("HOME"), statePath);

        ASSERT(m_poAppContext.get() == nullptr);

        std::string rdir(m_readDir);

        // Create wchar strings from the arguments.
        drmdir_ = createDrmWchar(rdir);

        // Initialize Ocdm directory.
        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        // Store store location
        std::string store(m_storeLocation);

        drmStore_.pwszString = createDrmWchar(store);
        drmStore_.cchString = store.length();

        // Init opaque buffer.
        appContextOpaqueBuffer_ = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

        // Init revocation buffer.
        pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

        //return CDMi_SUCCESS;

        // TODO: this is just a move from InitSystemExt
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_RESULT err;

        // DRM Platform Initialization
#ifdef PR_3_3
        err = Drm_Platform_Initialize(nullptr);
#else
        err = Drm_Platform_Initialize();
#endif
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "Error in Drm_Platform_Initialize: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        std::unique_ptr<DRM_APP_CONTEXT> appCtx;
        appCtx.reset(new DRM_APP_CONTEXT);

        memset(appCtx.get(), 0, sizeof(DRM_APP_CONTEXT));
        err  = Drm_Initialize(appCtx.get(), nullptr,
                              appContextOpaqueBuffer_,
                              MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                              &drmStore_);
        if(DRM_FAILED(err)) {
            fprintf(stderr, "Error in Drm_Initialize: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        m_poAppContext.swap(appCtx);
        err = Drm_Revocation_SetBuffer(m_poAppContext.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "Error in Drm_Revocation_SetBuffer: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        //return CDMi_SUCCESS;
    }

private:
    DRM_WCHAR* drmdir_;
    DRM_CONST_STRING drmStore_;

    DRM_BYTE *appContextOpaqueBuffer_ = nullptr;
    DRM_BYTE *pbRevocationBuffer_ = nullptr;
    std::unique_ptr<DRM_APP_CONTEXT> m_poAppContext;

    string m_readDir;
    string m_storeLocation;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
