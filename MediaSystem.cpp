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

#include <plugins/plugins.h>
//#include <cdmi.h>
#include <interfaces/IDRM.h>
#include <memory>
#include <vector>
#include <iostream>
#include <string.h>

// <plugins/plugins.h> has its own TRACING mechanism. We do not want to use those, undefine it here to avoid a warning.
// with the TRACE macro of the PLAYREADY software.
#undef TRACE

#include "MediaSession.h"

using namespace std;
using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;

extern DRM_CONST_STRING g_dstrDrmPath;

Core::CriticalSection drmAppContextMutex_;

static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = ONE_WCHAR(s[i], '\0');
    w[s.length()] = ONE_WCHAR('\0', '\0');
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
        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_poAppContext.get(), !isNetflixPlayready);
 
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {
        MediaKeySession * mediaKeySession = dynamic_cast<MediaKeySession *>(f_piMediaKeySession);
        ASSERT((mediaKeySession != nullptr) && "Expected a locally allocated MediaKeySession");

        // TODO: is this call still needed? Can't we move it to the destructor?
        mediaKeySession->UninitializeContext();
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

       DRM_UINT64 utctime64;
       DRM_RESULT err = Drm_Clock_GetSystemTime(m_poAppContext.get(), &utctime64);
       if (err != DRM_SUCCESS) {
           fprintf(stderr, "Error: Drm_Clock_GetSystemTime returned 0x%lX\n", (long)err);
           // return invalid time
           return static_cast<uint64_t>(-1);
       } else {
           return static_cast<uint64_t>(utctime64);
       }

       return 0;

    }

    CDMi_RESULT DestroyMediaKeySessionExt(IMediaKeySession *f_piMediaKeySession)
    {
        SafeCriticalSection systemLock(drmAppContextMutex_);
        delete f_piMediaKeySession;

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
        SafeCriticalSection lock(drmAppContextMutex_);

        uint32_t ldlLimit = 0;
        DRM_RESULT err = Drm_LicenseAcq_GetLdlSessionsLimit_Netflix(m_poAppContext.get(), &ldlLimit);
        if (err != DRM_SUCCESS) {
            fprintf(stderr, "Error: Drm_LicenseAcq_GetLdlSessionsLimit_Netflix returned 0x%lX\n", (long)err);
            return 0;
        }

        return ldlLimit;
    }

    bool IsSecureStopEnabled() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        return static_cast<bool>(Drm_SupportSecureStop());
    }

    CDMi_RESULT EnableSecureStop(bool enable) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        Drm_TurnSecureStop(static_cast<int>(enable));

        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return 0;

        DRM_WORD numDeleted = 0;
        DRM_RESULT err = Drm_ResetSecureStops(m_poAppContext.get(), &numDeleted);
        if (err != DRM_SUCCESS) {
            fprintf(stderr, "Drm_ResetSecureStops returned 0x%lx\n", (long)err);
        }
        return numDeleted;
    }

    CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint8_t, uint32_t & count)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

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

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * rawData,
            uint16_t & rawSize)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

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

        // PlayReady doesn't like valid pointer + size 0
        DRM_BYTE* passedRawData = static_cast<DRM_BYTE*>(rawData);
        DRM_RESULT err = Drm_GetSecureStop(m_poAppContext.get(), uuid, passedRawData, &rawSize);
        if (err != DRM_E_BUFFERTOOSMALL) {
            fprintf(stderr, "Drm_GetSecureStop(0) returned 0x%lx\n", (long)err);
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT CommitSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            const uint8_t serverResponse[],
            uint32_t serverResponseLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

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

        return CDMi_SUCCESS;
    }

    CDMi_RESULT CreateSystemExt() override
    {
        // Clear DRM app context.
        if (m_poAppContext.get() != nullptr) {
            m_poAppContext.reset();
        }

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

        return CDMi_SUCCESS;
    }

    CDMi_RESULT InitSystemExt() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_RESULT err;

        // DRM Platform Initialization
        err = Drm_Platform_Initialize();
        if(DRM_FAILED(err))
        {
            if (m_poAppContext.get() != nullptr) {
               m_poAppContext.reset();
            }
            fprintf(stderr, "Error in Drm_Platform_Initialize: 0x%08lX\n", err);
            return CDMi_S_FALSE;
        }
        
        if (m_poAppContext.get() != nullptr) {
           m_poAppContext.reset();
        }

        // TODO: move app context to OpenCDMAccessor
        m_poAppContext.reset(new DRM_APP_CONTEXT);

        memset(m_poAppContext.get(), 0, sizeof(DRM_APP_CONTEXT));
        err  = Drm_Initialize(m_poAppContext.get(), nullptr,
                              appContextOpaqueBuffer_,
                              MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                              &drmStore_);
        if(DRM_FAILED(err)) {
            m_poAppContext.reset();
            fprintf(stderr, "Error in Drm_Initialize: 0x%08lX\n", err);
            return CDMi_S_FALSE;
        }

        err = Drm_Revocation_SetBuffer(m_poAppContext.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        if(DRM_FAILED(err))
        {
            m_poAppContext.reset();
            fprintf(stderr, "Error in Drm_Revocation_SetBuffer: 0x%08lX\n", err);
            return CDMi_S_FALSE;
        }

        //return ERROR_NONE;
        return CDMi_SUCCESS;
    }

    CDMi_RESULT TeardownSystemExt() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        if(!m_poAppContext.get()) {
            fprintf(stderr, "Error, no app context yet\n");
            return CDMi_S_FALSE;
        }

        DRM_RESULT err;
        err = Drm_Reader_Commit(m_poAppContext.get(), nullptr, nullptr);
        if(DRM_FAILED(err)) {
            fprintf(stderr, "Warning, Drm_Reader_Commit returned 0x%08lX\n", err);
        }

        err = Drm_StoreMgmt_CleanupStore(m_poAppContext.get(),
                                         DRM_STORE_CLEANUP_DELETE_EXPIRED_LICENSES |
                                         DRM_STORE_CLEANUP_DELETE_REMOVAL_DATE_LICENSES,
                                         nullptr, 0, nullptr);
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "Warning, Drm_StoreMgmt_CleanupStore returned 0x%08lX\n", err);
        }
        // Uninitialize drm context
        Drm_Uninitialize(m_poAppContext.get());
        m_poAppContext.reset();

        // Unitialize platform
        err = Drm_Platform_Uninitialize();
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "Failed to call Drm_Platform_Unitialize\n");
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteKeyStore() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_RESULT err = Drm_DeleteKeyStore();
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_DeleteKeyStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteSecureStore() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_RESULT err = Drm_DeleteSecureStore(&drmStore_);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr, "Error: Drm_DeleteSecureStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetKeyStoreHash(
            uint8_t keyStoreHash[],
            uint32_t keyStoreHashLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

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

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

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

        return CDMi_SUCCESS;
    }

    void OnSystemConfigurationAvailable(const PluginHost::IShell * shell, const std::string& configline)
    {
        string persistentPath = shell->PersistentPath() + string("/playready");
        string statePath = persistentPath + "/state"; // To store rollback clock state etc
        m_readDir = persistentPath + "/playready";
        m_storeLocation = persistentPath + "/playready/storage/drmstore";

        Core::Directory stateDir(statePath.c_str());
        stateDir.Create();

        Core::SystemInfo::SetEnvironment(_T("HOME"), statePath);
    }

private:
    DRM_WCHAR* drmdir_;
    DRM_CONST_STRING drmStore_;

    DRM_BYTE *appContextOpaqueBuffer_ = nullptr;
    DRM_BYTE *pbRevocationBuffer_ = nullptr;
    std::shared_ptr<DRM_APP_CONTEXT> m_poAppContext;

    string m_readDir;
    string m_storeLocation;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
