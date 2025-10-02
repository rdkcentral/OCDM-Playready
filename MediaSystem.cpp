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
#include "MediaSession.h"

#include <memory>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>
#include <cdmi.h>
#include <core/core.h>

#include <drmint64.h>

#define CLEAN_ON_INIT 1

#define DEVICESTORE_DIGEST_BYTES_SIZE OEM_SHA256_DIGEST_SIZE_IN_BYTES

#define ErrCheckCert() do {                                                \
            if ( m_pbPublisherCert == NULL || m_cbPublisherCert == 0 ) {   \
                fprintf(stderr, "SecureStop publisher certificate is not set."); \
                return CDMi_S_FALSE;                                       \
            }                                                              \
        }while( 0 )

using namespace std;

/* TO DO: temp fix to resolve build error */
#ifndef ENABLE_AMBIGUOUS_FIX
 extern DRM_CONST_STRING g_dstrDrmPath;
#endif

DRM_CONST_STRING g_dstrCDMDrmStoreName;

WPEFramework::Core::CriticalSection drmAppContextMutex_;

static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = ONE_WCHAR(s[i], '\0');
    w[s.length()] = ONE_WCHAR('\0', '\0');
    return w;
}

static void PackedCharsToNativeImpl(DRM_CHAR *f_pPackedString, DRM_DWORD f_cch) {
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

std::string GetDrmStorePath()
{
    const uint32_t MAXLEN = 256;
    char pathStr[MAXLEN];
    if (g_dstrCDMDrmStoreName.cchString >= MAXLEN)
        return "";
    DRM_UTL_DemoteUNICODEtoASCII(g_dstrCDMDrmStoreName.pwszString,
            pathStr, MAXLEN);
    ((DRM_BYTE*)pathStr)[g_dstrCDMDrmStoreName.cchString] = 0;
    PackedCharsToNativeImpl(pathStr, g_dstrCDMDrmStoreName.cchString + 1);

    return string(pathStr);
}

namespace CDMi {

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    class Config : public WPEFramework::Core::JSON::Container {
    private:
        Config& operator= (const Config&);

    public:
        Config () 
            : ReadDir()
            , StoreLocation() {
            Add("read-dir", &ReadDir);
            Add("store-location", &StoreLocation);
            Add("home-path", &HomePath);
        }
        Config (const Config& copy) 
            : ReadDir(copy.ReadDir)
            , StoreLocation(copy.StoreLocation)
            , HomePath(copy.HomePath) {
            Add("read-dir", &ReadDir);
            Add("store-location", &StoreLocation);
            Add("home-path", &HomePath);
        }
        virtual ~Config() {
        }

    public:
        WPEFramework::Core::JSON::String ReadDir;
        WPEFramework::Core::JSON::String StoreLocation;
        WPEFramework::Core::JSON::String HomePath;

        CDMi_RESULT SetSecureStopPublisherCert( const DRM_BYTE*, DRM_DWORD  );
    };

private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

    DRM_RESULT CleanLicenseStore()
    {
        return Drm_StoreMgmt_CleanupStore(m_poAppContext.get(),
                                         DRM_STORE_CLEANUP_DELETE_EXPIRED_LICENSES |
                                         DRM_STORE_CLEANUP_DELETE_REMOVAL_DATE_LICENSES,
                                         nullptr, 0, nullptr);
    }

public:

    PlayReady() :
       m_poAppContext(nullptr) {
    }

    ~PlayReady(void) {
        SAFE_OEM_FREE( m_pbPublisherCert );
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
            if(!m_isAppCtxInitialized)
            {
                InitializeAppCtx();
            }     
            *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData,  m_poAppContext.get(), !isNetflixPlayready);
         } else {
            *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_poAppContext.get(), !isNetflixPlayready);
         }
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetSecureStopPublisherCert( const DRM_BYTE *f_pbPublisherCert, DRM_DWORD f_cbPublisherCert )
    {
        if ( NULL == f_pbPublisherCert )
        {
            fprintf(stderr, "[%s:%d] f_pbPublisherCert should not be NULL",__FUNCTION__,__LINE__);
            return CDMi_FAIL;
        }
        if ( 0 == f_cbPublisherCert )
        {
            fprintf(stderr, "[%s:%d] f_pbPublisherCert should not be 0",__FUNCTION__,__LINE__);
            return CDMi_FAIL;
        }

        SAFE_OEM_FREE( m_pbPublisherCert );
        m_cbPublisherCert = 0;

        m_pbPublisherCert = (DRM_BYTE *)Oem_MemAlloc( f_cbPublisherCert );
        ZEROMEM( m_pbPublisherCert, f_cbPublisherCert );
        memcpy( m_pbPublisherCert, f_pbPublisherCert, f_cbPublisherCert );

        m_cbPublisherCert = f_cbPublisherCert;
        return CDMi_SUCCESS;
    }

    CDMi_RESULT SetServerCertificate( const uint8_t *f_pbServerCertificate, uint32_t f_cbServerCertificate)
    {
        CDMi_RESULT cr = CDMi_SUCCESS;
        if ( CDMi_FAILED( ( cr=SetSecureStopPublisherCert( f_pbServerCertificate, f_cbServerCertificate ) ) ) )
        {
            fprintf(stderr, "[%s:%d] SetSecureStopPublisherCert failed",__FUNCTION__,__LINE__);
        }
        return cr;
    }

    virtual CDMi_RESULT Metrics(uint32_t length, const uint8_t* buffer)
    {
       return CDMi_SUCCESS;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {
        MediaKeySession * mediaKeySession = dynamic_cast<MediaKeySession *>(f_piMediaKeySession);
        if ( mediaKeySession != nullptr )
        {
            delete f_piMediaKeySession;
        }
        else
        {
            fprintf(stderr, "[%s:%d] Expected a locally allocated MediaKeySession",__FUNCTION__,__LINE__);
        }
        return CDMi_SUCCESS;
    }
    
    uint64_t GetDrmSystemTime() const /* override */
    {
        DRM_RESULT dr                        = DRM_SUCCESS;
        DRM_SECURETIME_CLOCK_TYPE eClockType = DRM_SECURETIME_CLOCK_TYPE_INVALID;
        DRMFILETIME oftSystemTime            = { 0 };
        uint64_t ui64RetTime                 = (uint64_t) -1;

        SafeCriticalSection lock(drmAppContextMutex_);

        dr = Drm_SecureTime_GetValue( ( DRM_APP_CONTEXT* ) m_poAppContext.get(),
                &oftSystemTime, &eClockType );

        if ( dr != DRM_SUCCESS )
        {
            fprintf(stderr, "[%s:%d] Drm_SecureTime_GetValue failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
        }
        else if ( eClockType == DRM_SECURETIME_CLOCK_TYPE_INVALID )
        {
            fprintf(stderr, "[%s:%d] Drm_SecureTime_GetValue returned an invalid clock type",__FUNCTION__,__LINE__);
        }
        else
        {
            DRM_UINT64 ui64 = DRM_UI64LITERAL(0, 0);

            FILETIME_TO_UI64( oftSystemTime, ui64 );
            ui64RetTime = ( uint64_t ) DRM_UI2I64( ui64 );
        }

        return ui64RetTime;
    }

    CDMi_RESULT CreateMediaKeySessionExt(
            const std::string& keySystem,
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            IMediaKeySessionExt** session) /* override */
    {
        bool isNetflixPlayready = (strstr(keySystem.c_str(), "netflix") != nullptr);
        printf("\n [TEL ELXSI] isNetflixPlayready is %d",&isNetflixPlayready);
        *session = new CDMi::MediaKeySession(drmHeader, drmHeaderLength, m_poAppContext.get(), !isNetflixPlayready);

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DestroyMediaKeySessionExt(IMediaKeySession *f_piMediaKeySession)
    {
        SafeCriticalSection systemLock(drmAppContextMutex_);
        delete f_piMediaKeySession;
        return CDMi_SUCCESS;
    }

    std::string GetVersionExt() const /* override */
    {
        const uint32_t MAXLEN = 64;
        char versionStr[MAXLEN];
        if (g_dstrReqTagPlayReadyClientVersionData.cchString >= MAXLEN)
            return "";
        DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPlayReadyClientVersionData.pwszString,
                versionStr, MAXLEN);
        ((DRM_BYTE*)versionStr)[g_dstrReqTagPlayReadyClientVersionData.cchString] = 0;
        PackedCharsToNativeImpl(versionStr, g_dstrReqTagPlayReadyClientVersionData.cchString + 1);
        return string(versionStr);
    }

    uint32_t GetLdlSessionLimit() const /* override */
    {
        return ( uint32_t )DRM_MAX_NONCE_COUNT_PER_SESSION;
    }

    bool IsSecureStopEnabled() /* override */
    {
        return true;
    }

    CDMi_RESULT EnableSecureStop(bool enable) /* override */
    {
        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() /* override */
    {
        return 0;
    }

    /*Return a list of the current SecureStop sessions.*/
    CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint16_t idsLength, uint32_t & count)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        CDMi_RESULT cr           = CDMi_SUCCESS;
        DRM_ID     *pidSessions  = NULL;
        DRM_DWORD   cidSessions  = 0;
        DRM_DWORD   cBytesNeeded = 0;

        ErrCheckCert();

        DRM_RESULT err = Drm_SecureStop_EnumerateSessions(
                m_poAppContext.get(),
                m_cbPublisherCert,
                m_pbPublisherCert,
                &cidSessions,
                &pidSessions );

        if ( err == DRM_SUCCESS )
        {
            cBytesNeeded = cidSessions * DRM_ID_SIZE;
            if ( idsLength < cBytesNeeded )
            {
                count = cidSessions;
                cr = CDMi_S_FALSE;
            }
            else
            {
                count = cidSessions;

                for ( DRM_DWORD i = 0; i < count; ++i)
                {
                    memcpy(&ids[i * DRM_ID_SIZE], pidSessions[i].rgb, DRM_ID_SIZE);
                }
            }
        }
        else
        {
            fprintf(stderr, "[%s:%d] Drm_GetSecureStopIds returned: 0x%lx",__FUNCTION__,__LINE__,(long)err);
            cr = CDMi_S_FALSE;
        }

        SAFE_OEM_FREE( pidSessions );
        return cr;
    }

    /*Generate a SecureStop challenge to send to the server.*/
    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * f_pbChallenge,
            uint16_t & f_cbChallenge)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        if ( sessionIDLength < DRM_ID_SIZE )
        {
            fprintf(stderr, "[%s:%d] Invalid argument: sessionIDlength %zu expecting %zu",__FUNCTION__,__LINE__,sessionIDLength,DRM_ID_SIZE);
            return CDMi_INVALID_ARG;
        }

        if (f_cbChallenge == 0 || f_pbChallenge == nullptr )
        {
            fprintf(stderr, "[%s:%d] Invalid argument: challenge buffer is null",__FUNCTION__,__LINE__);
            return CDMi_INVALID_ARG;
        }

        ErrCheckCert();

        DRM_BYTE   *pbChallenge = NULL;
        DRM_DWORD   cbChallenge = 0;
        DRM_ID      SID         = DRM_ID_EMPTY;
        CDMi_RESULT cr          = CDMi_SUCCESS;

        ::memcpy( (void*)SID.rgb, (const void*)&sessionID[0], DRM_ID_SIZE );

        DRM_RESULT err = Drm_SecureStop_GenerateChallenge(
                m_poAppContext.get(),
                &SID,
                m_cbPublisherCert,
                m_pbPublisherCert,
                0,
                nullptr,
                &cbChallenge,
                &pbChallenge );

        if ( err != DRM_SUCCESS )
        {
            f_cbChallenge = 0;
            fprintf(stderr, "[%s:%d] Drm_SecureStop_GenerateChallenge failed. 0x%X - %s",__FUNCTION__,__LINE__,(long)err,DRM_ERR_NAME(err));
            cr = CDMi_S_FALSE;
        }
        else if ( f_cbChallenge < cbChallenge )
        {
            f_cbChallenge = (uint16_t)cbChallenge;
            fprintf(stderr, "[%s:%d] SecureStop challenge buffer is too small. %u, need %u",__FUNCTION__,__LINE__,f_cbChallenge,cbChallenge);
            cr = CDMi_S_FALSE;
        }
        else
        {
            f_cbChallenge = (uint16_t)cbChallenge;
            ::memcpy( f_pbChallenge, pbChallenge, f_cbChallenge );
        }

        SAFE_OEM_FREE( pbChallenge );

        return cr;
    }

    /*Process the response from the SecureStop server.*/
    CDMi_RESULT CommitSecureStop(
            const uint8_t f_sessionID[],
            uint32_t f_sessionIDLength,
            const uint8_t f_serverResponse[],
            uint32_t f_serverResponseLength) /* override */
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        ErrCheckCert();

        if ( f_sessionIDLength < DRM_ID_SIZE )
        {
            fprintf(stderr, "[%s:%d] Invalid argument: sessionIDlength %zu, expecting %zu ",__FUNCTION__,__LINE__,f_sessionIDLength,DRM_ID_SIZE);
            return CDMi_INVALID_ARG;
        }

        DRM_ID      SID             = DRM_ID_EMPTY;
        DRM_CHAR   *pcchCustomData  = NULL;
        DRM_DWORD   cchCustomData   = 0;
        CDMi_RESULT cr              = CDMi_SUCCESS;

        memcpy( (void*)SID.rgb, (const void*)&f_sessionID[0], DRM_ID_SIZE );

        DRM_RESULT err = Drm_SecureStop_ProcessResponse(
                m_poAppContext.get(),
                &SID,
                m_cbPublisherCert,
                m_pbPublisherCert,
                f_serverResponseLength,
                f_serverResponse,
                &cchCustomData,
                &pcchCustomData);

        if ( err == DRM_E_SECURESTOP_SESSION_NOT_FOUND )
        {
            cr = CDMi_S_FALSE;
        }
        else
        {
            fprintf(stderr, "[%s:%d] Drm_SecureStop_ProcessResponse failed. 0x%X - %s",__FUNCTION__,__LINE__,(long)err,DRM_ERR_NAME(err));
            cr = CDMi_S_FALSE;
        }
        SAFE_OEM_FREE( pcchCustomData ); 
        return cr;
    }

    CDMi_RESULT CreateSystemExt() /* override */
    {
        if (m_poAppContext.get() != nullptr) {
            m_poAppContext.reset();
        }

        std::string rdir(m_readDir);

        drmdir_ = createDrmWchar(rdir);

        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        // Store store location
        std::string store(m_storeLocation);

        g_dstrCDMDrmStoreName.pwszString = createDrmWchar(store);
        g_dstrCDMDrmStoreName.cchString = store.length();

        // Init revocation buffer.
        pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

        return CDMi_SUCCESS;
    }

    /*Initialize the PlayReady application context*/
    CDMi_RESULT InitializeAppCtx()
    {
        DRM_BYTE *appOpaqueBuffer = nullptr;
        DRM_VOID *pDrmOemContext = NULL;
        bool bIsInitSecureClockNeed = false;

        if (m_poAppContext.get() != nullptr) {
           m_poAppContext.reset();
        }

        m_poAppContext.reset(new DRM_APP_CONTEXT);

        // Init opaque buffer.
        appOpaqueBuffer = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

        ::memset(m_poAppContext.get(), 0, sizeof(DRM_APP_CONTEXT));

        svpGetDrmOEMContext(&pDrmOemContext);
        DRM_RESULT err  = Drm_Initialize(m_poAppContext.get(), pDrmOemContext,
                              appOpaqueBuffer,
                              MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                              &g_dstrCDMDrmStoreName);

        if((err == DRM_E_SECURESTOP_STORE_CORRUPT) || \
                (err == DRM_E_SECURESTORE_CORRUPT) || \
                (err == DRM_E_DST_CORRUPTED)) {

            //if drmstore file is corrupted, remove it and init again, playready will create a new one
            remove(GetDrmStorePath().c_str());

            err = Drm_Initialize(m_poAppContext.get(), pDrmOemContext,
                                appOpaqueBuffer,
                                MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                                &g_dstrCDMDrmStoreName );
        }

        if (DRM_FAILED(err)) {
            delete [] appOpaqueBuffer;
            m_poAppContext.reset();
            return CDMi_S_FALSE;
        }

        ::memset(pbRevocationBuffer_, 0, REVOCATION_BUFFER_SIZE);
        err = Drm_Revocation_SetBuffer(m_poAppContext.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        if(DRM_FAILED(err))
        {
            delete [] appOpaqueBuffer;
            m_poAppContext.reset();
            fprintf(stderr, "[%s:%d] Drm_Revocation_SetBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }

        bIsInitSecureClockNeed = svpIsSecureClockInitNeed();

        if(bIsInitSecureClockNeed)
        {
            DRMFILETIME               ftSystemTime; /* Initialized by Drm_SecureTime_GetValue */
            DRM_SECURETIME_CLOCK_TYPE eClockType;   /* Initialized by Drm_SecureTime_GetValue */

            CDMi_RESULT cr = CDMi_SUCCESS;
            DRM_RESULT dr = DRM_SUCCESS;

            dr = Drm_SecureTime_GetValue( m_poAppContext.get(), &ftSystemTime, &eClockType  );
            if (dr == DRM_E_CLK_NOT_SUPPORTED)  /* Secure Clock not supported, try the Anti-Rollback Clock */
            {
#if defined DRM_ANTI_ROLLBACK_CLOCK_SUPPORT
                DRMSYSTEMTIME   systemTime;
                struct timeval  tv;
                struct tm      *tm;

                printf("Secure Clock not supported, trying the Anti-Rollback Clock...");

                gettimeofday(&tv, nullptr);
                tm = gmtime(&tv.tv_sec);

                systemTime.wYear         = tm->tm_year+1900;
                systemTime.wMonth        = tm->tm_mon+1;
                systemTime.wDayOfWeek    = tm->tm_wday;
                systemTime.wDay          = tm->tm_mday;
                systemTime.wHour         = tm->tm_hour;
                systemTime.wMinute       = tm->tm_min;
                systemTime.wSecond       = tm->tm_sec;
                systemTime.wMilliseconds = tv.tv_usec/1000;


                if(Drm_AntiRollBackClock_Init(m_poAppContext.get(), &systemTime) != 0)
                {
                    printf("\n antoFailed to initiize Anti-Rollback Clock, quitting....");
                    return CDMi_S_FALSE;
                }
#else
            printf("Secure Clock and Anti-Rollback Clock is not supported...");
            return CDMi_S_FALSE;
#endif
            }
            else
            {
                if (dr != 0) {
                    printf("\nExpect platform to support Secure Clock or Anti-Rollback Clock. Possible certificate (error 0x%08X)", static_cast<unsigned int>(dr));
                    return CDMi_S_FALSE;
                }
            }
        }

        if( !svpLoadRevocationList())
        {
            return CDMi_S_FALSE;
        }

        m_isAppCtxInitialized = true;
        return CDMi_SUCCESS;
    }

    /*Unitialize the playready context and opaque buffer*/
    CDMi_RESULT UninitializeAppCtx()
    {
        DRM_BYTE *pbOldBuf = nullptr;
        DRM_DWORD cbOldBuf = 0;

        m_isAppCtxInitialized = false;

        if (m_poAppContext.get() == nullptr)
        {
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_GetOpaqueBuffer( m_poAppContext.get(), &pbOldBuf, &cbOldBuf );
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] Drm_GetOpaqueBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
        }

        Drm_Uninitialize(m_poAppContext.get());
        m_poAppContext.reset();

        if ( pbOldBuf ){
            delete [] pbOldBuf;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT InitSystemExt() /* override */
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_BYTE *appOpaqueBuffer = nullptr;

        DRM_RESULT err = CPRDrmPlatform::DrmPlatformInitialize();

        if(DRM_FAILED(err))
        {
            if (m_poAppContext.get() != nullptr) {
               m_poAppContext.reset();
            }
            fprintf(stderr, "[%s:%d] DrmPlatformInitialize failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }

        if (CDMi_SUCCESS != InitializeAppCtx())
        {
            fprintf(stderr, "[%s:%d] InitializeAppCtx failed.",__FUNCTION__,__LINE__);
            return CDMi_S_FALSE;
        }

#ifdef CLEAN_ON_INIT
        err = CleanLicenseStore();
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] CleanLicenseStore failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
        }
#endif
        return CDMi_SUCCESS;
    }

    void Deinitialize(const WPEFramework::PluginHost::IShell * shell)
    {
        TeardownSystemExt();
        /* We can do SoC specific de-init requirement for Playready */
        svpPlatformUninitializePlayready();
    }

    CDMi_RESULT TeardownSystemExt() /* override */
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        if(!m_poAppContext.get()) {
            fprintf(stderr, "[%s:%d] no app context yet",__FUNCTION__,__LINE__);
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = CleanLicenseStore();
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] CleanLicenseStore failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
        }

        if (CDMi_SUCCESS != UninitializeAppCtx() )
        {
            fprintf(stderr, "[%s:%d] UninitializeAppCtx failed.",__FUNCTION__,__LINE__);
        }

        delete [] pbRevocationBuffer_;

        delete [] drmdir_;
        delete [] g_dstrCDMDrmStoreName.pwszString;

        err = CPRDrmPlatform::DrmPlatformUninitialize();
        if(DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] DrmPlatformUninitialize failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteKeyStore() /* override */
    {
        return CDMi_S_FALSE;
    }

    CDMi_RESULT DeleteSecureStore() /* override */
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        struct stat buf;
        CDMi_RESULT cr = CDMi_SUCCESS;

        if (CDMi_SUCCESS != UninitializeAppCtx() )
        {
            fprintf(stderr, "[%s:%d] UninitializeAppCtx failed.",__FUNCTION__,__LINE__);
        }

        if (stat(m_storeLocation.c_str(), &buf) != -1)
        {
            int status = remove(m_storeLocation.c_str());
            if(status == 0)
            {
                cr = CDMi_SUCCESS;
            }
            else
            {
                fprintf(stderr, "[%s:%d] Failed to delete key store",__FUNCTION__,__LINE__);
                cr = CDMi_S_FALSE;
            }
        }
        else
            cr = CDMi_SUCCESS;

        return cr;
    }

    CDMi_RESULT GetKeyStoreHash(
            uint8_t keyStoreHash[],
            uint32_t keyStoreHashLength) // override
    {
        return CDMi_S_FALSE;
    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) // override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        CDMi_RESULT ret = CDMi_SUCCESS;

        FILE* const file = fopen(m_storeLocation.c_str(), "rb");
        if (!file)
             return CDMi_S_FALSE;

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int BUFSIZE = 32768;
        std::vector<unsigned char> buffer(BUFSIZE, 0);
        size_t bytesRead = 0;
        while ((bytesRead = fread(&buffer[0], 1, BUFSIZE, file))) {
            if (!SHA256_Update(&sha256, &buffer[0], bytesRead)) {
                ret = CDMi_S_FALSE;
                break;
            }
        }
        fclose(file);
        SHA256_Final(secureStoreHash, &sha256);

        return ret;
    }

    void OnSystemConfigurationAvailable(const std::string& configline)
    {
        Config config;
        config.FromString(configline);
        m_readDir = config.ReadDir.Value();
        m_storeLocation = config.StoreLocation.Value();

        svpGetDrmStoragePath(m_readDir, m_storePath, m_storeLocation);
 
        WPEFramework::Core::Directory(m_storePath.c_str()).CreatePath();
        WPEFramework::Core::Directory(m_readDir.c_str()).CreatePath();

        string homePath = config.HomePath.Value();
        if(!homePath.empty()) {
            WPEFramework::Core::SystemInfo::SetEnvironment(_T("HOME"), homePath.c_str());
        } else {
            fprintf(stderr, "[%s:%d] Warning : could not set HOME variable. SecureStop functionality may not work!",__FUNCTION__,__LINE__);
        }

        CreateSystemExt();

        InitSystemExt();
    }

    void Initialize(const WPEFramework::PluginHost::IShell * service, const std::string& configline)
    {
        /* We can do SoC specific requirement for Playready */
        svpPlatformInitializePlayready();
        OnSystemConfigurationAvailable(configline);
    }

private:
    DRM_WCHAR* drmdir_;

    DRM_BYTE *pbRevocationBuffer_ = nullptr;
    std::shared_ptr<DRM_APP_CONTEXT> m_poAppContext;

    string m_readDir;
    string m_storeLocation;
    string m_storePath;

    DRM_BYTE *m_pbPublisherCert = nullptr;
    DRM_DWORD m_cbPublisherCert = 0;
    bool m_isAppCtxInitialized = false;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
