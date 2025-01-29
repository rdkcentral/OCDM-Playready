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
#pragma once

#include <drmbuild_oem.h>
#include <drmmanager.h>
#include <drmmathsafe.h>
#include <drmtypes.h>
#include <drmerr.h>
#include <drmerror.h>
#include <drmversionconstants.h>
#include <drmbytemanip.h>
#include <drmmanagertypes.h>
#include <drmconstants.h>

#if defined TEE_CONFIG_NEED
#include <playready_ca.h>
#endif /* TEE_CONFIG_NEED */

#undef min
#undef max
#undef __in
#undef __out

#include <string.h>
#include <vector>
#include <utility>
#include <memory>
#include <cdmi.h>
#include <core/Sync.h>

#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

#ifndef SIZEOF
#define SIZEOF sizeof
#endif

#ifdef DRM_ONE_CHAR
#define ONE_CHAR DRM_ONE_CHAR
#endif

#ifdef DRM_ONE_WCHAR
#define ONE_WCHAR DRM_ONE_WCHAR
#endif

#ifdef DRM_CREATE_DRM_STRING
#define CREATE_DRM_STRING DRM_CREATE_DRM_STRING
#endif

#define DRM_ERR_NAME( dr ) DRM_ERR_GetErrorNameFromCode( dr, nullptr )

#define DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP ((DRM_RESULT)0x8004dc80)
#define DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP22 ((DRM_RESULT)0x8004dc81)
typedef struct
{
    char pszGlobalDir[128];
    char pszApplicationDir[128];
}DRM_INIT_CONTEXT;

#define PR4ChkDR(expr) do {                           \
            dr = ( expr );                            \
            if( DRM_FAILED( dr ) )                    \
            {                                         \
                fprintf(stderr, "errcode: 0x%X; call: %s; infunc: %s()",dr, #expr, __func__); \
                goto ErrorExit;                       \
            }                                         \
        } while(0)

///////////////////////////////////////////////////////////////////
class KeyId
{
public:

    enum KeyIdOrder { KEYID_ORDER_GUID_LE, KEYID_ORDER_UUID_BE, KEYID_ORDER_UNKNOWN };

    static const KeyId EmptyKeyId;

    KeyId( const DRM_BYTE * , KeyIdOrder);
    void setKeyIdOrder(KeyIdOrder);
    KeyIdOrder getKeyIdOrder();
    const DRM_BYTE* getmBytes();
    DRM_RESULT  keyDecode( const DRM_CONST_STRING & );

    KeyId()
    { 
        m_hexStr.clear();
        m_base64Str.clear();
        ZEROMEM( m_bytes, DRM_ID_SIZE );
        keyIdOrder = KEYID_ORDER_UNKNOWN;       
    }
    ~KeyId(){ }

    const char* HexStr();
    const char* B64Str();
    KeyId& ToggleFormat();

    bool operator==( const KeyId &keyId );
    bool operator<( const KeyId &keyId ) const;
    bool operator!=( const KeyId &keyId )
    {
        return !( operator==(keyId) );
    };

private:
    DRM_BYTE m_bytes[ DRM_ID_SIZE ];

    std::string m_base64Str;

    std::string m_hexStr;

    KeyIdOrder keyIdOrder;
};

struct __DECRYPT_CONTEXT
{
    KeyId keyId;
    DRM_DECRYPT_CONTEXT oDrmDecryptContext;
    DRM_DECRYPT_CONTEXT oDrmDecryptAudioContext;

    __DECRYPT_CONTEXT()
    {
        memset( &oDrmDecryptContext, 0, sizeof( DRM_DECRYPT_CONTEXT ) );
        memset( &oDrmDecryptAudioContext, 0, sizeof( DRM_DECRYPT_CONTEXT ) );
    }
};

typedef std::shared_ptr<__DECRYPT_CONTEXT> DECRYPT_CONTEXT;

#define NEW_DECRYPT_CONTEXT() std::make_shared<__DECRYPT_CONTEXT>()

//////////////////////////////////////////////////////////////////
class SafeCriticalSection
{
public:
    explicit SafeCriticalSection(WPEFramework::Core::CriticalSection& lock) : mLock(lock), mLocked(false)
    {
        relock();
    }

    ~SafeCriticalSection()
    {
        unlock();
    }

    void unlock()
    {
        if (mLocked) {
            mLocked = false;
            mLock.Unlock();
        }
    }

    void relock()
    {
        if (!mLocked) {
            mLocked = true;
            mLock.Lock();
        }
    }

    WPEFramework::Core::CriticalSection &mutex() { return mLock; }
    const WPEFramework::Core::CriticalSection &mutex() const { return mLock; }
private:
    WPEFramework::Core::CriticalSection& mLock;
    bool mLocked;
};

namespace CDMi {

struct PlayreadyOutProtLevels
{
    uint16_t compressedDigitalVideoLevel;
    uint16_t uncompressedDigitalVideoLevel;
    uint16_t analogVideoLevel;
};


struct PlayLevels {
    uint16_t compressedDigitalVideoLevel_;
    uint16_t uncompressedDigitalVideoLevel_;
    uint16_t analogVideoLevel_;
    uint16_t compressedDigitalAudioLevel_;
    uint16_t uncompressedDigitalAudioLevel_;
};

class PlayreadySession
{
public:
    PlayreadySession();
    ~PlayreadySession();

    DRM_APP_CONTEXT *InitializeDRM(const DRM_CONST_STRING * pDRMStoreName);

    bool IsPlayreadySessionInit() { return m_bInitCalled; }

protected:
    DRM_APP_CONTEXT *m_poAppContext;

    DRM_BYTE *m_pbPROpaqueBuf;
    DRM_DWORD m_cbPROpaqueBuf;
    bool m_bInitCalled;
};

class MediaKeySession : public PlayreadySession , public IMediaKeySession , public IMediaKeySessionExt {
private:
    enum KeyState {
        // Has been initialized.
        KEY_INIT = 0,
        // Has a key message pending to be processed.
        KEY_PENDING = 1,
        // Has a usable key.
        KEY_READY = 2,
        // Has an error.
        KEY_ERROR = 3,
        // Has been closed.
        KEY_CLOSED = 4
    };
    enum MessageType {
        LicenseRequest = 0,
        LicenseRenewal = 1,
        LicenseRelease = 2,
        IndividualizationRequest = 3
    };
public:

    MediaKeySession(
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration = false);

    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration = false);
    ~MediaKeySession();

    bool playreadyGenerateKeyRequest();
    bool ready() const { return m_eKeyState == KEY_READY; }

    virtual void Run(
    const IMediaKeySessionCallback *f_piMediaKeySessionCallback);

    virtual CDMi_RESULT Load();

    virtual void Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse);

    virtual CDMi_RESULT Remove();

    virtual CDMi_RESULT Close(void);
    virtual CDMi_RESULT PlaybackStopped(void);

    virtual CDMi_RESULT SetParameter(const std::string& name, const std::string& value);
    virtual const char *GetSessionId(void) const;
    virtual const char *GetKeySystem(void) const;

    virtual CDMi_RESULT MediaKeySession::Decrypt(
        uint8_t*                 inData,
        const uint32_t           inDataLength,
        uint8_t**                outData,
        uint32_t*                outDataLength,
        const SampleInfo*        sampleInfo,
        const IStreamProperties* properties);

    virtual CDMi_RESULT ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque );

    static DRM_BOOL m_bPrintOPLError;

    uint32_t GetSessionIdExt(void) const;

    virtual CDMi_RESULT SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength);
    virtual CDMi_RESULT GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL);
    virtual CDMi_RESULT CancelChallengeDataExt();
    virtual CDMi_RESULT StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, unsigned char * secureStopId);
    virtual CDMi_RESULT SelectKeyId(const uint8_t keyLength, const uint8_t keyId[]);
    virtual CDMi_RESULT CleanDecryptContext();
    
    

private:
    std::vector< DECRYPT_CONTEXT > m_DecryptContextVector;

    static bool mMaxResDecodeSet;
    static uint64_t mMaxResDecodePixels;

    virtual CDMi_RESULT DRM_DecryptFailure(DRM_RESULT dr, const uint8_t *payloadData, uint32_t *f_pcbOpaqueClearContent, uint8_t **f_ppbOpaqueClearContent);

    struct PlayreadyOutProtLevels m_playreadyLevels;

    static DRM_RESULT DRM_CALL _PolicyCallback(const DRM_VOID *,
            DRM_POLICY_CALLBACK_TYPE f_dwCallbackType, const DRM_KID *,
            const DRM_LID *, const DRM_VOID *);

 
    DRM_BYTE *m_pbRevocationBuffer;
    KeyState m_eKeyState;
    DRM_CHAR m_rgchSessionID[CCH_BASE64_EQUIV(SIZEOF(DRM_ID)) + 1];
      
    DRM_BYTE *m_pbChallenge;
    DRM_DWORD m_cbChallenge;
    DRM_CHAR *m_pchSilentURL;  
    std::string m_customData;
    IMediaKeySessionCallback *m_piCallback;

    std::vector<uint8_t> mDrmHeader;
    uint32_t mSessionId;
    PlayLevels levels_;
    bool mInitiateChallengeGeneration;
    DRM_DWORD m_cHeaderKIDs;
    DRM_CONST_STRING *m_pdstrHeaderKIDs;
    eDRM_HEADER_VERSION m_eHeaderVersion;
    DRM_ID m_oBatchID;
    std::vector<std::pair<DRM_ID, DRM_ID>> m_oPersistentLicenses;
    DECRYPT_CONTEXT m_currentDecryptContext;
    SecureBufferInfo m_stSecureBuffInfo = {0};
#ifdef USE_SVP
    void* m_pSVPContext;
    unsigned int m_rpcID;
#endif
    CDMi_RESULT PersistentLicenseCheck();
    DRM_RESULT ProcessLicenseResponse(
                            DRM_PROCESS_LIC_RESPONSE_FLAG    f_eResponseFlag,
                    const   DRM_BYTE                        *f_pbResponse,
                            DRM_DWORD                        f_cbResponse,
                            DRM_LICENSE_RESPONSE            *f_pLiceneResponse );

    const char* MapDrToKeyMessage( DRM_RESULT );
    DRM_RESULT ReaderBind(
            const DRM_CONST_STRING *f_rgpdstrRights[],
            DRM_DWORD f_cRights,
            DRMPFNPOLICYCALLBACK  f_pfnPolicyCallback,
            const DRM_VOID             *f_pv,
            DRM_DECRYPT_CONTEXT *f_pcontextDecrypt );
    void UpdateFromLicenseResponse( DRM_LICENSE_RESPONSE & );
    DECRYPT_CONTEXT GetDecryptCtx( KeyId & );
    CDMi_RESULT SetKeyIdProperty( KeyId & f_rKeyId );
    CDMi_RESULT SetKeyIdProperty( const DRM_WCHAR *, DRM_DWORD );
    CDMi_RESULT BindKeyNow(DECRYPT_CONTEXT decryptContext);
    CDMi_RESULT BindKey(KeyId keyId);
    CDMi_RESULT Unbind(KeyId keyId);
    void CloseDecryptContexts();
    void DeleteInMemoryLicenses();
    void SaveTemporaryPersistentLicenses(const DRM_LICENSE_RESPONSE* f_poLicenseResponse);
    void DeleteTemporaryPersistentLicenses();
    const char* printGuid(KeyId &keyId);
    const char* printUuid(KeyId &keyId);    

protected:
    DRM_BOOL m_fCommit;
    DRM_APP_CONTEXT *m_poAppContext;
    bool m_decryptInited;
    bool m_bDRMInitializedLocally;
};

class CPRDrmPlatform
{
public:
    static DRM_RESULT DrmPlatformInitialize();
    static DRM_RESULT DrmPlatformInitialize( void * );
    static DRM_RESULT DrmPlatformUninitialize();
private:
    static DRM_DWORD m_dwInitRefCount;
    CPRDrmPlatform() { }
};

//extern DRM_INIT_CONTEXT g_oDrmInitContext;

} // namespace CDMi
