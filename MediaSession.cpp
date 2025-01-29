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
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>
#include <sys/utsname.h>
#include <drmresults.h>

#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;
extern DRM_CONST_STRING g_dstrCDMDrmStoreName;

#define NYI_KEYSYSTEM "keysystem-placeholder"

#ifdef DRM_WCHAR_CAST
#define WCHAR_CAST DRM_WCHAR_CAST
#endif

#ifdef DRM_CREATE_DRM_STRING
#define CREATE_DRM_STRING DRM_CREATE_DRM_STRING
#endif

#ifdef DRM_EMPTY_DRM_STRING
#define EMPTY_DRM_STRING DRM_EMPTY_DRM_STRING
#endif

#ifdef DRM_NO_OF
#define NO_OF DRM_NO_OF
#endif

#define DEVCERT_WAIT_SECS 30
#define DEVCERT_RETRY_MAX 4

#define EXPECTED_AES_CTR_IVDATA_SIZE (8)
#define EXPECTED_AES_CBC_IVDATA_SIZE (16)
using namespace std;

KeyId::KeyId( const DRM_BYTE *f_pBytes , KeyIdOrder keyOrder)
{
    m_hexStr.clear();
    m_base64Str.clear();
    ZEROMEM( m_bytes, DRM_ID_SIZE );
    keyIdOrder = KEYID_ORDER_UNKNOWN;
    memcpy( m_bytes, f_pBytes, DRM_ID_SIZE );
    keyIdOrder = keyOrder;
}

DRM_RESULT KeyId::keyDecode( const DRM_CONST_STRING &f_pdstrB64 ){

    DRM_DWORD cBytes = DRM_ID_SIZE;
	DRM_RESULT dr = DRM_B64_DecodeW( &f_pdstrB64, &cBytes, getmBytes(), 0 );
	if ( dr != DRM_SUCCESS )
	{
		fprintf(stderr, "\n[keyDecode] DRM_B64_DecodeW Failed");
	}
	return dr;
}

void KeyId::setKeyIdOrder(KeyIdOrder keyOrder)
{
    keyIdOrder = keyOrder;
}

KeyId::KeyIdOrder KeyId::getKeyIdOrder()
{
    return keyIdOrder;
}

const DRM_BYTE* KeyId::getmBytes()
{
    return m_bytes;
}

KeyId& KeyId::ToggleFormat()
{
    DRM_BYTE tmp;

    if ( keyIdOrder != KEYID_ORDER_UNKNOWN )
    {
        tmp = m_bytes[3];
        m_bytes[3] = m_bytes[0];
        m_bytes[0] = tmp;
        tmp = m_bytes[2];
        m_bytes[2] = m_bytes[1];
        m_bytes[1] = tmp;
        tmp = m_bytes[5];
        m_bytes[5] = m_bytes[4];
        m_bytes[4] = tmp;
        tmp = m_bytes[7];
        m_bytes[7] = m_bytes[6];
        m_bytes[6] = tmp;

        if ( keyIdOrder == KEYID_ORDER_GUID_LE )
            keyIdOrder = KEYID_ORDER_UUID_BE;
        else
            keyIdOrder = KEYID_ORDER_GUID_LE;
    }
    m_hexStr.clear();
    m_base64Str.clear();

    return *this;
}

bool KeyId::operator< ( const KeyId &keyId ) const
{
    if ( memcmp(keyId.m_bytes, m_bytes, DRM_ID_SIZE) < 0 )
        return true;
    return false;
}

bool KeyId::operator== ( const KeyId &keyId )
{
    bool areEqual = false;

    if ( memcmp(&m_bytes[8], &(keyId.m_bytes[8]), 8) == 0 )
    {
        if ( memcmp(keyId.m_bytes, m_bytes, 8) == 0 )
        {
            areEqual = true;
        }
        else
        {
            ToggleFormat();
            areEqual = ( memcmp(keyId.m_bytes, m_bytes, DRM_ID_SIZE ) == 0 );
            ToggleFormat();
        }
    }

    return areEqual;
}

const char* KeyId::HexStr()
{
    if ( m_hexStr.empty() )
    {
        char hex[64];
        ::memset(hex, 0, 64);
        for (int i = 0; i < DRM_ID_SIZE; i++)
        {
            hex[i * 2] = "0123456789abcdef"[m_bytes[i] >> 4];
            hex[i * 2 + 1] = "0123456789abcdef"[m_bytes[i] & 0x0F];
        }
        m_hexStr = hex;
    }

    return m_hexStr.c_str();
}

const char* KeyId::B64Str()
{
    DRM_RESULT dr = DRM_SUCCESS;
    if ( m_base64Str.empty() )
    {
        char b64[64];
        DRM_DWORD cbB64 = 64;
        ::memset( b64, 0, 64 );
        PR4ChkDR( DRM_B64_EncodeA( m_bytes, DRM_ID_SIZE, b64, &cbB64, 0 ) );

        m_base64Str = b64;
    }

    ErrorExit:

    return m_base64Str.c_str();
}

namespace CDMi {

namespace {

void Swap(uint8_t& lhs, uint8_t& rhs)
{
    uint8_t tmp =lhs;
    lhs = rhs;
    rhs = tmp;
}

}

const DRM_CONST_STRING *g_rgpdstrRights[1] = {&g_dstrDRM_RIGHT_PLAYBACK};

uint64_t MediaKeySession::mMaxResDecodePixels = 0;
bool MediaKeySession::mMaxResDecodeSet = false;

WPEFramework::Core::CriticalSection prPlatformMutex_;
WPEFramework::Core::CriticalSection prSessionMutex_;
DRM_DWORD CPRDrmPlatform::m_dwInitRefCount = 0;

/*Parsing the first playready init header from _initData_. In success case the header will be stored in _output_*/
bool parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
      
    };

    while (!input.IsEOF()) {
      size_t startPosition = input.pos();

      uint64_t atomSize;

      if (!input.Read4Into8(&atomSize)) {
        return false;
      }

      std::vector<uint8_t> atomType;
      if (!input.ReadVec(&atomType, 4)) {
          return false;
      }

      if (atomSize == 1) {
          if (!input.Read8(&atomSize)) {
              return false;
          }
      } else if (atomSize == 0) {
        atomSize = input.size() - startPosition;
      }

      if (memcmp(&atomType[0], "pssh", 4)) {
          if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
            return false;
          }
          continue;
      }

      uint8_t version;
      if (!input.Read1(&version)) {
          return false;
      }


      if (version > 1) {
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      if (!input.SkipBytes(3)) {
        return false;
      }

      std::vector<uint8_t> systemId;
      if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
        return false;
      }

      if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      if (version == 1) {
        uint32_t numKeyIds;
        if (!input.Read4(&numKeyIds)) {
          return false;
        }

        if (!input.SkipBytes(numKeyIds * 16)) {
          return false;
        }
      }

      uint32_t dataLength;
      if (!input.Read4(&dataLength)) {
        return false;
      }

      output->clear();
      if (!input.ReadString(output, dataLength)) {
        return false;
      }

      return true;
  }

  return false;
}

/*
 * f_pContext(input) : It could be NULL or Valid pointer
 */
DRM_RESULT CPRDrmPlatform::DrmPlatformInitialize( void *f_pContext )
{
    DRM_RESULT dr = DRM_SUCCESS;
    SafeCriticalSection systemLock(prPlatformMutex_);

    if ( ++m_dwInitRefCount == 1 )
    {
        DRM_RESULT dr = DRM_SUCCESS;
        DRM_DWORD cAttempts = 0;

        while( ( dr=Drm_Platform_Initialize( f_pContext ) ) == DRM_E_DEPRECATED_DEVCERT_READ_ERROR) {

            Drm_Platform_Uninitialize( (void *)nullptr );

            if ( cAttempts >= DEVCERT_RETRY_MAX ){
                ChkDR( DRM_E_DEPRECATED_DEVCERT_READ_ERROR);
            }
            sleep( DEVCERT_WAIT_SECS );
            ++cAttempts;
        }
    }

    ErrorExit:

    if ( DRM_FAILED( dr ) )
    {
        --m_dwInitRefCount;
        fprintf(stderr, "[%s:%d] failed. 0x%X",__FUNCTION__,__LINE__,dr);
    }

    return dr;
}

DRM_RESULT CPRDrmPlatform::DrmPlatformInitialize()
{
    void *pPlatformInitData = NULL;
    svpGetDrmPlatformInitData( &pPlatformInitData);
    return DrmPlatformInitialize( (void *)pPlatformInitData );
}

DRM_RESULT CPRDrmPlatform::DrmPlatformUninitialize()
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_VOID *pDrmOemContext = NULL;

    SafeCriticalSection systemLock(prPlatformMutex_);

    if ( m_dwInitRefCount == 0 )
    {
        fprintf(stderr, "[%s:%d] ref count is already 0",__FUNCTION__,__LINE__);
        ChkDR( DRM_E_FAIL );
    }
    else if ( --m_dwInitRefCount == 0 )
    {
        svpGetDrmOEMContext(&pDrmOemContext);

        if ( DRM_FAILED( (dr=Drm_Platform_Uninitialize( (void *)pDrmOemContext ) ) ) )
        {
            fprintf(stderr, "[%s:%d] Drm_Platform_Uninitialize failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            goto ErrorExit;
        }
    }

    ErrorExit:

    if ( DRM_FAILED( dr ) )
    {
        fprintf(stderr, "[%s:%d]  failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
    }

    return dr;

}

/*Get the version and list of keyids from the header*/
DRM_RESULT Header_GetInfo(
        const DRM_CONST_STRING      *f_pdstrWRMHEADER,
              eDRM_HEADER_VERSION   *f_pHeaderVersion,
              DRM_CONST_STRING     **f_ppdstrKIDs,
              DRM_DWORD             *f_pcbKIDs)
{
    DRM_RESULT          dr              = DRM_SUCCESS;
    DRM_DWORD           cKIDs           = 0;
    DRM_CONST_STRING   *pdstrKIDs       = NULL;

    PR4ChkDR( DRM_HDR_GetHeaderVersion( f_pdstrWRMHEADER, f_pHeaderVersion ) );

    PR4ChkDR( DRM_HDR_GetAttribute(
         f_pdstrWRMHEADER,
         NULL,
         DRM_HEADER_ATTRIB_KIDS,
         NULL,
         &cKIDs,
         &pdstrKIDs,
         0 ) );

    *f_ppdstrKIDs = pdstrKIDs;
    *f_pcbKIDs = cKIDs;

ErrorExit:
    return dr;
}

PlayreadySession::PlayreadySession() 
    : m_poAppContext(nullptr)
    , m_pbPROpaqueBuf(nullptr)
    , m_cbPROpaqueBuf(0)
    , m_bInitCalled(false)
{
  void *pPlatformInitData = NULL;
  svpGetDrmPlatformInitData( &pPlatformInitData);

  if ( DRM_FAILED( CPRDrmPlatform::DrmPlatformInitialize( pPlatformInitData ) ) )
  {
      fprintf(stderr, "[%s:%d] DrmPlatformInitialize failed.",__FUNCTION__,__LINE__);
  }
}

PlayreadySession::~PlayreadySession()
{
    SafeCriticalSection systemLock(prSessionMutex_);

    if ( IsPlayreadySessionInit() )
    {
        SAFE_OEM_FREE(m_pbPROpaqueBuf);
        m_cbPROpaqueBuf = 0;

        if (m_poAppContext != nullptr)
        {
            Drm_Uninitialize(m_poAppContext);
            SAFE_OEM_FREE(m_poAppContext);
            m_poAppContext = nullptr;
        }
    }

    if (DRM_FAILED(CPRDrmPlatform::DrmPlatformUninitialize()))
    {
        fprintf(stderr, "[%s:%d] DrmPlatformUninitialize failed.",__FUNCTION__,__LINE__);
    }

}

DRM_APP_CONTEXT * PlayreadySession::InitializeDRM(const DRM_CONST_STRING * pDRMStoreName)
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_VOID *pDrmOemContext = nullptr;

    SafeCriticalSection systemLock(prSessionMutex_);

    m_bInitCalled = true;

    if (m_poAppContext == nullptr)
    {
        ChkMem( m_pbPROpaqueBuf = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE) );
        ZEROMEM(m_pbPROpaqueBuf, MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE);
        m_cbPROpaqueBuf = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

        ChkMem( m_poAppContext = (DRM_APP_CONTEXT * )Oem_MemAlloc( sizeof(DRM_APP_CONTEXT) ) );
        ZEROMEM( m_poAppContext, sizeof(DRM_APP_CONTEXT) );

        svpGetDrmOEMContext(&pDrmOemContext);
        dr = Drm_Initialize(m_poAppContext, pDrmOemContext, m_pbPROpaqueBuf, m_cbPROpaqueBuf, pDRMStoreName);
        if (dr != DRM_SUCCESS)
        {
            ChkDR(Drm_Initialize(m_poAppContext, pDrmOemContext, m_pbPROpaqueBuf, m_cbPROpaqueBuf, pDRMStoreName));
        }
  }
  else
  {
      DRM_RESULT err = Drm_Reinitialize(m_poAppContext);
      if (DRM_FAILED(err))
      {
          fprintf(stderr, "[%s:%d] Drm_Reinitialize failed. 0x%lX - %s",__FUNCTION__,__LINE__,(long )err,DRM_ERR_NAME(err));
      }
  }

  return m_poAppContext;

ErrorExit:
  if (DRM_FAILED(dr)) {
    fprintf(stderr, "[%s:%d]  failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
  }
  return nullptr;    
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration /* = false */)
    : m_pbRevocationBuffer(nullptr)
    , m_eKeyState(KEY_CLOSED)
    , m_pbChallenge(nullptr)
    , m_cbChallenge(0)
    , m_pchSilentURL(nullptr) 
    , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
    , m_piCallback(nullptr)
    , mSessionId(0)
    , mInitiateChallengeGeneration(initiateChallengeGeneration)
    , m_cHeaderKIDs(0)
    , m_pdstrHeaderKIDs( nullptr )
    , m_eHeaderVersion( DRM_HEADER_VERSION_UNKNOWN )
    , m_oBatchID( DRM_ID_EMPTY )
    , m_currentDecryptContext( nullptr )
#ifdef USE_SVP
    , m_pSVPContext(nullptr)
    , m_rpcID(0)
#endif
    , m_fCommit(FALSE)
    , m_poAppContext(poAppContext)
    , m_decryptInited(false)
    , m_bDRMInitializedLocally(false)
{
  DRM_RESULT          dr            = DRM_SUCCESS;
  DRM_ID              oSessionID    = DRM_ID_EMPTY;
  DRM_CONST_STRING    dstrWRMHEADER = DRM_EMPTY_DRM_STRING;

  DRM_DWORD cchEncodedSessionID = SIZEOF(m_rgchSessionID);

#ifdef USE_SVP
  gst_svp_ext_get_context(&m_pSVPContext, Client, 0);

  m_stSecureBuffInfo.bCreateSecureMemRegion = true;
  m_stSecureBuffInfo.SecureMemRegionSize = 512 * 1024;

  if( 0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
  {
      /* No need to break here */
      m_stSecureBuffInfo.SecureMemRegionSize = 0;
  }
#endif

  std::string initData(reinterpret_cast<const char*>(f_pbInitData), f_cbInitData);
  std::string playreadyInitData;

  ChkBOOL(m_eKeyState == KEY_CLOSED, DRM_E_INVALIDARG);

  mMaxResDecodePixels = 0;
  mMaxResDecodeSet = false;

  if (m_poAppContext == nullptr) {
      m_poAppContext = InitializeDRM(&g_dstrCDMDrmStoreName);
  }

  if (DRM_REVOCATION_IsRevocationSupported()) {
    ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

    ChkDR(Drm_Revocation_SetBuffer(m_poAppContext,
                                   m_pbRevocationBuffer,
                                   REVOCATION_BUFFER_SIZE));
  }
      
  ChkDR(Oem_Random_GetBytes(nullptr, (DRM_BYTE *)&oSessionID, SIZEOF(oSessionID)));
  ZEROMEM(m_rgchSessionID, SIZEOF(m_rgchSessionID));

  ChkDR(DRM_B64_EncodeA((DRM_BYTE *)&oSessionID,
                        SIZEOF(oSessionID),
                        m_rgchSessionID,
                        &cchEncodedSessionID,
                        0));

  if (!parsePlayreadyInitializationData(initData, &playreadyInitData)) {
      playreadyInitData = initData;
  }

  mDrmHeader.resize( playreadyInitData.size() );
 ::memcpy( &mDrmHeader[ 0 ],
         reinterpret_cast<const DRM_BYTE*>(playreadyInitData.data()),
                                playreadyInitData.size() );

  ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_AUTODETECT_HEADER,
                                &mDrmHeader[ 0 ],
                                mDrmHeader.size()) );

  DRM_CONST_DSTR_FROM_PB( &dstrWRMHEADER, &mDrmHeader[ 0 ], mDrmHeader.size() );

  ChkDR( Header_GetInfo( &dstrWRMHEADER,
                                     &m_eHeaderVersion,
                                     &m_pdstrHeaderKIDs,
                                     &m_cHeaderKIDs ) );

      for( DRM_DWORD idx = 0; idx < m_cHeaderKIDs; idx++ )
      {
          KeyId kid , kid2;
          DRM_DWORD cBytes = DRM_ID_SIZE;
          DRM_DWORD cBytes2 = DRM_ID_SIZE;

          DRM_RESULT dr = DRM_B64_DecodeW( &m_pdstrHeaderKIDs[ idx ], &cBytes, kid.getmBytes(), 0 );
          if ( dr == DRM_SUCCESS )
          {
            kid.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);
          }  

          DRM_RESULT dr2 = DRM_B64_DecodeW( &m_pdstrHeaderKIDs[ idx ], &cBytes2, kid2.getmBytes(), 0 );
          if ( dr2 == DRM_SUCCESS )
          {
            kid2.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);
          }
      }

  m_eKeyState = KEY_INIT;

ErrorExit:

    if (DRM_FAILED(dr))
    {
        m_eKeyState = KEY_ERROR;
        fprintf(stderr, "[%s:%d]  Playready initialization error: 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
    }

  return;
}

MediaKeySession::~MediaKeySession(void)
{
    mMaxResDecodePixels = 0;
    mMaxResDecodeSet = false;
    Close();

}

const char* MediaKeySession::printGuid(KeyId &keyId)
{
    if (keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_UUID_BE)
           keyId.ToggleFormat();
        return keyId.B64Str();
}

const char* MediaKeySession::printUuid(KeyId &keyId)
{
    if (keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_GUID_LE)
           keyId.ToggleFormat();
        return keyId.B64Str();
}

const char *MediaKeySession::GetSessionId(void) const {
  return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM;
}

DRM_RESULT DRM_CALL MediaKeySession::_PolicyCallback(
    const DRM_VOID *f_pvOutputLevelsData, 
    DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
    const DRM_KID *f_pKID,
    const DRM_LID *f_pLID,
    const DRM_VOID *f_pv) {
    DRM_RESULT res = DRM_SUCCESS;

    switch (f_dwCallbackType)
    {
        case DRM_PLAY_OPL_CALLBACK:
        {
            const DRM_PLAY_OPL_LATEST * const opl = static_cast<const DRM_PLAY_OPL_LATEST *>(f_pvOutputLevelsData);
            assert(opl->dwVersion == VER_DRM_PLAY_OPL_LATEST);

            /* MaxResDecode */
            const DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_IDS_LATEST &dvopi = opl->dvopi;
            assert(dvopi.dwVersion == VER_DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_IDS_LATEST);
            for (size_t i = 0; i < dvopi.cEntries; ++i)
            {
                const DRM_OUTPUT_PROTECTION_LATEST &entry = dvopi.rgVop[i];
                if (DRM_IDENTICAL_GUIDS(&entry.guidId, &g_guidMaxResDecode))
                {
                    assert(entry.dwVersion == VER_DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_LATEST);

                    uint32_t mrdWidth = (uint32_t)(entry.rgbConfigData[0] << 24 | entry.rgbConfigData[1] << 16 | entry.rgbConfigData[2] << 8 | entry.rgbConfigData[3]);
                    uint32_t mrdHeight = (uint32_t)(entry.rgbConfigData[4] << 24 | entry.rgbConfigData[5] << 16 | entry.rgbConfigData[6] << 8 | entry.rgbConfigData[7]);
                    

                    mMaxResDecodePixels = mrdWidth*mrdHeight;
                    mMaxResDecodeSet = true;
                    res = DRM_SUCCESS;
                    break;
                }
            }
            break;
        }
        default:
            // ignored
            res = DRM_SUCCESS;
            break;
    }

    return res;
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {
  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

    if (mInitiateChallengeGeneration) {
      if ( CDMi_SUCCESS != PersistentLicenseCheck() ) {
          playreadyGenerateKeyRequest();
      }
    }
  } else {
      m_piCallback = nullptr;
  }
}

bool MediaKeySession::playreadyGenerateKeyRequest() {

  DRM_RESULT dr = DRM_SUCCESS;
  DRM_DWORD cchSilentURL = 0;
  SAFE_OEM_FREE( m_pbChallenge );
  SAFE_OEM_FREE( m_pchSilentURL );

  m_cbChallenge = 0;

  ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_AUTODETECT_HEADER,
                                &mDrmHeader[ 0 ],
                                mDrmHeader.size()) );

  dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        nullptr,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size(),
                                        nullptr,
                                        &cchSilentURL,
                                        nullptr,
                                        nullptr,
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        &m_oBatchID );

  if ( dr == DRM_E_NO_URL )
  {
      dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        nullptr,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                         m_customData.size() ,
                                        nullptr,
                                        nullptr,  // null pointer to buffer size
                                        nullptr,
                                        nullptr,
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        &m_oBatchID );
  }

  if (dr == DRM_E_BUFFERTOOSMALL)
  {
        if (cchSilentURL > 0)
        {
            ChkMem( m_pchSilentURL = (DRM_CHAR * )Oem_MemAlloc(cchSilentURL + 1));
            ZEROMEM( m_pchSilentURL, cchSilentURL + 1 );
        }

        if ( m_cbChallenge > 0 )
        {
            ChkMem( m_pbChallenge = (DRM_BYTE * )Oem_MemAlloc( m_cbChallenge + 1 ) );
            ZEROMEM( m_pbChallenge, m_cbChallenge + 1 );
        }

    dr = DRM_SUCCESS;
  }
  else
  {
    ChkDR(dr);
  }

  ChkDR(Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                         g_rgpdstrRights,
                                         sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                         NULL,
                                         !m_customData.empty() ? m_customData.c_str() : nullptr,
                                         m_customData.size(),
                                         m_pchSilentURL,
                                         cchSilentURL ? &cchSilentURL : nullptr,
                                         nullptr,
                                         nullptr,
                                         m_pbChallenge,
                                         &m_cbChallenge,
                                         &m_oBatchID ) );


  m_eKeyState = KEY_PENDING;

  if (m_piCallback)
     m_piCallback->OnKeyMessage((const uint8_t *) m_pbChallenge, m_cbChallenge,
                m_pchSilentURL != NULL ? (char *)m_pchSilentURL : "" );

ErrorExit:
  if (DRM_FAILED(dr)) {
    fprintf(stderr, "[%s:%d]  failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));

    if(m_piCallback)
    {
        m_piCallback->OnError( 0, CDMi_S_FALSE, "KeyError" );
        m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage(dr), nullptr, 0);
        m_piCallback->OnKeyStatusesUpdated();
    }
    m_eKeyState = KEY_ERROR;
  }

  return ( dr == DRM_SUCCESS );
}

CDMi_RESULT MediaKeySession::Load(void) {
  return CDMi_S_FALSE;
}

/*Set KeyId property which will be used by the Reader_Bind during license searching*/
CDMi_RESULT MediaKeySession::SetKeyIdProperty( const DRM_WCHAR *f_rgwchEncodedKid, DRM_DWORD f_cchEncodedKid ){
    DRM_RESULT err = Drm_Content_SetProperty(
            m_poAppContext,
            DRM_CSP_AUTODETECT_HEADER,
            (DRM_BYTE*)f_rgwchEncodedKid,
            f_cchEncodedKid * sizeof( DRM_WCHAR ) );

    if (DRM_FAILED(err)) {
        fprintf(stderr, "[%s:%d] Drm_Content_SetProperty DRM_CSP_AUTODETECT_HEADER failed. 0x%08X - %s",__FUNCTION__,__LINE__,static_cast<unsigned int>(err),DRM_ERR_NAME(err));
        return CDMi_FAIL;
    }

    return CDMi_SUCCESS;
}

/*Converting KeyId into base64-encoded format*/
CDMi_RESULT MediaKeySession::SetKeyIdProperty( KeyId & f_rKeyId ){
    DRM_WCHAR rgwchEncodedKid[CCH_BASE64_EQUIV(DRM_ID_SIZE)]= {0};
    DRM_DWORD cchEncodedKid = CCH_BASE64_EQUIV(DRM_ID_SIZE);

    if ( f_rKeyId.getKeyIdOrder() == KeyId::KEYID_ORDER_UUID_BE )
    {
        f_rKeyId.ToggleFormat();
    }

    DRM_RESULT err = DRM_B64_EncodeW( f_rKeyId.getmBytes(), DRM_ID_SIZE,
            rgwchEncodedKid, &cchEncodedKid, 0);

    if (DRM_FAILED(err)) {
        fprintf(stderr, "[%s:%d] DRM_B64_EncodeW failed. 0x%08X - %s",__FUNCTION__,__LINE__,static_cast<unsigned int>(err),DRM_ERR_NAME(err));
        return CDMi_FAIL;
    }
    return SetKeyIdProperty( rgwchEncodedKid, cchEncodedKid );
}

/*handles all the licenses in the response using Drm_LicenseAcq_ProcessResponse().*/
DRM_RESULT MediaKeySession::ProcessLicenseResponse(
                DRM_PROCESS_LIC_RESPONSE_FLAG    f_eResponseFlag,
        const   DRM_BYTE                        *f_pbResponse,
                DRM_DWORD                        f_cbResponse,
                DRM_LICENSE_RESPONSE            *f_pLiceneResponse ) {
    DRM_RESULT dr = DRM_SUCCESS;

    dr = Drm_LicenseAcq_ProcessResponse(
            m_poAppContext,
            f_eResponseFlag,
            f_pbResponse,
            f_cbResponse,
            f_pLiceneResponse );

    if ( dr == DRM_E_LICACQ_TOO_MANY_LICENSES )
    {
        DRM_DWORD cLicenses = f_pLiceneResponse->m_cAcks;
        f_pLiceneResponse->m_pAcks = ( DRM_LICENSE_ACK * )Oem_MemAlloc( cLicenses * sizeof( DRM_LICENSE_ACK ) );
        f_pLiceneResponse->m_cMaxAcks = cLicenses;

        dr = Drm_LicenseAcq_ProcessResponse(
                m_poAppContext,
                f_eResponseFlag,
                f_pbResponse,
                f_cbResponse,
                f_pLiceneResponse );
    }
    return dr;
}

/*Wrapper function for Drm_Reader_Bind()*/
DRM_RESULT MediaKeySession::ReaderBind(
            const DRM_CONST_STRING *f_rgpdstrRights[],
            DRM_DWORD f_cRights,
            DRMPFNPOLICYCALLBACK  f_pfnPolicyCallback,
            const DRM_VOID             *f_pv,
            DRM_DECRYPT_CONTEXT *f_pDecryptContext ) {
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_BYTE *newOpaqueBuffer = nullptr;

    while( (dr=Drm_Reader_Bind(
                    m_poAppContext,
                    f_rgpdstrRights,
                    f_cRights,
                    f_pfnPolicyCallback,
                    f_pv,
                    f_pDecryptContext ) ) == DRM_E_BUFFERTOOSMALL ){
                    

        DRM_BYTE *pbOldBuf = nullptr;
        DRM_DWORD cbOldBuf = 0;

        if ( m_cbPROpaqueBuf == 0 )
            m_cbPROpaqueBuf = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

        m_cbPROpaqueBuf *= 2;

        if ( m_cbPROpaqueBuf > MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE * 64 ){
            ChkDR( DRM_E_OUTOFMEMORY );
        }

        ChkMem( newOpaqueBuffer = ( DRM_BYTE* )Oem_MemAlloc( m_cbPROpaqueBuf ) );

        dr = Drm_GetOpaqueBuffer( m_poAppContext, &pbOldBuf, &cbOldBuf );
        if ( DRM_FAILED( dr ) ){
            fprintf(stderr, "[%s:%d] Drm_GetOpaqueBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            SAFE_OEM_FREE( newOpaqueBuffer );
            ChkDR( dr );
        }

        dr = Drm_ResizeOpaqueBuffer( m_poAppContext, newOpaqueBuffer, m_cbPROpaqueBuf );
        if ( DRM_FAILED( dr ) ){
            fprintf(stderr, "[%s:%d] Drm_ResizeOpaqueBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            SAFE_OEM_FREE( newOpaqueBuffer );
            ChkDR( dr );
        }

        if ( m_pbPROpaqueBuf != nullptr && m_pbPROpaqueBuf == pbOldBuf ){
            SAFE_OEM_FREE( pbOldBuf );
            m_pbPROpaqueBuf = newOpaqueBuffer;
        }else{
            SAFE_OEM_FREE( pbOldBuf );
        }
    }

    ErrorExit:
    if ( DRM_FAILED( dr ) ){
        fprintf(stderr, "[%s:%d] failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
    }

    return dr;
}

CDMi_RESULT MediaKeySession::PersistentLicenseCheck() {
#ifdef NO_PERSISTENT_LICENSE_CHECK
    // DELIA-51437: The Webkit EME implementation used by OTT apps
    // such as Amazon and YouTube fails when the key is usable from
    // just the init data.  Webkit is expecting a license request
    // message and the lack of this message prevents the session from
    // loading correctly.
    //
    // The EME concept of a persistent session uses the Session Id to
    // reload a session, not the raw Key ID.  We do not current
    // support that type of session in the OCDM.  Apps wishing to use
    // persistent keys should directly link to PR4 or the OCDM should
    // be rewritten to use PR4's CDMI API
    // (modules/cdmi/real/drmcdmireal.c).
    fprintf(stderr, "\n PersistentLicenseCheck: skipping persistent check");
    return CDMi_S_FALSE;
#else
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_CONTENT_SET_PROPERTY eContentPropertyType = DRM_CSP_HEADER_NOT_SET;

    if ( !mDrmHeader.size() ) {
        fprintf(stderr, "[%s:%d] mDrmHeader not set",__FUNCTION__,__LINE__);
        return CDMi_FAIL;
    }
    if ( m_pdstrHeaderKIDs == NULL || m_cHeaderKIDs == 0 ){
        fprintf(stderr, "[%s:%d] key ids not set",__FUNCTION__,__LINE__);
        return CDMi_FAIL;
    }

    if ( m_eHeaderVersion == DRM_HEADER_VERSION_4_2 )
        eContentPropertyType = DRM_CSP_V4_2_HEADER;
    else if ( m_eHeaderVersion == DRM_HEADER_VERSION_4_3 )
        eContentPropertyType = DRM_CSP_V4_3_HEADER;
    else{
        eContentPropertyType = DRM_CSP_AUTODETECT_HEADER;
    }

    for( DRM_DWORD idx = 0; idx < m_cHeaderKIDs; idx++ ){

        KeyId keyId;
		keyId.keyDecode(m_pdstrHeaderKIDs[ idx ]);
        keyId.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);

        DECRYPT_CONTEXT decryptContext;

        if ( CDMi_SUCCESS != SetKeyIdProperty( m_pdstrHeaderKIDs[idx].pwszString,
                m_pdstrHeaderKIDs[idx].cchString ) ) {
            fprintf(stderr, "[%s:%d] SetKeyIdProperty failed. %s",__FUNCTION__,__LINE__,printGuid(keyId));
            ChkDR( DRM_E_FAIL );
        }

        decryptContext = NEW_DECRYPT_CONTEXT();

        dr = ReaderBind(
                    g_rgpdstrRights,
                    NO_OF(g_rgpdstrRights),
                    _PolicyCallback,
                    &m_playreadyLevels,
                    &(decryptContext->oDrmDecryptContext) );
        if ( DRM_FAILED( dr ) ){
            ChkDR( dr );
        }

        decryptContext->keyId = keyId;
        m_DecryptContextVector.push_back(decryptContext);
    }

ErrorExit:

    if ( DRM_FAILED( dr ) ){
        CloseDecryptContexts();
        return CDMi_FAIL;
    }

    if ( m_piCallback )
    {
        for (DECRYPT_CONTEXT &p : m_DecryptContextVector)
        {
            m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage( dr ), p->keyId.getmBytes(), DRM_ID_SIZE);
        }
        m_piCallback->OnKeyStatusesUpdated();
    }

    m_eKeyState = KEY_READY;

    return CDMi_SUCCESS;
#endif
}

// Allow persistent PlayReady licenses to be used in a temporary
// session.
//
// Ideally, the license server would only return temporary licenses
// and would could block all persistent license with the
// `DRM_PROCESS_LIC_RESPONSE_FLAG` value of
// `DRM_PROCESS_LIC_RESPONSE_BLOCK_PERSISTENT_LICENSES`.
//
// Instead, we allow persistent licenses to be used but attempt to
// clean them up when the session closes.
void MediaKeySession::SaveTemporaryPersistentLicenses(const DRM_LICENSE_RESPONSE* f_poLicenseResponse) {

    fprintf(stderr, "\n SaveTemporaryPersistentLicenses: response has persistent licenses: %s",
         f_poLicenseResponse->m_fHasPersistentLicenses ? "true" : "false");

    if (!f_poLicenseResponse->m_fHasPersistentLicenses) {
        return;
    }

    // We know there are persistent license but not which ones.  Save
    // them all for deletion when we close a session.
    for (DRM_DWORD i = 0; i < f_poLicenseResponse->m_cAcks; ++i) {
        const DRM_LICENSE_ACK *pLicenseAck = nullptr;

        pLicenseAck = f_poLicenseResponse->m_pAcks != nullptr
            ? &f_poLicenseResponse->m_pAcks[ i ] : &f_poLicenseResponse->m_rgoAcks[ i ];

        if ( DRM_SUCCEEDED( pLicenseAck->m_dwResult ) ) {
            m_oPersistentLicenses.emplace_back(pLicenseAck->m_oKID, pLicenseAck->m_oLID);
        }
    }
}

void MediaKeySession::DeleteTemporaryPersistentLicenses() {
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_CONST_STRING          dstrKID              = DRM_EMPTY_DRM_STRING;
    DRM_CONST_STRING          dstrLID              = DRM_EMPTY_DRM_STRING;
    DRM_DWORD                 cbstrKID             = 0;
    DRM_DWORD cLicDeleted = 0;

    fprintf(stderr, "\n DeleteTemporaryPersistentLicenses: deleting %zd possibly persistent licenses",
         m_oPersistentLicenses.size());

    /* Allocate strKID buffer */
    cbstrKID = CCH_BASE64_EQUIV( sizeof( DRM_ID ) ) * sizeof( DRM_WCHAR );
    ChkMem( dstrKID.pwszString = (DRM_WCHAR *) Oem_MemAlloc( cbstrKID ) );
    dstrKID.cchString = CCH_BASE64_EQUIV( sizeof( DRM_ID ) );

    ChkMem( dstrLID.pwszString = (DRM_WCHAR *) Oem_MemAlloc( cbstrKID ) );
    dstrLID.cchString = CCH_BASE64_EQUIV( sizeof( DRM_ID ) );

    for (const auto& pair: m_oPersistentLicenses) {

        /* Convert KID to string */
        dr = DRM_B64_EncodeW(
            (DRM_BYTE*)&pair.first,
            sizeof( DRM_ID ),
            (DRM_WCHAR*)dstrKID.pwszString,
            &dstrKID.cchString,
            DRM_BASE64_ENCODE_NO_FLAGS );

        if (DRM_FAILED(dr)) {
            fprintf(stderr, "\n DeleteTemporaryPersistentLicenses: DRM_B64_EncodeW failed for KID: 0x%08X", dr);
            continue;
        }

        /* Convert LID to string */
        dr = DRM_B64_EncodeW(
            (DRM_BYTE*)&pair.second,
            sizeof( DRM_ID ),
            (DRM_WCHAR*)dstrLID.pwszString,
            &dstrKID.cchString,
            DRM_BASE64_ENCODE_NO_FLAGS );

        if (DRM_FAILED(dr)) {
            fprintf(stderr, "\n DeleteTemporaryPersistentLicenses: DRM_B64_EncodeW failed for LID: 0x%08X", dr);
            continue;
        }

        dr = Drm_StoreMgmt_DeleteLicenses(
            m_poAppContext,
            &dstrKID,
            &dstrLID,
            &cLicDeleted);

    }

ErrorExit:
    SAFE_OEM_FREE( dstrKID.pwszString );
    SAFE_OEM_FREE( dstrLID.pwszString );

    return;
}

/*processes the license response and creates decryptor for each valid ack available in the response*/
void MediaKeySession::Update(const uint8_t *m_pbKeyMessageResponse, uint32_t  m_cbKeyMessageResponse) {


    DRM_RESULT dr = DRM_SUCCESS;
    DRM_LICENSE_RESPONSE oLicenseResponse = { eUnknownProtocol, 0 };
    DRM_LICENSE_ACK *pLicenseAck = nullptr;
    DRM_DWORD decryptionMode;
    bool bIsAudioNeedNonSVPContext;

    ChkBOOL(m_eKeyState == KEY_PENDING, DRM_E_INVALIDARG);

    ChkArg(m_pbKeyMessageResponse && m_cbKeyMessageResponse > 0);

    ChkDR( ProcessLicenseResponse(
            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
            const_cast<DRM_BYTE *>(m_pbKeyMessageResponse),
            m_cbKeyMessageResponse,
            &oLicenseResponse ) );

    SaveTemporaryPersistentLicenses(&oLicenseResponse);

    for (DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {

        pLicenseAck = oLicenseResponse.m_pAcks != nullptr
                ? &oLicenseResponse.m_pAcks[ i ] : &oLicenseResponse.m_rgoAcks[ i ];

        KeyId keyId(&pLicenseAck->m_oKID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

        dr = pLicenseAck->m_dwResult;
        if ( DRM_SUCCEEDED( dr ) ) {

            DECRYPT_CONTEXT decryptContext;

            if ( CDMi_SUCCESS != SetKeyIdProperty( keyId ) )
            {
                dr = DRM_E_FAIL;
                goto LoopEnd;
            }

            decryptContext = NEW_DECRYPT_CONTEXT();

            decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
            dr = Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                    (const DRM_BYTE*)&decryptionMode,
                                    sizeof decryptionMode);
            if (!DRM_SUCCEEDED(dr)) {
                fprintf(stderr, "[%s:%d] Drm_Content_SetProperty() failed with %lx - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
                goto ErrorExit;
            }

            dr = ReaderBind(
                    g_rgpdstrRights,
                    NO_OF(g_rgpdstrRights),
                    _PolicyCallback,
                    &m_playreadyLevels,
                    &(decryptContext->oDrmDecryptContext) );

            if ( DRM_FAILED( dr ) ){
                fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
                goto LoopEnd;
            }

            bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();

            if(bIsAudioNeedNonSVPContext)
            {
              decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
              dr = Drm_Content_SetProperty(m_poAppContext,
                                      DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                      (const DRM_BYTE*)&decryptionMode,
                                      sizeof decryptionMode);
              if (!DRM_SUCCEEDED(dr)) {
                  fprintf(stderr, "[%s:%d] Drm_Content_SetProperty() failed with %lx - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
                  goto ErrorExit;
              }

              dr = ReaderBind(
                      g_rgpdstrRights,
                      NO_OF(g_rgpdstrRights),
                      _PolicyCallback,
                      &m_playreadyLevels,
                      &(decryptContext->oDrmDecryptAudioContext) );

              if ( DRM_FAILED( dr ) ){
                  fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
                  goto LoopEnd;
              }
            }

            decryptContext->keyId = keyId;

            if ( oLicenseResponse.m_cAcks == 1 ){
                m_currentDecryptContext = decryptContext;
            }

            m_DecryptContextVector.push_back(decryptContext);

            m_eKeyState = KEY_READY;
        }
    LoopEnd:
        if ( m_piCallback ){
            m_piCallback->OnKeyStatusUpdate( MapDrToKeyMessage( dr ), keyId.getmBytes(), DRM_ID_SIZE);
        }
    } 

    if ( m_eKeyState == KEY_READY ){
        dr = DRM_SUCCESS;
    }else{
        fprintf(stderr, "[%s:%d] Could not bind to any licenses",__FUNCTION__,__LINE__);
        dr = DRM_E_FAIL;
    }

ErrorExit:

    if (DRM_FAILED(dr)) {
        fprintf(stderr, "[%s:%d] failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
        m_eKeyState = KEY_ERROR;
    }
    if (m_piCallback){
        m_piCallback->OnKeyStatusesUpdated();
    }
    SAFE_OEM_FREE( oLicenseResponse.m_pAcks );
  return;
}

CDMi_RESULT MediaKeySession::Remove(void) {
  fprintf(stderr, "[%s:%d] returning false ",__FUNCTION__,__LINE__);
  return CDMi_S_FALSE;
}

/*Closes each DRM_DECRYPT_CONTEXT using Drm_Reader_Close()*/
void MediaKeySession::CloseDecryptContexts(void) {
    m_currentDecryptContext = nullptr;
    for (DECRYPT_CONTEXT &p : m_DecryptContextVector)
    {
        Drm_Reader_Close(&(p->oDrmDecryptContext));
        Drm_Reader_Close(&(p->oDrmDecryptAudioContext));
    }
    m_DecryptContextVector.clear();
}

void MediaKeySession::DeleteInMemoryLicenses()  {
    DRM_ID emptyId = DRM_ID_EMPTY;

    if (memcmp(&m_oBatchID, &emptyId, sizeof(DRM_ID)) == 0) {
        return;
    }
    KeyId batchId(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

    DRM_RESULT dr = Drm_StoreMgmt_DeleteInMemoryLicenses(m_poAppContext, &m_oBatchID);
    if (DRM_FAILED(dr) && dr != DRM_E_NOMORE) {
        fprintf(stderr, "[%s:%d]  Drm_StoreMgmt_DeleteInMemoryLicenses failed for batchId:%s. 0x%X - %s",__FUNCTION__,__LINE__,printUuid(batchId),dr,DRM_ERR_NAME(dr));
    } 
}

CDMi_RESULT MediaKeySession::Close(void) {

    if ( m_eKeyState != KEY_CLOSED ) {
#ifdef USE_SVP
        m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
        if(0 != svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr, nullptr, 0))
        {
            fprintf(stderr, "[%s:%d]  secure memory, free failed",__FUNCTION__,__LINE__);
        }
        else {
            m_stSecureBuffInfo.bCreateSecureMemRegion = false;
            m_stSecureBuffInfo.SecureMemRegionSize = 0;
        }
        gst_svp_ext_free_context(m_pSVPContext);
        m_pSVPContext = NULL;
#endif

        SAFE_OEM_FREE(m_pbChallenge);

        SAFE_OEM_FREE(m_pchSilentURL);

        CloseDecryptContexts();

        DeleteInMemoryLicenses();

        DeleteTemporaryPersistentLicenses();

        mDrmHeader.clear();

        SAFE_OEM_FREE(m_pbRevocationBuffer);

        SAFE_OEM_FREE(m_pdstrHeaderKIDs);

        m_eKeyState = KEY_CLOSED;
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::PlaybackStopped(void) {
  return CDMi_SUCCESS;
}

const char* MediaKeySession::MapDrToKeyMessage( DRM_RESULT dr )
{
    switch (dr)
    {
    case DRM_SUCCESS:
        return "KeyUsable";
    case DRM_E_TEE_OUTPUT_PROTECTION_REQUIREMENTS_NOT_MET:
    case DRM_E_TEST_OPL_MISMATCH:
        return "KeyOutputRestricted";
    case DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP:
        return "KeyOutputRestrictedHDCP";
    case DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP22:
    case DRM_E_TEST_INVALID_OPL_CALLBACK:
        return "KeyOutputRestrictedHDCP22";
    case DRM_E_LICENSE_NOT_FOUND:
        return "LicenseNotFound";
    case DRM_E_LICENSE_EXPIRED:
        return "LicenseExpired";
    default:
        return "KeyInternalError";
    }
}

CDMi_RESULT MediaKeySession::DRM_DecryptFailure(DRM_RESULT dr, const uint8_t *payloadData, uint32_t *f_pcbOpaqueClearContent, uint8_t **f_ppbOpaqueClearContent)
{
      fprintf(stderr, "[%s:%d] playready decrypt() failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));

      if(f_pcbOpaqueClearContent != nullptr)
      {
          *f_pcbOpaqueClearContent = 0;
      }
      if(f_ppbOpaqueClearContent != nullptr && payloadData != nullptr)
      {
          *f_ppbOpaqueClearContent = (uint8_t *)payloadData;
      }

      if(m_piCallback){
          char errStr[50];
          uint64_t errCode = (0xFFFFFFFF00000000)|(dr);
          sprintf(errStr,"0x%llx-DecryptError",errCode);
          m_piCallback->OnError(0, CDMi_S_FALSE, errStr);
          m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage( dr ), nullptr, 0);
          m_piCallback->OnKeyStatusesUpdated();
      }
      return CDMi_S_FALSE;  
}

DECRYPT_CONTEXT MediaKeySession::GetDecryptCtx( KeyId &f_rKeyId )
{
    for (DECRYPT_CONTEXT &ctx : m_DecryptContextVector)
    {
        if (ctx->keyId == f_rKeyId)
        {
            return ctx;
        }
    }
    return nullptr;
}

CDMi_RESULT MediaKeySession::SetParameter(const std::string& name, const std::string& value)
{
  CDMi_RESULT retVal = CDMi_S_FALSE;

  if(name.find("rpcId") != std::string::npos) {
    // Got the RPC ID for gst-svp-ext communication
    unsigned int nID = 0;
    nID =  (unsigned int)std::stoul(value.c_str(), nullptr, 16);
    if(nID != 0) {
#ifdef USE_SVP
      //fprintf(stderr, "Initializing SVP context for client side ID = %X\n", nID);
      gst_svp_ext_get_context(&m_pSVPContext, Client, nID);
#endif
    }
  }
  return retVal;
}

CDMi_RESULT MediaKeySession::Decrypt(
        uint8_t*                 inData,
        const uint32_t           inDataLength,
        uint8_t**                outData,
        uint32_t*                outDataLength,
        const SampleInfo*        sampleInfo,
        const IStreamProperties* properties)
{
  CDMi_RESULT ret = CDMi_S_FALSE;
  DRM_RESULT dr = DRM_SUCCESS;
  DRM_RESULT err = DRM_SUCCESS;
  DRM_UINT64 iv_high = 0;
  DRM_UINT64 iv_low = 0;
  void* pSecureToken = nullptr;
  uint8_t* pEncryptedDataStart  = nullptr;
  uint32_t actualEncDataLength = 0;
  void* header = NULL;
  DRM_DWORD encryptedRegionIvCounts = 1;
  DRM_DWORD encryptedRegionCounts;
  std::vector<DRM_DWORD> encryptedRegionSkip;
  std::vector<DRM_DWORD> encryptedRegionMapping;
  bool bGstSvpStatus = false;
  bool useSVP = true; // By default SVP is required
  DRM_UINT64 iv_vector[2] = { 0 };
  bool bIsVideoResCheckNeed = false;
  bool bIsDynamicSVPEncEnabled = false;
  uint64_t mCurrentPixels;
  bool bIsAudioNeedNonSVPContext;
  bool bIsMultipleOpaqueSupportCTR = false;
  DRM_DWORD* pDecryptedLength = 0;
  DRM_BYTE* pDecryptedContent = NULL;
  DRM_BYTE*  pEncryptedData = NULL;

  assert(sampleInfo->ivLength > 0);

  bIsVideoResCheckNeed = svpIsVideoResCheckNeed();

  if(bIsVideoResCheckNeed)
  {
    if (properties->GetMediaType() == Video) {
        mCurrentPixels = properties->GetHeight() * properties->GetWidth();
    }

    /* MaxResDecode */
    if (mMaxResDecodeSet) {
      if ((mCurrentPixels > mMaxResDecodePixels)) {
          fprintf(stderr, "[%s:%d] video resolution:%llu exceeds maximum resolution:%lu",__FUNCTION__,__LINE__,mCurrentPixels,mMaxResDecodePixels);
          return CDMi_S_FALSE;
      }
    }
  }

  bIsDynamicSVPEncEnabled = svpIsDynamicSVPEncEnabled();
  if(bIsDynamicSVPEncEnabled)
  {
    if (properties->GetMediaType() != Video) {
      useSVP = false;
    }
  }

  if ( sampleInfo->keyId != nullptr ){
      KeyId keyId(&sampleInfo->keyId[0],KeyId::KEYID_ORDER_UUID_BE);

      if (m_currentDecryptContext == nullptr
                || m_currentDecryptContext->keyId != keyId)
      {
          m_currentDecryptContext = GetDecryptCtx( keyId );
      }
  }

  if ( m_currentDecryptContext == nullptr ){
      fprintf(stderr, "[%s:%d] m_currentDecryptContext is Nullptr",__FUNCTION__,__LINE__);
      return CDMi_S_FALSE;
  }

  SafeCriticalSection systemLock(drmAppContextMutex_);

  if (properties->InitLength()) {
      // Netflix case
      memcpy(iv_vector, sampleInfo->iv, sampleInfo->ivLength * sizeof(uint8_t));

  } else {
    // Regular case
    NETWORKBYTES_TO_QWORD(iv_vector[0], sampleInfo->iv, 0);
    if (sampleInfo->ivLength == 16) {
        NETWORKBYTES_TO_QWORD(iv_vector[1], sampleInfo->iv, 8);
    }
  }

  if (gst_svp_has_header(m_pSVPContext, inData))
  {

    header = (void*)inData;
    pEncryptedDataStart = reinterpret_cast<DRM_BYTE *>(gst_svp_header_get_start_of_data(m_pSVPContext, header));
    gst_svp_header_get_field(m_pSVPContext, header, SvpHeaderFieldName::DataSize, &actualEncDataLength);
  }

  if (sampleInfo->subSampleCount > 0) {
    for (int i = 0; i < sampleInfo->subSampleCount; i++) {
      encryptedRegionMapping.push_back(sampleInfo->subSample[i].clear_bytes);
      encryptedRegionMapping.push_back(sampleInfo->subSample[i].encrypted_bytes);
    }
  } else {
      encryptedRegionMapping.push_back(0);
      encryptedRegionMapping.push_back(actualEncDataLength);
  }

  encryptedRegionCounts = encryptedRegionMapping.size()/2;

  if(useSVP)
  {
    // Reallocate input memory if needed.
    if(m_stSecureBuffInfo.bCreateSecureMemRegion)
    {
        if (actualEncDataLength >  m_stSecureBuffInfo.SecureMemRegionSize) {
            m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
            if(0 != svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr, nullptr, 0))
            {
                fprintf(stderr, "[%s:%d]  Secure memory free falied",__FUNCTION__,__LINE__);
                return CDMi_S_FALSE;
            }
            m_stSecureBuffInfo.SecureMemRegionSize = actualEncDataLength;
            m_stSecureBuffInfo.bReleaseSecureMemRegion = false;

            if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
            {
                fprintf(stderr, "[%s:%d] Secure memory, re-allocation failed %d",__FUNCTION__,__LINE__, m_stSecureBuffInfo.SecureMemRegionSize);
                return CDMi_S_FALSE;
            }
        }
    }

    m_stSecureBuffInfo.patternClearBlocks = sampleInfo->pattern.clear_blocks;

    if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, pEncryptedDataStart, actualEncDataLength))
    {
        fprintf(stderr, "[%s:%d]  secure memory, allocate failed [%d]",__FUNCTION__,__LINE__, actualEncDataLength);
        return CDMi_S_FALSE;
    }

/* TO DO */
#if defined TEE_CONFIG_NEED
    OEM_OPTEE_SetHandle(m_stSecureBuffInfo.pSecBufHandle);
#endif /* TEE_CONFIG_NEED */

    bGstSvpStatus = svp_buffer_alloc_token(&pSecureToken);
    if (!bGstSvpStatus) {
        fprintf(stderr, "[%s:%d]  memory allocation for Token is failure",__FUNCTION__,__LINE__);
        m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
        // Free decrypted secure buffer.
        svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
        return CDMi_S_FALSE;
    }

    bGstSvpStatus = svp_buffer_to_token(m_pSVPContext, (void *)&m_stSecureBuffInfo, pSecureToken);
    if (!bGstSvpStatus) {
        fprintf(stderr, "[%s:%d]  Buffer to Token creation is failure",__FUNCTION__,__LINE__);
        m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
        // Free decrypted secure buffer.
        svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
        svp_buffer_free_token(pSecureToken);
        return CDMi_S_FALSE;
    }
  }

  if (sampleInfo->pattern.encrypted_blocks != 0){
      encryptedRegionSkip.push_back(sampleInfo->pattern.encrypted_blocks);
      encryptedRegionSkip.push_back(sampleInfo->pattern.clear_blocks);
  }

  if (useSVP)
  {
    pDecryptedLength = reinterpret_cast<DRM_DWORD*>(actualEncDataLength);
    pDecryptedContent = reinterpret_cast<DRM_BYTE**>(m_stSecureBuffInfo.pPhysAddr);
    pEncryptedData = reinterpret_cast<DRM_BYTE*>(m_stSecureBuffInfo.pEncryptedDataBuffer);
  }
  else
  {
      pEncryptedData = pEncryptedDataStart;
  }

  /* For Video */
  if (useSVP == true)
  {
    bIsMultipleOpaqueSupportCTR = svpIsMultipleOpaqueSupportCTR();

    if(bIsMultipleOpaqueSupportCTR)
    {
      err = Drm_Reader_DecryptMultipleOpaque(&(m_currentDecryptContext->oDrmDecryptContext),
                                                encryptedRegionIvCounts,
                                                iv_vector,
                                                sampleInfo->ivLength == 16 ? iv_vector + 1 : nullptr,
                                                &encryptedRegionCounts,
                                                encryptedRegionMapping.size(),
                                                &encryptedRegionMapping[0],
                                                encryptedRegionSkip.size(),
                                                &encryptedRegionSkip[0],
                                                (DRM_DWORD) actualEncDataLength,
                                                (DRM_BYTE *) pEncryptedData,
                                                reinterpret_cast<DRM_DWORD*>(&pDecryptedLength),
                                                reinterpret_cast<DRM_BYTE**>(&pDecryptedContent));
    } else {
      err = Drm_Reader_DecryptOpaque(
                        &(m_currentDecryptContext->oDrmDecryptContext),
                        encryptedRegionMapping.size(),
                        reinterpret_cast<const DRM_DWORD*>(&encryptedRegionMapping[0]),
                        iv_vector[0],
                        actualEncDataLength,
                        (DRM_BYTE *) pEncryptedData,
                        reinterpret_cast<DRM_DWORD*>(&pDecryptedLength),
                        reinterpret_cast<DRM_BYTE**>(&pDecryptedContent));
    }

  }
  else
  {
    bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();
    bIsMultipleOpaqueSupportCTR = svpIsMultipleOpaqueSupportCTR();

    if(bIsMultipleOpaqueSupportCTR)
    {
      /* For Audio with Non-SVP support*/
      err = Drm_Reader_DecryptMultipleOpaque(&(bIsAudioNeedNonSVPContext ? m_currentDecryptContext->oDrmDecryptAudioContext :
                                                  m_currentDecryptContext->oDrmDecryptContext),
                                                encryptedRegionIvCounts,
                                                iv_vector,
                                                sampleInfo->ivLength == 16 ? iv_vector + 1 : nullptr,
                                                &encryptedRegionCounts,
                                                encryptedRegionMapping.size(),
                                                &encryptedRegionMapping[0],
                                                encryptedRegionSkip.size(),
                                                &encryptedRegionSkip[0],
                                                (DRM_DWORD) actualEncDataLength,
                                                (DRM_BYTE *) pEncryptedData,
                                                reinterpret_cast<DRM_DWORD*>(&pDecryptedLength),
                                                reinterpret_cast<DRM_BYTE**>(&pDecryptedContent));
    } else {
      err = Drm_Reader_DecryptOpaque(
                        &(bIsAudioNeedNonSVPContext ? m_currentDecryptContext->oDrmDecryptAudioContext :
                                                  m_currentDecryptContext->oDrmDecryptContext),
                        encryptedRegionMapping.size(),
                        reinterpret_cast<const DRM_DWORD*>(&encryptedRegionMapping[0]),
                        iv_vector[0],
                        actualEncDataLength,
                        (DRM_BYTE *) pEncryptedData,
                        reinterpret_cast<DRM_DWORD*>(&pDecryptedLength),
                        reinterpret_cast<DRM_BYTE**>(&pDecryptedContent));
    }

  }

  if (DRM_FAILED(err))
  {
    fprintf(stderr, "[%s:%d] Drm_Reader_DecryptMultipleOpaque failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
    DRM_DecryptFailure(err, nullptr, nullptr, nullptr);
#ifdef USE_SVP
    if (useSVP)
    {
      m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
      // Free decrypted secure buffer.
      svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
      svp_buffer_free_token(pSecureToken);
    }
#endif
    return err;
  }

  if(useSVP)
  {
    // Add a header to the output buffer.
    if (header)
    {
      gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::Handle);
    }

    memcpy((void *)(uint8_t*)pEncryptedDataStart, pSecureToken, svp_token_size());
    svp_buffer_free_token(pSecureToken);
  }
  else
  {
    if (header)
    {
      gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::InPlace);
    }

    if(NULL != pDecryptedContent)
    {
        memcpy((void *)(uint8_t*)pEncryptedDataStart, pDecryptedContent, pDecryptedLength);
        free(pDecryptedContent);
        pDecryptedContent = NULL;
    }

  }

  if (useSVP)
  {
    m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
    // Free decrypted secure buffer.
    svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr , nullptr, 0);
  }

  if (!m_fCommit) {
    err = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, &m_playreadyLevels);
    m_fCommit = TRUE;
  }

  // Copy and Return the Memory token in the incoming payload buffer.
  *outDataLength = inDataLength;
  *outData = inData;

  return CDMi_SUCCESS;

}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ) {
  return CDMi_SUCCESS;
}

}  // namespace CDMi
