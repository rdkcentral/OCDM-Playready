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
#include <core/core.h>

using namespace Thunder;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;
extern Core::CriticalSection drmAppContextMutex_;

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

MODULE_NAME_DECLARATION(BUILD_REFERENCE);

using namespace std;

namespace CDMi {

// The default location of CDM DRM store.
// /tmp/drmstore.dat

const DRM_WCHAR g_rgwchCDMDrmStoreName[] = {WCHAR_CAST('/'), WCHAR_CAST('t'), WCHAR_CAST('m'), WCHAR_CAST('p'), WCHAR_CAST('/'),
                                            WCHAR_CAST('d'), WCHAR_CAST('r'), WCHAR_CAST('m'), WCHAR_CAST('s'), WCHAR_CAST('t'),
                                            WCHAR_CAST('o'), WCHAR_CAST('r'), WCHAR_CAST('e'), WCHAR_CAST('.'), WCHAR_CAST('d'),
                                            WCHAR_CAST('a'), WCHAR_CAST('t'), WCHAR_CAST('\0')};

const DRM_CONST_STRING g_dstrCDMDrmStoreName = CREATE_DRM_STRING(g_rgwchCDMDrmStoreName);

const DRM_CONST_STRING *g_rgpdstrRights[1] = {&g_dstrDRM_RIGHT_PLAYBACK};
// Parse out the first PlayReady initialization header found in the concatenated
// block of headers in _initData_.
// If a PlayReady header is found, this function returns true and the header
// contents are stored in _output_.
// Otherwise, returns false and _output_ is not touched.
bool parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
    };

    // one PSSH box consists of:
    // 4 byte size of the atom, inclusive.  (0 means the rest of the buffer.)
    // 4 byte atom type, "pssh".
    // (optional, if size == 1) 8 byte size of the atom, inclusive.
    // 1 byte version, value 0 or 1.  (skip if larger.)
    // 3 byte flags, value 0.  (ignored.)
    // 16 byte system id.
    // (optional, if version == 1) 4 byte key ID count. (K)
    // (optional, if version == 1) K * 16 byte key ID.
    // 4 byte size of PSSH data, exclusive. (N)
    // N byte PSSH data.
    while (!input.IsEOF()) {
      size_t startPosition = input.pos();

      // The atom size, used for skipping.
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
        // unrecognized version - skip.
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      // flags
      if (!input.SkipBytes(3)) {
        return false;
      }

      // system id
      std::vector<uint8_t> systemId;
      if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
        return false;
      }

      if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
        // skip non-Playready PSSH boxes.
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      if (version == 1) {
        // v1 has additional fields for key IDs.  We can skip them.
        uint32_t numKeyIds;
        if (!input.Read4(&numKeyIds)) {
          return false;
        }

        if (!input.SkipBytes(numKeyIds * 16)) {
          return false;
        }
      }

      // size of PSSH data
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

  // we did not find a matching record
  return false;
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_APP_CONTEXT * poAppContext, bool initWithLast15, bool initiateChallengeGeneration /* = false */)
    : m_pbOpaqueBuffer(nullptr)
    , m_cbOpaqueBuffer(0)
    , m_pbRevocationBuffer(nullptr)
    , m_eKeyState(KEY_INIT)
    , m_pbChallenge(nullptr)
    , m_cbChallenge(0)
    , m_pchSilentURL(nullptr)
    , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
    , m_piCallback(nullptr)
    , mSessionId(0)
    , mInitWithLast15(initWithLast15)
    , mInitiateChallengeGeneration(initiateChallengeGeneration) 
    , m_fCommit(false)
    , m_poAppContext(poAppContext)
    , m_oDecryptContext(nullptr)
    , m_decryptInited(false)
{
   memset(&levels_, 0, sizeof(levels_));
   DRM_RESULT dr = DRM_SUCCESS;

   if (!initiateChallengeGeneration) {
      mLicenseResponse = std::unique_ptr<LicenseResponse>(new LicenseResponse());
      mSecureStopId.clear();

      // TODO: can we do this nicer?
      mDrmHeader.resize(f_cbCDMData);
      memcpy(&mDrmHeader[0], f_pbCDMData, f_cbCDMData);
   } else {
      m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
         
      DRM_ID oSessionID;

      DRM_DWORD cchEncodedSessionID = SIZEOF(m_rgchSessionID);

      // FIXME: Change the interface of this method? Not sure why the win32 bondage is still so popular.
      std::string initData(reinterpret_cast<const char*>(f_pbInitData), f_cbInitData);
      std::string playreadyInitData;

      printf("Constructing PlayReady Session [%p]\n", this);

      ChkMem(m_pbOpaqueBuffer = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE));
      m_cbOpaqueBuffer = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

      ChkMem(m_poAppContext = (DRM_APP_CONTEXT *)Oem_MemAlloc(SIZEOF(DRM_APP_CONTEXT)));

      // Initialize DRM app context.
      ChkDR(Drm_Initialize(m_poAppContext,
                           nullptr,
                           m_pbOpaqueBuffer,
                           m_cbOpaqueBuffer,
                           &g_dstrCDMDrmStoreName));

      if (DRM_REVOCATION_IsRevocationSupported()) {
         ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

         ChkDR(Drm_Revocation_SetBuffer(m_poAppContext,
                                       m_pbRevocationBuffer,
                                       REVOCATION_BUFFER_SIZE));
      }

      //temporary hack to allow time based licenses
      ( DRM_REINTERPRET_CAST( DRM_APP_CONTEXT_INTERNAL, m_poAppContext ) )->fClockSet = TRUE;    
            
      // Generate a random media session ID.
      ChkDR(Oem_Random_GetBytes(nullptr, (DRM_BYTE *)&oSessionID, SIZEOF(oSessionID)));
      ZEROMEM(m_rgchSessionID, SIZEOF(m_rgchSessionID));

      // Store the generated media session ID in base64 encoded form.
      ChkDR(DRM_B64_EncodeA((DRM_BYTE *)&oSessionID,
                              SIZEOF(oSessionID),
                              m_rgchSessionID,
                              &cchEncodedSessionID,
                              0));

      // The current state MUST be KEY_INIT otherwise error out.
      ChkBOOL(m_eKeyState == KEY_INIT, DRM_E_INVALIDARG);

      if (!parsePlayreadyInitializationData(initData, &playreadyInitData)) {
            playreadyInitData = initData;
      }
      ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_AUTODETECT_HEADER,
                                    reinterpret_cast<const DRM_BYTE*>(playreadyInitData.data()),
                                    playreadyInitData.size()));

      // The current state MUST be KEY_INIT otherwise error out.
      ChkBOOL(m_eKeyState == KEY_INIT, DRM_E_INVALIDARG);
      return; 
   }

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    printf("playready error: %s\n", description);
  }
}

MediaKeySession::~MediaKeySession(void) {
  Close();
  printf("Destructing PlayReady Session [%p]\n", this);
}

const char *MediaKeySession::GetSessionId(void) const {
  return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM; // FIXME : replace with keysystem and test.
}

DRM_RESULT DRM_CALL MediaKeySession::_PolicyCallback(
    VARIABLE_IS_NOT_USED const DRM_VOID *f_pvOutputLevelsData,
    VARIABLE_IS_NOT_USED DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
    VARIABLE_IS_NOT_USED const DRM_KID *f_pKID,
    VARIABLE_IS_NOT_USED const DRM_LID *f_pLID,
    VARIABLE_IS_NOT_USED const DRM_VOID *f_pv) {
  return DRM_SUCCESS;
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {
   
  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

    if (mInitiateChallengeGeneration) {
      playreadyGenerateKeyRequest();
    }
  } else {
      m_piCallback = nullptr;
  }
}

bool MediaKeySession::playreadyGenerateKeyRequest() {
    
  DRM_RESULT dr = DRM_SUCCESS; 
  DRM_DWORD cchSilentURL = 0;

  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext);

  // FIXME :  Check add case Play rights already acquired
  // Try to figure out the size of the license acquisition
  // challenge to be returned.
  dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        NULL,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size(),
                                        NULL,
                                        &cchSilentURL,
                                        NULL,
                                        NULL,
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        NULL);

  if (dr == DRM_E_BUFFERTOOSMALL) {
    if (cchSilentURL > 0) {
      ChkMem(m_pchSilentURL = (DRM_CHAR *)Oem_MemAlloc(cchSilentURL + 1));
      ZEROMEM(m_pchSilentURL, cchSilentURL + 1);
    }

    // Allocate buffer that is sufficient to store the license acquisition
    // challenge.
    if (m_cbChallenge > 0)
      ChkMem(m_pbChallenge = (DRM_BYTE *)Oem_MemAlloc(m_cbChallenge));

    dr = DRM_SUCCESS;
  } else {
    ChkDR(dr);
  }

  // Supply a buffer to receive the license acquisition challenge.
  ChkDR(Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                         g_rgpdstrRights,
                                         sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                         NULL,
                                         !m_customData.empty() ? m_customData.c_str() : nullptr,
                                         m_customData.size(),
                                         m_pchSilentURL,
                                         &cchSilentURL,
                                         nullptr,
                                         nullptr,
                                         m_pbChallenge,
                                         &m_cbChallenge,
                                         nullptr));


  m_eKeyState = KEY_PENDING;
  if (m_piCallback)
        m_piCallback->OnKeyMessage((const uint8_t *) m_pbChallenge, m_cbChallenge, (char *)m_pchSilentURL);
  return true;

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    printf("playready error: %s\n", description);
    if (m_piCallback)
        m_piCallback->OnKeyMessage((const uint8_t *) "", 0, "");
  }
  return false;
}

CDMi_RESULT MediaKeySession::Load(void) {
  return CDMi_S_FALSE;
}

void MediaKeySession::Update(const uint8_t *m_pbKeyMessageResponse, uint32_t  m_cbKeyMessageResponse) {

  DRM_RESULT dr = DRM_SUCCESS;
PUSH_WARNING(DISABLE_WARNING_MISSING_FIELD_INITIALIZERS)
  DRM_LICENSE_RESPONSE oLicenseResponse = {eUnknownProtocol, 0};
POP_WARNING()

  ChkArg(m_pbKeyMessageResponse && m_cbKeyMessageResponse > 0);

  ChkDR(Drm_LicenseAcq_ProcessResponse(m_poAppContext,
                                       DRM_PROCESS_LIC_RESPONSE_SIGNATURE_NOT_REQUIRED,
                                       const_cast<DRM_BYTE *>(m_pbKeyMessageResponse),
                                       m_cbKeyMessageResponse,
                                       &oLicenseResponse));

  ChkDR(Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext));

  m_eKeyState = KEY_READY;

  if (m_eKeyState == KEY_READY) {
    if (m_piCallback) {
      for (uint32_t i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        if (DRM_SUCCEEDED(oLicenseResponse.m_rgoAcks[i].m_dwResult)) {
            m_piCallback->OnKeyStatusUpdate("KeyUsable", oLicenseResponse.m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
        }
      }
      m_piCallback->OnKeyStatusesUpdated();
    }
  }

  return;

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    printf("playready error: %s\n", description);

    m_eKeyState = KEY_ERROR;

    // The upper layer is blocked waiting for an update, let's wake it.
    if (m_piCallback) {
      for (uint32_t i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        m_piCallback->OnKeyStatusUpdate("KeyError", oLicenseResponse.m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
      }
      m_piCallback->OnKeyStatusesUpdated();
    }
  }
  return;
}

CDMi_RESULT MediaKeySession::Remove(void) {
  return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Close(void) {
  m_eKeyState = KEY_CLOSED;

  if (mInitiateChallengeGeneration == true) {
      if (DRM_REVOCATION_IsRevocationSupported() && m_pbRevocationBuffer != nullptr) {
        SAFE_OEM_FREE(m_pbRevocationBuffer);
        m_pbRevocationBuffer = nullptr;
      }

      if (m_poAppContext != nullptr) {
          Drm_Uninitialize(m_poAppContext);
          SAFE_OEM_FREE(m_poAppContext);
          m_poAppContext = nullptr;
      }

      if (m_pbOpaqueBuffer != nullptr) {
        SAFE_OEM_FREE(m_pbOpaqueBuffer);
        m_pbOpaqueBuffer = nullptr;
      }

      if (m_oDecryptContext != nullptr) {
        delete m_oDecryptContext;
        m_oDecryptContext = nullptr;
      }

      if (m_pbChallenge != nullptr) {
          SAFE_OEM_FREE(m_pbChallenge);
          m_pbChallenge = nullptr;
      }

      if (m_pchSilentURL != nullptr) {
          SAFE_OEM_FREE(m_pchSilentURL);
          m_pchSilentURL = nullptr;
      }
  }
   m_piCallback = nullptr;
   m_fCommit = FALSE;
   m_decryptInited = false;

  return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::Decrypt(
    VARIABLE_IS_NOT_USED const uint8_t *f_pbSessionKey,
    VARIABLE_IS_NOT_USED uint32_t f_cbSessionKey,
    VARIABLE_IS_NOT_USED const EncryptionScheme encryptionScheme,
    VARIABLE_IS_NOT_USED const EncryptionPattern& pattern,
    const uint8_t *f_pbIV,
    uint32_t f_cbIV,
    uint8_t *payloadData,
    uint32_t payloadDataSize,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent,
    const uint8_t, // keyIdLength
    const uint8_t*, // keyId
    bool ) //initWithLast15
{
    uint32_t *f_pdwSubSampleMapping;
    uint32_t f_cdwSubSampleMapping;

    SafeCriticalSection systemLock(drmAppContextMutex_);
    assert(f_cbIV > 0);
    if(payloadDataSize == 0){
        return CDMi_SUCCESS;
    }

    if (!m_oDecryptContext) {
        fprintf(stderr, "Error: no decrypt context (yet?)\n");
        return CDMi_S_FALSE;
    }
    
    DRM_RESULT err = DRM_SUCCESS;
PUSH_WARNING(DISABLE_WARNING_MISSING_FIELD_INITIALIZERS)
    DRM_AES_COUNTER_MODE_CONTEXT ctrContext = { 0 };
POP_WARNING()

    DRM_DWORD rgdwMappings[2];

    if ( (f_pcbOpaqueClearContent == NULL) || (f_ppbOpaqueClearContent == NULL)
        || (f_pbIV == NULL || f_cbIV == 0) || (m_eKeyState != KEY_READY) )
    {
        fprintf(stderr, "Error: Decrypt - Invalid argument\n");
        return CDMi_S_FALSE;
    }

    *f_pcbOpaqueClearContent = 0;
    *f_ppbOpaqueClearContent = NULL;


    // TODO: can be done in another way (now abusing "initWithLast15" variable)
    if (mInitWithLast15) {
        // Netflix case
       memcpy(&ctrContext, f_pbIV, sizeof(ctrContext));
    } else {
       // Regular case
       std::vector<uint8_t> iv(f_cbIV, 0);
       for (uint8_t i = 0; i < f_cbIV; i++) {
#if defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
           iv[(f_cbIV - 1) - i] = f_pbIV[i];
#else
           iv[i] = f_pbIV[i];
#endif
       }

       MEMCPY(&ctrContext.qwInitializationVector, iv.data(), iv.size());
    }

    rgdwMappings[0] = 0;
    rgdwMappings[1] = payloadDataSize;
    f_pdwSubSampleMapping = reinterpret_cast<uint32_t*>(rgdwMappings);
    f_cdwSubSampleMapping = NO_OF(rgdwMappings);

    err = Drm_Reader_DecryptOpaque(
        m_oDecryptContext,
        f_cdwSubSampleMapping,
        reinterpret_cast<const DRM_DWORD*>(f_pdwSubSampleMapping),
        ctrContext.qwInitializationVector,
        payloadDataSize,
        (DRM_BYTE *) payloadData,
        reinterpret_cast<DRM_DWORD*>(f_pcbOpaqueClearContent),
        reinterpret_cast<DRM_BYTE**>(f_ppbOpaqueClearContent));

    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Failed to run Drm_Reader_Decrypt\n");
        return CDMi_S_FALSE;
    }

    if ( (*f_ppbOpaqueClearContent != nullptr) && (*f_pcbOpaqueClearContent > 0) && (*f_pcbOpaqueClearContent <= payloadDataSize) ) {
        ::memcpy(payloadData, *f_ppbOpaqueClearContent, *f_pcbOpaqueClearContent);
        ChkVOID( DRM_Reader_FreeOpaqueDecryptedContent( m_oDecryptContext, *f_pcbOpaqueClearContent, *f_ppbOpaqueClearContent) );
        *f_ppbOpaqueClearContent = payloadData;
    }
 
    // Call commit during the decryption of the first sample.
    if (!m_fCommit) {
        //err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, &levels_);
        err = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, nullptr); // TODO: pass along user data
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "Failed to do Reader Commit\n");
            return CDMi_S_FALSE;
        }
        m_fCommit = TRUE;
    }


    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    VARIABLE_IS_NOT_USED const uint8_t *f_pbSessionKey,
    VARIABLE_IS_NOT_USED uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ) {
    
    CDMi_RESULT res = CDMi_S_FALSE;
    if( f_pbClearContentOpaque != NULL && f_cbClearContentOpaque > 0 && m_oDecryptContext){
        ChkVOID( DRM_Reader_FreeOpaqueDecryptedContent( m_oDecryptContext, f_cbClearContentOpaque, f_pbClearContentOpaque ) );
        res = CDMi_SUCCESS;
    }
    else{
        fprintf(stderr,"ReleaseClearContent: Failed to free the Clear Content buffer\n");
    }
    return res;
}

void MediaKeySession::CleanLicenseStore(DRM_APP_CONTEXT *pDrmAppCtx){
    if (m_poAppContext != nullptr) {
        fprintf(stderr, "Licenses cleanup");
        // Delete all the licenses added by this session
        DRM_RESULT dr = Drm_StoreMgmt_DeleteInMemoryLicenses(pDrmAppCtx, &mBatchId);
        // Since there are multiple licenses in a batch, we might have already cleared
        // them all. Ignore DRM_E_NOMORE returned from Drm_StoreMgmt_DeleteInMemoryLicenses.
        if (DRM_FAILED(dr) && (dr != DRM_E_NOMORE)) {
            fprintf(stderr, "Error in Drm_StoreMgmt_DeleteInMemoryLicenses 0x%08lX", dr);
        }
    }
}

}  // namespace CDMi
