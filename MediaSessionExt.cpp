#include "MediaSession.h"

#include <iostream>
#include <stdio.h>
#include <sstream>

#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

using namespace std;

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

const DRM_WCHAR PLAY[] = { ONE_WCHAR('P', '\0'),
                           ONE_WCHAR('l', '\0'),
                           ONE_WCHAR('a', '\0'),
                           ONE_WCHAR('y', '\0'),
                           ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = CREATE_DRM_STRING(PLAY);

const KeyId KeyId::EmptyKeyId;

namespace CDMi {

std::map<KeyId, DECRYPT_CONTEXT> mBindMap;
static const DRM_CONST_STRING* RIGHTS[] = { &PLAY_RIGHT };

MediaKeySession::MediaKeySession(const uint8_t drmHeader[], uint32_t drmHeaderLength, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration /* = false */)
   : m_pbRevocationBuffer(nullptr)
   , m_eKeyState(KEY_CLOSED)
   , m_pbChallenge(nullptr)
   , m_cbChallenge(0)
   , m_pchSilentURL(nullptr)
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
   , m_fCommit(false)
   , m_poAppContext(poAppContext)
   , m_decryptInited(false)
   , m_bDRMInitializedLocally(false)
{
#ifdef USE_SVP
    gst_svp_ext_get_context(&m_pSVPContext, Client, m_rpcID);
#endif

    mDrmHeader.resize(drmHeaderLength);
    memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);

    m_eKeyState = KEY_INIT;
}

uint32_t MediaKeySession::GetSessionIdExt() const
{
    return mSessionId;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
    mDrmHeader.resize(drmHeaderLength);
    memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::BindKeyNow(DECRYPT_CONTEXT decryptContext)
{
    DRM_VOID * pvData = nullptr;
    DRMPFNPOLICYCALLBACK pfnOPLCallback = nullptr;
    DECRYPT_CONTEXT tmpDecryptContext;
    DRM_DWORD decryptionMode;
    bool bIsAudioNeedNonSVPContext;
    CDMi_RESULT result = CDMi_SUCCESS;
    DRM_RESULT dr;

    for(;;)
    {
        if ( CDMi_SUCCESS != SetKeyIdProperty( decryptContext->keyId ) )
        {
            result = CDMi_S_FALSE;
            break;
        }

        decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;

        dr = Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                (const DRM_BYTE*)&decryptionMode,
                                sizeof decryptionMode);
        if (!DRM_SUCCEEDED(dr)) {
            fprintf(stderr, "[%s:%d] Drm_Content_SetProperty() failed with %lx - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
        }

        dr = ReaderBind(
                        RIGHTS,
                        sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                        _PolicyCallback,
                        pvData,
                        &(decryptContext->oDrmDecryptContext ) );

        if (DRM_FAILED(dr))
        {
            fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
        }

        dr = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, pvData);
        if (DRM_FAILED(dr))
        {
            fprintf(stderr, "[%s:%d] Drm_Reader_Commit failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
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
            result = CDMi_S_FALSE;
            break;
            }

            dr = ReaderBind(
                            RIGHTS,
                            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                            _PolicyCallback,
                            pvData,
                            &(decryptContext->oDrmDecryptAudioContext ) );

            if (DRM_FAILED(dr))
            {
            fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
            }

            dr = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, pvData);
            if (DRM_FAILED(dr))
            {
                fprintf(stderr, "[%s:%d] Drm_Reader_Commit failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
                result = CDMi_S_FALSE;
                break;
            }
        }

        if ( nullptr == ( tmpDecryptContext = GetDecryptCtx( decryptContext->keyId ) ) ){
            m_DecryptContextVector.push_back(decryptContext);
        }

        break;
    }

    return result;
}

CDMi_RESULT MediaKeySession::BindKey(KeyId keyId)
{
    DECRYPT_CONTEXT decryptContext;
    CDMi_RESULT result = CDMi_SUCCESS;
    decryptContext = NEW_DECRYPT_CONTEXT();
    decryptContext->keyId = keyId;
    
    auto it = mBindMap.find(keyId);

    for(;;)
    {
        if (it != mBindMap.end())
        {
            it->second = decryptContext;
            break;
        }

        result = BindKeyNow(decryptContext);
        if (CDMi_SUCCESS != result)
        {
            break;
        }
        mBindMap.insert(std::make_pair(decryptContext->keyId, std::shared_ptr<__DECRYPT_CONTEXT>()));

        break;
    }

    return result;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t f_rgbLicenseData[], uint32_t f_cbLicenseDataSize, uint8_t * f_pSecureStopId)
{
    DRM_RESULT err = DRM_SUCCESS;
    DRM_LICENSE_RESPONSE oLicenseResponse = {eUnknownProtocol, 0};
    DRM_LICENSE_ACK *pLicenseAck = nullptr;

    SafeCriticalSection systemLock(drmAppContextMutex_);

    if ( f_cbLicenseDataSize == 0 )
    {
        fprintf(stderr, "[%s:%d] f_cbLicenseDataSize should not be 0",__FUNCTION__,__LINE__);
        return CDMi_S_FALSE;
    }

    memset( f_pSecureStopId, 0, DRM_ID_SIZE );

    KeyId tmpBatchKeyId(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

    if ( tmpBatchKeyId == KeyId::EmptyKeyId ){
        fprintf(stderr, "[%s:%d] Invalid batchId/SecureStopId: %s",__FUNCTION__,__LINE__,tmpBatchKeyId.B64Str());
        return CDMi_S_FALSE;
    }

    DRM_BYTE *pbLicenseData = ( DRM_BYTE * )&f_rgbLicenseData[ 0 ];

    err = ProcessLicenseResponse(
            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
            pbLicenseData,
            f_cbLicenseDataSize,
            &oLicenseResponse );

    if (DRM_FAILED(err)) {
        SAFE_OEM_FREE( oLicenseResponse.m_pAcks );
        fprintf(stderr, "[%s:%d] ProcessLicenseResponse failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
        return CDMi_S_FALSE;
    }

    // NOTE: Netflix, for persistent licenses, the response batchId will be empty
    //       and this check will have to be removed, but for non-persistent, any empty batchId
    //       is an issue.  The member m_oBatchId is generated in the GenerateChallenge
    //       call and that should be used for secureStopId and should match the returned
    //       batchId in the LICENSE_RESPONSE struct  for in-memory licenses.
    if ( ::memcmp( m_oBatchID.rgb, &oLicenseResponse.m_idSession.rgb[0], DRM_ID_SIZE ) != 0 )
    {
        KeyId mBatch(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);
        fprintf(stderr, "[%s:%d] Response batchID does not equal batchID %s from challenge.",__FUNCTION__,__LINE__,mBatch.B64Str());
        SAFE_OEM_FREE( oLicenseResponse.m_pAcks );
        return CDMi_S_FALSE;
    }

    for ( DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        pLicenseAck = oLicenseResponse.m_pAcks != nullptr
                ? &oLicenseResponse.m_pAcks[ i ] : &oLicenseResponse.m_rgoAcks[ i ];

        KeyId keyId(pLicenseAck->m_oKID.rgb,KeyId::KEYID_ORDER_GUID_LE);

        DRM_RESULT dr = pLicenseAck->m_dwResult;

        if (DRM_SUCCEEDED( dr )) {
            if ( m_piCallback != nullptr ){
                if (CDMi_SUCCESS != BindKey(keyId))
                {
                  fprintf(stderr, "[%s:%d] BindKey() failed for keyId %s",__FUNCTION__,__LINE__,printGuid(keyId));
                }
                if ( keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_GUID_LE )
                  keyId.ToggleFormat();
                m_piCallback->OnKeyStatusUpdate("KeyUsable", keyId.getmBytes(), DRM_ID_SIZE);
            }
        }
        else
        {
            fprintf(stderr, "[%s:%d] Error processing license %s, 0x%X - %s",__FUNCTION__,__LINE__,printGuid(keyId),dr,DRM_ERR_NAME(dr));
        }
    }
    if ( m_piCallback != nullptr )
        m_piCallback->OnKeyStatusesUpdated();

    ::memcpy( f_pSecureStopId, &m_oBatchID.rgb[ 0 ], DRM_ID_SIZE );

    SAFE_OEM_FREE( oLicenseResponse.m_pAcks );

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectKeyId( const uint8_t f_keyLength, const uint8_t f_keyId[] )
{
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;
    DRMPFNPOLICYCALLBACK pfnOPLCallback = nullptr;
    DRM_VOID * pvData = nullptr;
    DRM_DWORD decryptionMode;
    CDMi_RESULT result = CDMi_SUCCESS;
    bool bIsAudioNeedNonSVPContext;

    pfnOPLCallback = _PolicyCallback;

    for (;;)
    {
        if ( f_keyId == nullptr || f_keyLength != DRM_ID_SIZE )
        {
            fprintf(stderr, "[%s:%d] Bad value for keyId arg ",__FUNCTION__,__LINE__);
            result = CDMi_S_FALSE;
            break;
        }

        KeyId keyId(&f_keyId[0],KeyId::KEYID_ORDER_UUID_BE);
        std::string keyIdHex(keyId.HexStr());

        /* If decrypt context exists, no need to create the new one */
        if ( nullptr != ( m_currentDecryptContext = GetDecryptCtx( keyId ) ) ){
            result = CDMi_SUCCESS;
            break;
        }

        if ( CDMi_SUCCESS != SetKeyIdProperty( keyId ) )
        {
            fprintf(stderr, "[%s:%d] SetKeyIdProperty failed",__FUNCTION__,__LINE__);
            result = CDMi_S_FALSE;
            break;
        }

        DECRYPT_CONTEXT decryptContext = NEW_DECRYPT_CONTEXT();

        decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
        err = Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                (const DRM_BYTE*)&decryptionMode,
                                sizeof decryptionMode);
        if (!DRM_SUCCEEDED(err)) {
            fprintf(stderr, "[%s:%d] Drm_Content_SetProperty() failed with %lx - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        }

        err = ReaderBind(
                        RIGHTS,
                        sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                        pfnOPLCallback,
                        pvData,
                        &(decryptContext->oDrmDecryptContext ) );

        if (DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        } 

        err = Drm_Reader_Commit(m_poAppContext, pfnOPLCallback, pvData);
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] Drm_Reader_Commit failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        }

        bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();

        if(bIsAudioNeedNonSVPContext)
        {
            decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
            err = Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                    (const DRM_BYTE*)&decryptionMode,
                                    sizeof decryptionMode);
            if (!DRM_SUCCEEDED(err)) {
                fprintf(stderr, "[%s:%d] Drm_Content_SetProperty() failed with %lx - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }

            err = ReaderBind(
                            RIGHTS,
                            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                            pfnOPLCallback,
                            pvData,
                            &(decryptContext->oDrmDecryptAudioContext ) );

            if (DRM_FAILED(err))
            {
                fprintf(stderr, "[%s:%d] ReaderBind failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }

            err = Drm_Reader_Commit(m_poAppContext, pfnOPLCallback, pvData);
            if (DRM_FAILED(err))
            {
                fprintf(stderr, "[%s:%d] Drm_Reader_Commit failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }
        }

        m_fCommit = TRUE;
        m_decryptInited = true;
        decryptContext->keyId = keyId;
        m_DecryptContextVector.push_back(decryptContext);
        m_currentDecryptContext = decryptContext;
        
        break;
    }

    return result;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * f_pChallenge, uint32_t & f_ChallengeSize, uint32_t f_isLDL)
{
    DRM_RESULT err;
    DRM_CHAR *pchCustomData = nullptr;
    DRM_DWORD cchCustomData = 0;

    UNREFERENCED_PARAMETER( f_isLDL );

    SafeCriticalSection systemLock(drmAppContextMutex_);

    if (mDrmHeader.size() == 0)
    {
        fprintf(stderr, "[%s:%d] No valid DRM header",__FUNCTION__,__LINE__);
        return CDMi_S_FALSE;
    }

    ASSERT(m_poAppContext != nullptr);

    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
                                  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "[%s:%d] Drm_Content_SetProperty failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
        return CDMi_S_FALSE;
    }

    DRM_BYTE* pbPassedChallenge = static_cast<DRM_BYTE*>(f_pChallenge);
    if (f_ChallengeSize == 0) {
        pbPassedChallenge = nullptr;
    }

    err = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                           RIGHTS,
                                           sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                           nullptr,  // domain id
                                           pchCustomData,  // custom data
                                           cchCustomData,        // custom data size
                                           nullptr,  // silent URL
                                           0,        // silent URL size
                                           nullptr,  // non-silent URL
                                           0,        // non-silent URL size
                                           pbPassedChallenge,
                                           &f_ChallengeSize,
                                           &m_oBatchID );


    if ( DRM_FAILED( err ) )
    {
        if (err == DRM_E_BUFFERTOOSMALL) {
            return CDMi_OUT_OF_MEMORY ;   
        }
        else
        {
            fprintf(stderr, "[%s:%d] Drm_LicenseAcq_GenerateChallenge failed. 0x%X - %s",__FUNCTION__,__LINE__,err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }
    }

    m_eKeyState = KEY_PENDING;

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Unbind(KeyId keyId)
{
      auto it = mBindMap.find(keyId);
      if (it == mBindMap.end())
      {
          fprintf(stderr, "[%s:%d] failed to find binding lock with key ID",__FUNCTION__,__LINE__);
          return CDMi_S_FALSE;
      }

      if (it->second.get() == nullptr)
      {
              mBindMap.erase(it);
              return CDMi_SUCCESS;
      }

      if (it->second->keyId != keyId)
      {
              ASSERT(it->second->keyId == keyId);
              return CDMi_S_FALSE;
      }
      BindKeyNow(it->second);
      it->second.reset();
      mBindMap.erase(it);
      return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    SafeCriticalSection systemLock(drmAppContextMutex_);

    ASSERT(m_poAppContext != nullptr);

    for (DECRYPT_CONTEXT &ctx : m_DecryptContextVector)
    {
        Unbind(ctx->keyId);
    }

    CloseDecryptContexts();

    if (m_poAppContext && !m_fCommit)
    {
        DRM_RESULT err = Drm_Reader_Commit(m_poAppContext, nullptr, nullptr);
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "[%s:%d] Drm_Reader_Commit failed. 0x%X - %s",__FUNCTION__,__LINE__,static_cast<unsigned long>(err),DRM_ERR_NAME(err));
        }
    }

    m_fCommit = FALSE;
    m_decryptInited = false;
    return CDMi_SUCCESS;
}
}

