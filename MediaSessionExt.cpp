/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MediaSession.h"

#include <iostream>
#include <stdio.h>
#include <sstream>

using namespace std;

#include <core/core.h>

using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;
extern Core::CriticalSection drmAppContextMutex_;

// The rights we want to request.
#ifdef PR_3_3
const DRM_WCHAR PLAY[] = { DRM_ONE_WCHAR('P', '\0'),
                           DRM_ONE_WCHAR('l', '\0'),
                           DRM_ONE_WCHAR('a', '\0'),
                           DRM_ONE_WCHAR('y', '\0'),
                           DRM_ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = DRM_CREATE_DRM_STRING(PLAY);
#else
const DRM_WCHAR PLAY[] = { ONE_WCHAR('P', '\0'),
                           ONE_WCHAR('l', '\0'),
                           ONE_WCHAR('a', '\0'),
                           ONE_WCHAR('y', '\0'),
                           ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = CREATE_DRM_STRING(PLAY);
#endif

static const DRM_CONST_STRING* RIGHTS[] = { &PLAY_RIGHT };

namespace CDMi {

struct CallbackInfo
{
    IMediaKeySessionCallback * _callback;
    uint16_t _compressedVideo;
    uint16_t _uncompressedVideo;
    uint16_t _analogVideo;
    uint16_t _compressedAudio;
    uint16_t _uncompressedAudio;
};

static void * PlayLevelUpdateCallback(void * data)
{
    CallbackInfo * callbackInfo = static_cast<CallbackInfo *>(data);

    stringstream keyMessage;
    keyMessage << "{";
    keyMessage << "\"compressed-video\": " << callbackInfo->_compressedVideo << ",";
    keyMessage << "\"uncompressed-video\": " << callbackInfo->_uncompressedVideo << ",";
    keyMessage << "\"analog-video\": " << callbackInfo->_analogVideo << ",";
    keyMessage << "\"compressed-audio\": " << callbackInfo->_compressedAudio << ",";
    keyMessage << "\"uncompressed-audio\": " << callbackInfo->_uncompressedAudio;
    keyMessage << "}";

    string keyMessageStr = keyMessage.str();
    const uint8_t * messageBytes = reinterpret_cast<const uint8_t *>(keyMessageStr.c_str());

    char urlBuffer[64];
    strcpy(urlBuffer, "properties");
    callbackInfo->_callback->OnKeyMessage(messageBytes, keyMessageStr.length() + 1, urlBuffer);

    delete callbackInfo;
    return nullptr;
}

static DRM_RESULT opencdm_output_levels_callback(const DRM_VOID *outputLevels, DRM_POLICY_CALLBACK_TYPE callbackType, const DRM_VOID *data) {
    // We only care about the play callback.
    if (callbackType != DRM_PLAY_OPL_CALLBACK)
        return DRM_SUCCESS;

    const IMediaKeySessionCallback * constSessionCallback = reinterpret_cast<const IMediaKeySessionCallback *>(data);
    if (constSessionCallback != nullptr) {
        CallbackInfo * callbackInfo = new CallbackInfo;
        callbackInfo->_callback = const_cast<IMediaKeySessionCallback *>(constSessionCallback);

        // Pull out the protection levels.
        const DRM_PLAY_OPL_EX* playLevels = static_cast<const DRM_PLAY_OPL_EX*>(outputLevels);
        callbackInfo->_compressedVideo = playLevels->minOPL.wCompressedDigitalVideo;
        callbackInfo->_uncompressedVideo = playLevels->minOPL.wUncompressedDigitalVideo;
        callbackInfo->_analogVideo = playLevels->minOPL.wAnalogVideo;
        callbackInfo->_compressedAudio = playLevels->minOPL.wCompressedDigitalAudio;
        callbackInfo->_uncompressedAudio = playLevels->minOPL.wUncompressedDigitalAudio;

        // Run on a new thread, so we don't go too deep in the IPC callstack.
        pthread_t threadId;
        pthread_create(&threadId, nullptr, PlayLevelUpdateCallback, callbackInfo);

    }
    // All done.
    return DRM_SUCCESS;
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

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, uint8_t * secureStopId)
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);

#ifdef NETFLIX
    // Make sure PlayReady still expects a 16 byte array.
    ASSERT(TEE_SESSION_ID_LEN == 16);

    memset(secureStopId, 0, TEE_SESSION_ID_LEN);

    DRM_RESULT err;

    // reinitialze DRM_APP_CONTEXT and set DRM header for current session
    err = Drm_Reinitialize(m_poAppContext);
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
                                  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    mLicenseResponse->clear();

    // For whatever reason Drm_LicenseAcq_ProcessResponse_Netflix needs a non-const pointer to the license data...
    std::vector<uint8_t> localLicenseData;
    localLicenseData.resize(licenseDataSize);
    memcpy(&localLicenseData[0], licenseData, licenseDataSize);

    err = Drm_LicenseAcq_ProcessResponse_Netflix(m_poAppContext,
                                                 DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
                                                 nullptr, nullptr,
                                                 &localLicenseData[0],
                                                 (DRM_DWORD)localLicenseData.size(),
                                                 secureStopId,
                                                 mLicenseResponse->get());
    if (DRM_FAILED(err)) {
        fprintf(stderr, "Error: Drm_LicenseAcq_ProcessResponse_Netflix returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    // Also store copy of secure stop id in session struct
    mSecureStopId.clear();
    mSecureStopId.resize(TEE_SESSION_ID_LEN);
    mSecureStopId.assign(secureStopId, secureStopId + TEE_SESSION_ID_LEN);
#endif

    // All done.
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL)
{
    DRM_RESULT err;

    SafeCriticalSection systemLock(drmAppContextMutex_);

#ifdef NETFLIX
    // sanity check for drm header
    if (mDrmHeader.size() == 0)
    {
        fprintf(stderr, "Error: No valid DRM header\n");
        return CDMi_S_FALSE;
    }

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

    // reinitialize DRM_APP_CONTEXT - this is limitation of PlayReady 2.x
    err = Drm_Reinitialize(m_poAppContext);
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    /*
     * Set the drm context's drm header property to the systemSpecificData.
     */
    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
                                  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    mNounce.resize(TEE_SESSION_ID_LEN);

    fprintf(stderr, "challengeSize: %u\n", challengeSize);
    fprintf(stderr, "challenge: %p\n", challenge);
    fprintf(stderr, "isLDL: %u\n", isLDL);

    // PlayReady doesn't like valid pointer + size 0
    DRM_BYTE* passedChallenge = static_cast<DRM_BYTE*>(challenge);
    if (challengeSize == 0) {
        passedChallenge = nullptr;
    }

    err = Drm_LicenseAcq_GenerateChallenge_Netflix(m_poAppContext,
                                                   RIGHTS,
                                                   sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                                   nullptr,
                                                   nullptr, 0,
                                                   nullptr, nullptr,
                                                   nullptr, nullptr,
                                                   passedChallenge, &challengeSize,
                                                   &mNounce[0], isLDL);

    fprintf(stderr, "ChallengeSize: %u\n", challengeSize);

    if ((err != DRM_E_BUFFERTOOSMALL) && (DRM_FAILED(err)))
    {
        fprintf(stderr, "Error: Drm_LicenseAcq_GenerateChallenge_Netflix returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    if (err == DRM_E_BUFFERTOOSMALL) {
        fprintf(stderr, "Error: Drm_LicenseAcq_GenerateChallenge_Netflix returned 0x%lX\n", (long)err);
        return CDMi_OUT_OF_MEMORY ;
    }
    m_eKeyState = KEY_PENDING;
#endif
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    SafeCriticalSection systemLock(drmAppContextMutex_);
#ifdef NETFLIX
    DRM_RESULT err = Drm_LicenseAcq_CancelChallenge_Netflix(m_poAppContext, &mNounce[0]);
    if (DRM_FAILED(err)) {
        fprintf(stderr, "Error Drm_LicenseAcq_CancelChallenge_Netflix: 0x%08lx\n", static_cast<unsigned long>(err));
        return CDMi_S_FALSE;
    }
#endif
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectKeyId(const uint8_t /* keyLength */, const uint8_t[] /* keyId */)
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;
    CDMi_RESULT result = CDMi_SUCCESS;
#ifdef NETFLIX
    // reinitialze DRM_APP_CONTEXT and set DRM header for current session for
    // simulataneous decryption support
    err = Drm_Reinitialize(m_poAppContext);
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }
    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
                                  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }
    if (m_decryptInited) {
        return CDMi_SUCCESS;
    }
    m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
    //Create a decrypt context and bind it with the drm context.
    memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));
    if(mSecureStopId.size() == TEE_SESSION_ID_LEN ){
        err = Drm_Reader_Bind_Netflix(m_poAppContext,
                                      RIGHTS,
                                      sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                      &opencdm_output_levels_callback, m_piCallback,
                                      &mSecureStopId[0],
                                      m_oDecryptContext);

        if (DRM_FAILED(err))
        {
            fprintf(stderr, "Error: Drm_Reader_Bind_Netflix returned 0x%lX\n", (long)err);
            result = CDMi_S_FALSE;
        } else {

            err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, m_piCallback);
            if (DRM_FAILED(err))
            {
                fprintf(stderr, "Error: Drm_Reader_Commit returned 0x%lX\n", (long)err);
                result = CDMi_S_FALSE;
            }
        }
        if (result == CDMi_SUCCESS) {
            m_fCommit = TRUE;
            m_decryptInited = true;
        }
    } else {
        fprintf(stderr, "Error: secure stop ID is not valid\n");
        result = CDMi_S_FALSE;
    }
    if (result == CDMi_SUCCESS) {
        m_eKeyState = KEY_READY;
    }
    else {
        m_eKeyState = KEY_ERROR;
    }
#endif
    return result;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;

    CDMi_RESULT result = CDMi_SUCCESS;

#ifdef NETFLIX
    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);
    if (m_oDecryptContext) {
        err = Drm_Reader_Unbind(m_poAppContext, m_oDecryptContext);
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "Error Drm_Reader_Unbind: 0x%08lx when creating temporary DRM_DECRYPT_CONTEXT\n",
                       static_cast<unsigned long>(err));
            result = CDMi_S_FALSE;
        }

    } else {

        // reinitialize DRM_APP_CONTEXT - this is limitation of PlayReady 2.x
        err = Drm_Reinitialize(m_poAppContext);
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }

        // sanity check for drm header
        if (mDrmHeader.size() == 0)
        {
            fprintf(stderr, "Error: No valid DRM header\n");
            return CDMi_S_FALSE;
        }

        /*
         * Set the drm context's drm header property to the systemSpecificData.
         */
        err = Drm_Content_SetProperty(m_poAppContext,
                                      DRM_CSP_AUTODETECT_HEADER,
                                      &mDrmHeader[0],
                                      mDrmHeader.size());
        if (DRM_FAILED(err))
        {
            fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }

        //Create a decrypt context and bind it with the drm context.
        m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
        memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));

        if (mSecureStopId.size() == TEE_SESSION_ID_LEN )
        {
            err = Drm_Reader_Bind_Netflix(m_poAppContext,
                                          RIGHTS,
                                          sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                          &opencdm_output_levels_callback, nullptr,
                                          &mSecureStopId[0],
                                          m_oDecryptContext);
            if (DRM_FAILED(err))
            {
                fprintf(stderr, "Error: Drm_Reader_Bind_Netflix returned 0x%lX\n", (long)err);
                result = CDMi_S_FALSE;
            } else {

                err = Drm_Reader_Unbind(m_poAppContext, m_oDecryptContext);
                if (DRM_FAILED(err))
                {
                    fprintf(stderr, "Error Drm_Reader_Unbind: 0x%08lx when creating temporary DRM_DECRYPT_CONTEXT\n",
                                    static_cast<unsigned long>(err));
                    result = CDMi_S_FALSE;
                }
            }
        } else {
            fprintf(stderr, "Error: secure stop ID is not valid\n");
            result = CDMi_S_FALSE;
        }
    }
    if (m_poAppContext)
    {
        err = Drm_Reader_Commit(m_poAppContext, nullptr, nullptr);
        if (DRM_FAILED(err))
        {
            // nothing that we can do about. Just log
            fprintf(stderr, "Error Drm_Reader_Commit 0x%08lx\n", static_cast<unsigned long>(err));
        }
    }

    delete m_oDecryptContext;
    m_oDecryptContext = nullptr;
    m_fCommit = FALSE;
    m_decryptInited = false;
#endif
    return CDMi_SUCCESS;
}

}
