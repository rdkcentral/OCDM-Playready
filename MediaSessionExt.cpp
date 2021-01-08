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
#include <byteswap.h>
using namespace std;

#include <core/core.h>

using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;
extern Core::CriticalSection drmAppContextMutex_;

// The rights we want to request.
const DRM_WCHAR PLAY[] = { DRM_ONE_WCHAR('P', '\0'),
                           DRM_ONE_WCHAR('l', '\0'),
                           DRM_ONE_WCHAR('a', '\0'),
                           DRM_ONE_WCHAR('y', '\0'),
                           DRM_ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = DRM_CREATE_DRM_STRING(PLAY);

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

    // When a detached thread terminates, its resources are automatically released back to the system 
    // (i.e. without the need for another thread to join with it).
    pthread_detach(pthread_self());

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

DRM_RESULT opencdm_output_levels_callback(
    const DRM_VOID *outputLevels,
    DRM_POLICY_CALLBACK_TYPE callbackType,
    const DRM_KID * /*f_pKID */,
    const DRM_LID * /*f_pLID*/,
    const DRM_VOID *data)
{
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

    DRM_RESULT err;


    mLicenseResponse->clear();

    err = Drm_LicenseAcq_ProcessResponse(
            m_poAppContext,
            DRM_PROCESS_LIC_RESPONSE_SIGNATURE_NOT_REQUIRED,
            &licenseData[0],
            (DRM_DWORD)licenseDataSize,
            mLicenseResponse->get());


    if(DRM_SUCCEEDED(err))
       m_eKeyState = KEY_READY;

    if (m_piCallback && DRM_SUCCEEDED(err)) {
        for (int i = 0; i < mLicenseResponse->get()->m_cAcks; ++i) {
            if (DRM_SUCCEEDED(mLicenseResponse->get()->m_rgoAcks[i].m_dwResult)) {
                m_piCallback->OnKeyStatusUpdate("KeyUsable", mLicenseResponse->get()->m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
            }
        }
      m_piCallback->OnKeyStatusesUpdated();
    }

// First, check the return code of Drm_LicenseAcq_ProcessResponse()
    if (err ==  DRM_E_LICACQ_TOO_MANY_LICENSES) {
        // This means the server response contained more licenses than
        // DRM_MAX_LICENSE_ACK (usually 20). Should allocate space and retry.
        // FIXME NRDLIB-4481: This will need to be implemented when we start
        // using batch license requests.
        fprintf(stderr, "Drm_LicenseAcq_ProcessResponse too many licenses in response.");
        return CDMi_S_FALSE;
    }
    else if (DRM_FAILED(err)) {
        fprintf(stderr, "Drm_LicenseAcq_ProcessResponse failed (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    // Next, examine the returned drmLicenseResponse struct for a top-level error.
    if (DRM_FAILED(mLicenseResponse->get()->m_dwResult)) {
        fprintf(stderr, "Error in DRM_LICENSE_RESPONSE");
        return CDMi_S_FALSE;
    }

    // Finally, ensure that each license in the response was processed
    // successfully.
    const DRM_DWORD nLicenses = mLicenseResponse->get()->m_cAcks;
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        fprintf(stderr, "Checking license %d", i);
        if (DRM_FAILED(mLicenseResponse->get()->m_rgoAcks[i].m_dwResult)) {
            // Special handling for DRM_E_DST_STORE_FULL. If this error is
            // detected for any license, reset the DRM appcontext and return error.
            if (mLicenseResponse->get()->m_rgoAcks[i].m_dwResult == DRM_E_DST_STORE_FULL) {
                fprintf(stderr, "Found DRM_E_DST_STORE_FULL error in license %d, reinitializing!", i);
                
                err = Drm_Reinitialize(m_poAppContext);
                if (DRM_FAILED(err))
                {
                    fprintf(stderr, "Error: Drm_Reinitialize returned (error: 0x%08X)", static_cast<unsigned int>(err));
                    return CDMi_S_FALSE;
                }

            }
            else {
                fprintf(stderr, "Error 0x%08lX found in license %d", (unsigned long)mLicenseResponse->get()->m_rgoAcks[i].m_dwResult, i);
            }
            return CDMi_S_FALSE;
        }
    }

    // === Extract various ID's from drmLicenseResponse
    //
    // There are 3 ID's in the processed license response we are interested in:
    // BID - License batch ID. A GUID that uniquely identifies a batch of
    //       licenses that were processed in one challenge/response transaction.
    //       The BID is a nonce unique to the transaction. If the transaction
    //       contains a single license, this is identical to the license nonce.
    //       The secure stop ID is set to the BID value.
    // KID - Key ID. A GUID that uniquely identifies the media content key. This
    //       is the primary index for items in the license store. There can be
    //       multiple licenses with the same KID.
    // LID - License ID. A GUID that uniquely identifies a license. This is the
    //       secondary index for items in the license store.
    // When there are multiple licenses in the server response as in the PRK
    // case, there are correspondingly multiple KID/LID entries in the processed
    // response. There is always only a single BID per server response.

    // BID
    mBatchId = mLicenseResponse->get()->m_oBatchID; 
    PrintBase64(sizeof(mBatchId.rgb), mBatchId.rgb, "BatchId/SecureStopId");

    // Microsoft says that a batch ID of all zeros indicates some sort of error
    // for in-memory licenses. Hopefully this error was already caught above.
    const uint8_t zeros[sizeof(mBatchId.rgb)] = { 0 };
    if(memcmp(mBatchId.rgb, zeros, sizeof(mBatchId.rgb)) == 0){
        fprintf(stderr, "No batch ID in processed response");
        return CDMi_S_FALSE;
    }
    // We take the batch ID as the secure stop ID
    memcpy(secureStopId, mBatchId.rgb, sizeof(mBatchId.rgb));

    // KID and LID
    fprintf(stderr, "Found %d license%s in server response for :", nLicenses, (nLicenses > 1) ? "s" : "");
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        const DRM_LICENSE_ACK * const licAck = &mLicenseResponse->get()->m_rgoAcks[i];
        fprintf(stderr, "KID/LID[%d]:", i);
        PrintBase64(sizeof(licAck->m_oLID.rgb), licAck->m_oLID.rgb, "LID");
        PrintBase64(sizeof(licAck->m_oKID.rgb), licAck->m_oKID.rgb, "KID");
    }
    // All done.
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t /* isLDL */)
{
    DRM_RESULT err;

    uint32_t passedChallengeSize = challengeSize;

    SafeCriticalSection systemLock(drmAppContextMutex_);

    // sanity check for drm header
    if (mDrmHeader.size() == 0)
    {
        fprintf(stderr, "Error: No valid DRM header\n");
        return CDMi_S_FALSE;
    }

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

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

    // PlayReady doesn't like valid pointer + size 0
    DRM_BYTE* passedChallenge = static_cast<DRM_BYTE*>(challenge);
    if (challengeSize == 0) {
        passedChallenge = nullptr;
    }


    // Find the size of the challenge.
    err = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                            RIGHTS,
                                            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                            nullptr,
                                            nullptr,
                                            0,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            passedChallenge,
                                            &challengeSize,
                                            nullptr);

    if ((err != DRM_E_BUFFERTOOSMALL) && (DRM_FAILED(err)))
    {
        fprintf(stderr, "Error: Drm_LicenseAcq_GenerateChallenge returned 0x%lX\n", (long)err);
        return CDMi_S_FALSE;
    }

    if ((passedChallenge != nullptr) && (err == DRM_E_BUFFERTOOSMALL)){
        fprintf(stderr, "Error: Drm_LicenseAcq_GenerateChallenge (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_OUT_OF_MEMORY ;
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectKeyId(const uint8_t /* keyLength */, const uint8_t[] /* keyId */)
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;
    CDMi_RESULT result = CDMi_SUCCESS;
   
    ASSERT(m_poAppContext != nullptr);

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

	err = Drm_Reader_Bind(
                m_poAppContext,
                RIGHTS,
                sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                &opencdm_output_levels_callback,
                m_piCallback,
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
	    m_eKeyState = KEY_READY;
    }
    else {
        m_eKeyState = KEY_ERROR;
    }
    return result;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;
    fprintf(stderr, "MediaKeySession::CleanDecryptContext\n");
    CDMi_RESULT result = CDMi_SUCCESS;

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

    if (m_oDecryptContext != nullptr) {
        Drm_Reader_Close(m_oDecryptContext);
	fprintf(stderr, "Closing active decrypt context");
        Drm_Reader_Close(m_oDecryptContext);
        delete m_oDecryptContext;
        m_oDecryptContext = nullptr;
    }
    
    return result;
}

}
