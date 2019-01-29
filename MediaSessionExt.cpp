#include "MediaSession.h"

#include <iostream>
#include <stdio.h>

#include "ScopedMutex2.h"

using namespace std;

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

// The rights we want to request.
const DRM_WCHAR PLAY[] = { ONE_WCHAR('P', '\0'),
                           ONE_WCHAR('l', '\0'),
                           ONE_WCHAR('a', '\0'),
                           ONE_WCHAR('y', '\0'),
                           ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = CREATE_DRM_STRING(PLAY);
static const DRM_CONST_STRING* RIGHTS[] = { &PLAY_RIGHT };

namespace CDMi {

static DRM_RESULT opencdm_output_levels_callback(const DRM_VOID *outputLevels, DRM_POLICY_CALLBACK_TYPE callbackType, const DRM_VOID *data) {
    // We only care about the play callback.
    if (callbackType != DRM_PLAY_OPL_CALLBACK)
        return DRM_SUCCESS;

    // Pull out the protection levels.
    PlayLevels2* levels = static_cast<PlayLevels2*>(const_cast<DRM_VOID*>(data));
    const DRM_PLAY_OPL_EX* playLevels = static_cast<const DRM_PLAY_OPL_EX*>(outputLevels);
    levels->compressedDigitalVideoLevel_ = playLevels->minOPL.wCompressedDigitalVideo;
    levels->uncompressedDigitalVideoLevel_ = playLevels->minOPL.wUncompressedDigitalVideo;
    levels->analogVideoLevel_ = playLevels->minOPL.wAnalogVideo;
    levels->compressedDigitalAudioLevel_ = playLevels->minOPL.wCompressedDigitalAudio;
    levels->uncompressedDigitalAudioLevel_ = playLevels->minOPL.wUncompressedDigitalAudio;

    // All done.
    return DRM_SUCCESS;
}


MediaKeySession::MediaKeySession(const uint8_t drmHeader[], uint32_t drmHeaderLength, DRM_APP_CONTEXT * poAppContext)
   : m_poAppContext(poAppContext)
   , m_decryptInited(false)
{
    m_oDecryptContext = new DRM_DECRYPT_CONTEXT;

	mLicenseResponse = std::unique_ptr<LicenseResponse2>(new LicenseResponse2());
	mSessionState = OcdmSessionState::Ocdm_InvalidState;
	mSecureStopId.clear();

	// TODO: can we do this nicer?
	mDrmHeader.resize(drmHeaderLength);
	memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
}

uint32_t MediaKeySession::GetSessionIdExt() const
{
	cerr << "Null2 session is asked for Session ID Ext" << endl;
	return mSessionId;
}

uint16_t MediaKeySession::PlaylevelCompressedVideo() const
{
	cerr << "Null2 session is asked for PlaylevelCompressedVideo" << endl;
	return 57;
}

uint16_t MediaKeySession::PlaylevelUncompressedVideo() const
{
	return 58;
}

uint16_t MediaKeySession::PlaylevelAnalogVideo() const
{
	return 59;
}

uint16_t MediaKeySession::PlaylevelCompressedAudio() const
{
	return 60;
}

uint16_t MediaKeySession::PlaylevelUncompressedAudio() const
{
	return 61;
}

std::string MediaKeySession::GetContentIdExt() const
{
	return mContentId;
}

void MediaKeySession::SetContentIdExt(const std::string & contentId)
{
	cerr << "Null2 received content id ext: " << contentId << endl;

	_contentIdExt = contentId;
}

LicenseTypeExt MediaKeySession::GetLicenseTypeExt() const
{
	// TODO: conversion
	return (CDMi::LicenseTypeExt)mLicenseType;
}

void MediaKeySession::SetLicenseTypeExt(LicenseTypeExt licenseType)
{
}

SessionStateExt MediaKeySession::GetSessionStateExt() const
{
	// TODO: conversion
	return (SessionStateExt)mSessionState;
}

void MediaKeySession::SetSessionStateExt(SessionStateExt sessionState)
{
	// TODO: conversion
	mSessionState = (CDMi::OcdmSessionState)sessionState;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
	return 0;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, unsigned char * secureStopId)
{
    // open scope for DRM_APP_CONTEXT mutex
    ScopedMutex2 systemLock(drmAppContextMutex_);

    // Make sure PlayReady still expects a 16 byte array.
    // TODO: static assert?
    ASSERT(TEE_SESSION_ID_LEN == 16);

    memset(secureStopId, 0, TEE_SESSION_ID_LEN);

    // std::vector<uint8_t> localLicenseData = licenseData;
    std::vector<uint8_t> localLicenseData;
    localLicenseData.resize(licenseDataSize);
	memcpy(&localLicenseData[0], licenseData, licenseDataSize);

    DRM_RESULT err;

    // reinitialze DRM_APP_CONTEXT and set DRM header for current session
	err = Drm_Reinitialize(m_poAppContext);
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
	}

    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
								  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return 1;
    }

    mLicenseResponse->clear();

    err = Drm_LicenseAcq_ProcessResponse_Netflix(m_poAppContext,
                                                 DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
                                                 NULL, NULL,
                                                 &localLicenseData[0],
                                                 (DRM_DWORD)localLicenseData.size(),
												 secureStopId,
												 mLicenseResponse->get());
    if (DRM_FAILED(err)) {
        fprintf(stderr, "Error: Drm_LicenseAcq_ProcessResponse_Netflix returned 0x%lX\n", (long)err);
        return 1;
    }

    // Also store copy of secure stop id in session struct
    mSecureStopId.clear();
    mSecureStopId.resize(TEE_SESSION_ID_LEN);
    mSecureStopId.assign(secureStopId, secureStopId + TEE_SESSION_ID_LEN);

    // All done.
    return 0;
}

CDMi_RESULT MediaKeySession::InitDecryptContextByKid()
{
    // open scope for DRM_APP_CONTEXT mutex
    ScopedMutex2 systemLock(drmAppContextMutex_);

    DRM_RESULT err;

     // reinitialze DRM_APP_CONTEXT and set DRM header for current session for
     // simulataneous decryption support
	err = Drm_Reinitialize(m_poAppContext);
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
	}

    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
								  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return 1;
    }
    
    if (m_decryptInited) {
        return 0;
    }

     //Create a decrypt context and bind it with the drm context.
    memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));

    if(mSecureStopId.size() == TEE_SESSION_ID_LEN ){
        err = Drm_Reader_Bind_Netflix(m_poAppContext,
                                      RIGHTS,
                                      sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
									  &opencdm_output_levels_callback, &levels_,
                                      &mSecureStopId[0],
                                      m_oDecryptContext);
    } else {
    	fprintf(stderr, "Error: secure stop ID is not valid\n");
    	return 1;
    }

    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reader_Bind_Netflix returned 0x%lX\n", (long)err);
        return 1;
    }

    err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, &levels_);
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reader_Commit returned 0x%lX\n", (long)err);
        return 1;
    }
    m_fCommit = TRUE;
    m_decryptInited = true;

    return 0;
}

CDMi_RESULT MediaKeySession::GetChallengeDataNetflix(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL)
{
	// TODO: this is more or less a copy paste from Netflix, so deal with C-style casting and use or NULL instead of nullptr.
    DRM_RESULT err;

    ScopedMutex2 systemLock(drmAppContextMutex_);

    // sanity check for drm header
    if (mDrmHeader.size() == 0) {
    	fprintf(stderr, "Error: No valid DRM header\n");
        return 1;
    }

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

	// reinitialize DRM_APP_CONTEXT - this is limitation of PlayReady 2.x
	err = Drm_Reinitialize(m_poAppContext);
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
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
        return 1;
    }

    mNounce.resize(TEE_SESSION_ID_LEN);

    fprintf(stderr, "challengeSize: %u\n", challengeSize);
    fprintf(stderr, "challenge: %p\n", challenge);
    fprintf(stderr, "isLDL: %u\n", isLDL);

    // PlayReady doesn't like valid pointer + size 0
    DRM_BYTE* passedChallenge = (DRM_BYTE*)challenge; // TODO: C-style casting
    if (challengeSize == 0) {
    	passedChallenge = nullptr;
    }

    err = Drm_LicenseAcq_GenerateChallenge_Netflix(m_poAppContext,
                                                   RIGHTS,
                                                   sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                                   NULL,
                                                   NULL, 0,
                                                   NULL, NULL,
                                                   NULL, NULL,
												   passedChallenge, &challengeSize,
                                                   &mNounce[0], isLDL);

    fprintf(stderr, "ChallengeSize: %u\n", challengeSize);

    if ((err != DRM_E_BUFFERTOOSMALL) && (DRM_FAILED(err)))
    {
        fprintf(stderr, "Error: Drm_LicenseAcq_GenerateChallenge_Netflix returned 0x%lX\n", (long)err);
        return 1;
    }

    if (err == DRM_E_BUFFERTOOSMALL) {
    	//return ERROR_OUT_OF_MEMORY;
    	return 2;
    }

    return 0;
}

}

