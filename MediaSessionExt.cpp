#include "MediaSession.h"

#include <iostream>
#include <stdio.h>

#include "ScopedMutex2.h"

using namespace std;

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;
extern std::shared_ptr<DRM_APP_CONTEXT> appContext_;

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


MediaKeySession::MediaKeySession(uint32_t sessionId, const char contentId[], uint32_t contentIdLength, LicenseTypeExt licenseType, const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
	// "contentId" often starts with an '\0', so just assigning it to the string will not work, we need to do something like this
	std::string contentIdString(contentId, contentIdLength);

	mLicenseResponse = std::unique_ptr<LicenseResponse2>(new LicenseResponse2());
	mContentId = contentIdString;
	mLicenseType = (CDMi::OcdmLicenseType)licenseType; // TODO: convert
	mSessionId = sessionId;
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
	err = Drm_Reinitialize(appContext_.get());
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
	}

    err = Drm_Content_SetProperty(appContext_.get(),
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
								  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return 1;
    }

    mLicenseResponse->clear();

    err = Drm_LicenseAcq_ProcessResponse_Netflix(appContext_.get(),
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
	err = Drm_Reinitialize(appContext_.get());
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
	}

    err = Drm_Content_SetProperty(appContext_.get(),
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
								  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Content_SetProperty returned 0x%lX\n", (long)err);
        return 1;
    }

     //Create a decrypt context and bind it with the drm context.
    if (decryptContext_.get()){
        // we already have initialized decrypt context.
        // TODO: is this a situation we need to log?
    	return 0;
    }
    decryptContext_.reset(new DRM_DECRYPT_CONTEXT);
    memset(decryptContext_.get(), 0, sizeof(DRM_DECRYPT_CONTEXT));

    if(mSecureStopId.size() == TEE_SESSION_ID_LEN ){
        err = Drm_Reader_Bind_Netflix(appContext_.get(),
                                      RIGHTS,
                                      sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
									  &opencdm_output_levels_callback, &levels_,
                                      &mSecureStopId[0],
                                      decryptContext_.get());
    } else {
    	fprintf(stderr, "Error: secure stop ID is not valid\n");
    	return 1;
    }

    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reader_Bind_Netflix returned 0x%lX\n", (long)err);
        return 1;
    }

    err = Drm_Reader_Commit(appContext_.get(), &opencdm_output_levels_callback, &levels_);
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Error: Drm_Reader_Commit returned 0x%lX\n", (long)err);
        return 1;
    }

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
    ASSERT(appContext_.get() != nullptr);

	// reinitialize DRM_APP_CONTEXT - this is limitation of PlayReady 2.x
	err = Drm_Reinitialize(appContext_.get());
	if(DRM_FAILED(err))
	{
		fprintf(stderr, "Error: Drm_Reinitialize returned 0x%lX\n", (long)err);
		return 1;
	}

    /*
     * Set the drm context's drm header property to the systemSpecificData.
     */
    err = Drm_Content_SetProperty(appContext_.get(),
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

    err = Drm_LicenseAcq_GenerateChallenge_Netflix(appContext_.get(),
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

CDMi_RESULT MediaKeySession::DecryptNetflix(const unsigned char* f_pbIV, uint32_t f_cbIV, unsigned long long byteOffset, unsigned char payloadData[], uint32_t payloadDataSize, bool initWithLast15)
{
    ScopedMutex2 systemLock(drmAppContextMutex_);

    assert(f_cbIV > 0);
    if(payloadDataSize == 0){
    	//return ERROR_NONE;
    	return 0;
    }

    if (!decryptContext_.get()) {
    	fprintf(stderr, "Error: no decrypt context (yet?)\n");
    	return 1;
    }
    
    DRM_RESULT err = DRM_SUCCESS;
    if (!initWithLast15) {
        err = Drm_Reader_InitDecrypt(&m_oDecryptContext, NULL, 0);
    } else {
        // Initialize the decryption context for Cocktail packaged
        // content. This is a no-op for AES packaged content.
        if (payloadDataSize <= 15)
        {
            err = Drm_Reader_InitDecrypt(decryptContext_.get(), (DRM_BYTE*)payloadData, payloadDataSize);
        }
        else
        {
            err = Drm_Reader_InitDecrypt(decryptContext_.get(), (DRM_BYTE*)(payloadData + payloadDataSize - 15), payloadDataSize);
        }
    }
    if (DRM_FAILED(err))
    {
        fprintf(stderr, "Failed to init decrypt\n");
        return 1;
    }

    DRM_AES_COUNTER_MODE_CONTEXT ctrContext = { 0 };
    // TODO: can be done in another way (now abusing "initWithLast15" variable)
    if (initWithLast15) {
        // Netflix case
        // IV : 8 bytes seed + 8 bytes counter
        if (f_pbIV && f_cbIV == 8) {
            // f_pbIV : 8 bytes seeds only
            // In this case, f_pbIV include only 8 bytes seed. We need to calculate block offset from byte offset
            NETWORKBYTES_TO_QWORD(ctrContext.qwInitializationVector, f_pbIV, 0); // qwInitializeVector is represent upper 8 bytes of 16bytes IV.
            ctrContext.qwBlockOffset = byteOffset >> 4; // remaining 8 bytes block offset for IV calculated for 16 byte unit(>>4) AES block
            ctrContext.bByteOffset = (DRM_BYTE)(byteOffset & 0xf); // byte offset within 16byte block
        } else if (f_pbIV && f_cbIV == 16) {
            // Dolby Vision encrypted EL's 16 bytes IV case.
            // f_pbIV : 8 bytes seed + 8 bytes counter which is next block offset from last block offset of BL
            // f_pbIV includes both 8 bytes seed and 8bytes block offset already in this case. (lower 8 bytes of f_pbIV is block offset)
            NETWORKBYTES_TO_QWORD(ctrContext.qwInitializationVector, f_pbIV, 0);
            NETWORKBYTES_TO_QWORD(byteOffset, f_pbIV, 8);
            ctrContext.qwBlockOffset = byteOffset;
            ctrContext.bByteOffset = 0;
        } else  {
            ctrContext.qwInitializationVector = 0;
            ctrContext.qwBlockOffset = byteOffset >> 4;
            ctrContext.bByteOffset = (DRM_BYTE)(byteOffset & 0xf);
        }
    } else {
       // Regular case
       // FIXME: IV bytes need to be swapped ???
       // TODO: is this for-loop the same as "NETWORKBYTES_TO_QWORD"?
       unsigned char * ivDataNonConst = const_cast<unsigned char *>(f_pbIV); // TODO: this is ugly
       for (uint32_t i = 0; i < f_cbIV / 2; i++) {
          unsigned char temp = ivDataNonConst[i];
          ivDataNonConst[i] = ivDataNonConst[f_cbIV - i - 1];
          ivDataNonConst[f_cbIV - i - 1] = temp;
       }

       MEMCPY(&ctrContext.qwInitializationVector, f_pbIV, f_cbIV);
    }

    err = Drm_Reader_Decrypt(decryptContext_.get(), &ctrContext, (DRM_BYTE*)payloadData, payloadDataSize);
    if (DRM_FAILED(err))
    {
        return 1;
    }

    if (initWithLast15) {
       // TODO: don't abuse "initWithLast15" to find out if we are in the Netflix case or not
       // TODO: have netflix code play nice with "m_fCommit "
/*
  // Call commit during the decryption of the first sample.
  if (!m_fCommit) {
    ChkDR(Drm_Reader_Commit(m_poAppContext, _PolicyCallback, NULL));
    m_fCommit = TRUE;
  } 
  // Return clear content.
  *f_pcbOpaqueClearContent = payloadDataSize;
  *f_ppbOpaqueClearContent = (uint8_t *)payloadData;
  status = CDMi_SUCCESS;
*/
    }

    return 0;
}


}
