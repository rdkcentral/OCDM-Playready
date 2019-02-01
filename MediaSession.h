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

//#include "cdmi.h"
#include <interfaces/IDRM.h>

#include <drmbuild_oem.h>
#include <drmmanager.h>
#include <drmmathsafe.h>
#include <drmtypes.h>
#ifndef SIZEOF
#define PR_3_3
#define SIZEOF sizeof
#include <drmcrt.h>
#undef min
#undef max
#include <drmbytemanip.h>
#else
#include <drmcommon.h>
#endif
#include <drmerr.h>
#include <drmerror.h>

#undef __in
#undef __out

#include <string.h>
#include <memory>

namespace CDMi {

struct PlayLevels2 {
    uint16_t compressedDigitalVideoLevel_;   //!< Compressed digital video output protection level.
    uint16_t uncompressedDigitalVideoLevel_; //!< Uncompressed digital video output protection level.
    uint16_t analogVideoLevel_;              //!< Analog video output protection level.
    uint16_t compressedDigitalAudioLevel_;   //!< Compressed digital audio output protection level.
    uint16_t uncompressedDigitalAudioLevel_; //!< Uncompressed digital audio output protection level.
};

class LicenseResponse2 {
public:
    LicenseResponse2() : dlr(new DRM_LICENSE_RESPONSE) {}
    ~LicenseResponse2() { delete dlr; }
    DRM_LICENSE_RESPONSE * get() { return dlr; }
    void clear() { memset(dlr, 0, sizeof(DRM_LICENSE_RESPONSE)); }
private:
    DRM_LICENSE_RESPONSE * const dlr;
};

enum OcdmLicenseType {
    // this is in the order of priority
    // standard license has priority over limited duration license
    // TODO: do we need prefix here?
    OCDM_LICENSE_INVALID = 0,
    OCDM_LICENSE_LIMITED_DURATION,
    OCDM_LICENSE_STANDARD
};

enum OcdmSessionState {
    Ocdm_LicenseAcquisitionState = 0,
	Ocdm_InactiveDecryptionState,
	Ocdm_ActiveDecryptionState,
	Ocdm_InvalidState
};


class MediaKeySession : public IMediaKeySession, public IMediaKeySessionExt {
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
    //static const std::vector<std::string> m_mimeTypes;

    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData);

    // TODO: introduce MediaKeySessionExt?
    MediaKeySession(
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            DRM_APP_CONTEXT * poAppContext);

    ~MediaKeySession();

    bool playreadyGenerateKeyRequest();
    bool ready() const { return m_eKeyState == KEY_READY; }

// MediaKeySession overrides
    virtual void Run(
        const IMediaKeySessionCallback *f_piMediaKeySessionCallback);

    virtual CDMi_RESULT Load();

    virtual void Update(
        const uint8_t *f_pbKeyMessageResponse,
        uint32_t f_cbKeyMessageResponse);

    virtual CDMi_RESULT Remove();

    virtual CDMi_RESULT Close(void);

    virtual const char *GetSessionId(void) const;
    virtual const char *GetKeySystem(void) const;
    virtual CDMi_RESULT Decrypt(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t *f_pdwSubSampleMapping,
        uint32_t f_cdwSubSampleMapping,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        const uint8_t *f_pbData,
        uint32_t f_cbData,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t keyIdLength,
        const uint8_t* keyId,
        bool initWithLast15) override;

    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque );

    uint32_t GetSessionIdExt(void) const override;

    uint16_t PlaylevelCompressedVideo() const override;
    uint16_t PlaylevelUncompressedVideo() const override;
    uint16_t PlaylevelAnalogVideo() const override;
    uint16_t PlaylevelCompressedAudio() const override;
    uint16_t PlaylevelUncompressedAudio() const override;

    virtual std::string GetContentIdExt() const override;
    virtual void SetContentIdExt(const std::string & contentId) override;
    virtual LicenseTypeExt GetLicenseTypeExt() const override;
    virtual void SetLicenseTypeExt(LicenseTypeExt licenseType) override;
    virtual SessionStateExt GetSessionStateExt() const override;
    virtual void SetSessionStateExt(SessionStateExt sessionState) override;
    virtual CDMi_RESULT SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength) override;
    virtual CDMi_RESULT GetChallengeDataNetflix(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL) override;
    virtual CDMi_RESULT StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, unsigned char * secureStopId) override;
    virtual CDMi_RESULT InitDecryptContextByKid() override;

private:


    static DRM_RESULT DRM_CALL _PolicyCallback(const DRM_VOID *, DRM_POLICY_CALLBACK_TYPE f_dwCallbackType, 
#ifdef PR_3_3
        const DRM_KID *, const DRM_LID *,
#endif
        const DRM_VOID *);

    DRM_BYTE *m_pbOpaqueBuffer;
    DRM_DWORD m_cbOpaqueBuffer;

    DRM_BYTE *m_pbRevocationBuffer;
    KeyState m_eKeyState;
    DRM_CHAR m_rgchSessionID[CCH_BASE64_EQUIV(SIZEOF(DRM_ID)) + 1];
      
    DRM_BYTE *m_pbChallenge;
    DRM_DWORD m_cbChallenge;
    DRM_CHAR *m_pchSilentURL;  
    IMediaKeySessionCallback *m_piCallback;

private:
    std::string _contentIdExt; // TODO: remove this one

private:
	std::vector<uint8_t> mDrmHeader;
	std::vector<uint8_t> mNounce;
    std::string mContentId;
    OcdmLicenseType mLicenseType; // TODO: don't use netflix enum
    uint32_t mSessionId;
    OcdmSessionState mSessionState; // TODO: don't use netflix stuff
    std::unique_ptr<LicenseResponse2> mLicenseResponse;
    std::vector<uint8_t> mSecureStopId;
    PlayLevels2 levels_;

protected:
    DRM_BOOL m_fCommit;
    DRM_APP_CONTEXT *m_poAppContext;
    DRM_DECRYPT_CONTEXT *m_oDecryptContext;
    bool m_decryptInited; // TODO: keep track of this via pointer being != NULL?
};

} // namespace CDMi
