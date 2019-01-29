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

#include "cdmi.h"

#ifndef min
#define min min
#endif

#ifndef max
#define max max
#endif

#include <drmbuild_oem.h>
#include <drmcommon.h>
#include <drmmanager.h>
#include <drmmathsafe.h>
#include <drmtypes.h>
#include <drmerr.h>

#undef __in
#undef __out

#ifndef SIZEOF
#define PR_3_3
#define SIZEOF sizeof
#endif

namespace CDMi {

class MediaKeySession : public IMediaKeySession {
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
        const uint8_t* keyId);


    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque );


private:


    static DRM_RESULT DRM_CALL _PolicyCallback(const DRM_VOID *, DRM_POLICY_CALLBACK_TYPE f_dwCallbackType, 
#ifdef PR_3_3
        const DRM_KID *, const DRM_LID *,
#endif
        const DRM_VOID *);

    DRM_APP_CONTEXT *m_poAppContext;
    DRM_DECRYPT_CONTEXT m_oDecryptContext;

    DRM_BYTE *m_pbOpaqueBuffer;
    DRM_DWORD m_cbOpaqueBuffer;

    DRM_BYTE *m_pbRevocationBuffer;
    KeyState m_eKeyState;
    DRM_CHAR m_rgchSessionID[CCH_BASE64_EQUIV(SIZEOF(DRM_ID)) + 1];
    DRM_BOOL m_fCommit;
      
    DRM_BYTE *m_pbChallenge;
    DRM_DWORD m_cbChallenge;
    DRM_CHAR *m_pchSilentURL;  
    IMediaKeySessionCallback *m_piCallback;
   
};

} // namespace CDMi
