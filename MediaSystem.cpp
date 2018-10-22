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

#include <memory>
#include <vector>

#include <interfaces/IDRM.h>
#include "MediaSession.h"

std::shared_ptr<DRM_APP_CONTEXT> appContext_;

namespace CDMi {

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

public:
    PlayReady() {
    }

    ~PlayReady(void) {
    }

    CDMi_RESULT CreateMediaKeySession(
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData);
 
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {

        delete f_piMediaKeySession;

        return CDMi_SUCCESS; 
    }

    ////////////////////
    // Ext
    ////////////////////
    time_t GetDrmSystemTime() const override
    {
       fprintf(stderr, "%s:%d: PR is asked for system time\n", __FILE__, __LINE__);
       //return 46;

       // TODO
       //ScopedMutex2 lock(drmAppContextMutex_);

       DRM_UINT64 utctime64;
       DRM_RESULT err = Drm_Clock_GetSystemTime(appContext_.get(), &utctime64);
       if (err != DRM_SUCCESS) {
       	fprintf(stderr, "Error: Drm_Clock_GetSystemTime returned 0x%lX\n", (long)err);
           // return invalid time
           return (time_t) -1;
       } else {
           //*time = (time_t)utctime64;
    	   return (time_t)utctime64;
       }

       return 0;

    }

    CDMi_RESULT CreateMediaKeySessionExt(uint32_t sessionId,
            const char contentId[],
            uint32_t contentIdLength,
            LicenseTypeExt licenseType,
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            IMediaKeySessionExt** session) override
	{

        *session = new CDMi::MediaKeySession(sessionId, contentId, contentIdLength, licenseType, drmHeader, drmHeaderLength);

        fprintf(stderr, "%s:%d: PR created a session\n", __FILE__, __LINE__);

        return CDMi_SUCCESS;
	}

    std::string GetVersionExt() const override
    {
    	return "PR-version";
    }

    uint32_t GetLdlSessionLimit() const override
    {
    	return 17;
    }

    CDMi_RESULT EnableSecureStop(bool enable) override
    {
    	return 0;
    }

    CDMi_RESULT CommitSecureStop(
            const unsigned char sessionID[],
            uint32_t sessionIDLength,
            const unsigned char serverResponse[],
            uint32_t serverResponseLength) override
    {
    	return 0;
    }
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
