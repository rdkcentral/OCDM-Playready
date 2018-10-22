#include "MediaSession.h"

#include <iostream>
#include <stdio.h>

using namespace std;

namespace CDMi {

MediaKeySession::MediaKeySession(uint32_t sessionId, const char contentId[], uint32_t contentIdLength, LicenseTypeExt licenseType, const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
	fprintf(stderr, "%s:%d: create media key session ext in null2\n", __FILE__, __LINE__);
}

uint32_t MediaKeySession::GetSessionIdExt() const
{
	cerr << "Null2 session is asked for Session ID Ext" << endl;
	return 56;
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
	return _contentIdExt;
}

void MediaKeySession::SetContentIdExt(const std::string & contentId)
{
	cerr << "Null2 received content id ext: " << contentId << endl;

	_contentIdExt = contentId;
}

LicenseTypeExt MediaKeySession::GetLicenseTypeExt() const
{
	return LimitedDuration;
}

void MediaKeySession::SetLicenseTypeExt(LicenseTypeExt licenseType)
{
}

SessionStateExt MediaKeySession::GetSessionStateExt() const
{
	return ActiveDecryptionState;
}

void MediaKeySession::SetSessionStateExt(SessionStateExt sessionState)
{
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
	return 0;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, unsigned char * secureStopId)
{
	secureStopId[15] = 0x42;
	return 0;
}

CDMi_RESULT MediaKeySession::InitDecryptContextByKid()
{
	return 0;
}

CDMi_RESULT MediaKeySession::GetChallengeDataNetflix(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL)
{
	return 0;
}

}
