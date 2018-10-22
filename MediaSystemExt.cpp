#include <memory>
#include <vector>

#include <interfaces/IDRM.h>
#include "MediaSession.h"

extern std::shared_ptr<DRM_APP_CONTEXT> appContext_;

/*
struct OpenCDMAccessor* opencdm_create_system_netflix(const char readDir[], const char storeLocation[])
{
	OpenCDMAccessor * output = new OpenCDMAccessor;

	// Clear DRM app context.
	appContext_.reset();

    std::string rdir(readDir);

    // Create wchar strings from the arguments.
    output->drmdir_ = createDrmWchar(rdir);

    // Initialize Ocdm directory.
    g_dstrDrmPath.pwszString = output->drmdir_;
    g_dstrDrmPath.cchString = rdir.length();

    // Store store location
	std::string store(storeLocation);

    output->drmStore_.pwszString = createDrmWchar(store);
    output->drmStore_.cchString = store.length();
    output->drmStoreStr_ = store;

    // Init opaque buffer.
    output->appContextOpaqueBuffer_ = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

    // Init revocation buffer.
    output->pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

    return output;
}
*/
