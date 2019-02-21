# - Try to find PlayReady
# Once done this will define
#  PLAYREADY_FOUND - System has PlayReady
#  PLAYREADY_INCLUDE_DIRS - The PlayReady include directories
#  PLAYREADY_LIBRARIES - The libraries needed to use PlayReady
#  PLAYREADY_FLAGS - The flags needed to use PlayReady
#

find_package(PkgConfig)
pkg_check_modules(PC_PLAYREADY REQUIRED playready)

if(PC_PLAYREADY_FOUND)
    if(PLAYREADY_FIND_VERSION AND PC_PLAYREADY_VERSION)
        if ("${PLAYREADY_FIND_VERSION}" VERSION_GREATER "${PC_PLAYREADY_VERSION}")
            message(WARNING "Incorrect version, found ${PC_PLAYREADY_VERSION}, need at least ${PLAYREADY_FIND_VERSION}, please install correct version ${PLAYREADY_FIND_VERSION}")
            set(PLAYREADY_FOUND_TEXT "Found incorrect version")
            unset(PC_PLAYREADY_FOUND)
        endif()
    endif()

    if (PC_PLAYREADY_VERSION AND "${PC_PLAYREADY_VERSION}" EQUAL "3.3")
        add_definitions(-DPR_3_3)
    endif()

    if(PC_PLAYREADY_FOUND)
        find_path (PLAYREADY_INCLUDE NAME "playready.cmake" PATHS "usr/include/" PATH_SUFFIXES "playready")
        set(PLAYREADY_FLAGS ${PC_PLAYREADY_CFLAGS_OTHER} -DTARGET_SUPPORTS_UNALIGNED_DWORD_POINTERS=0 -DTARGET_LITTLE_ENDIAN=1)
        set(PLAYREADY_INCLUDE_DIRS ${PC_PLAYREADY_INCLUDE_DIRS})
        set(PLAYREADY_LIBRARIES ${PC_PLAYREADY_LIBRARIES})
        set(PLAYREADY_LIBRARY_DIRS ${PC_PLAYREADY_LIBRARY_DIRS})
    endif()
endif()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PLAYREADY DEFAULT_MSG PLAYREADY_INCLUDE_DIRS PLAYREADY_LIBRARIES)

mark_as_advanced(
    PLAYREADY_FOUND
    PLAYREADY_INCLUDE_DIRS
    PLAYREADY_LIBRARIES
    PLAYREADY_LIBRARY_DIRS
    PLAYREADY_FLAGS)

find_library(PLAYREADY_LIBRARY NAMES ${PLAYREADY_LIBRARIES}
        HINTS ${PLAYREADY_LIBDIR} ${PLAYREADY_LIBRARY_DIRS}
        )

if(PLAYREADY_LIBRARY AND NOT TARGET PlayReady::PlayReady)
    add_library(PlayReady::PlayReady UNKNOWN IMPORTED)
    set_target_properties(PlayReady::PlayReady PROPERTIES
            IMPORTED_LOCATION "${PLAYREADY_LIBRARY}"
            INTERFACE_LINK_LIBRARIES "${PLAYREADY_LIBRARIES}"
            INTERFACE_COMPILE_OPTIONS "${PLAYREADY_DEFINITIONS}"
            INTERFACE_INCLUDE_DIRECTORIES "${PLAYREADY_INCLUDE_DIRS}"
            )
endif()
