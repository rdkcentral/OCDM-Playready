cmake_minimum_required(VERSION 2.8)
project(DRMPlayready)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "PlayReady")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(NOT NAMESPACE)
   set(NAMESPACE "WPEFramework")
endif()

find_package(PlayReady)

include_directories(${STAGING_DIR}/usr/include/WPEFramework)
#include_directories(${STAGING_DIR}/usr/include/playready)

set(PLAYREADY_INCLUDE "${STAGING_DIR}/usr/include/playready")

add_definitions( -DPLAYREADY )
add_definitions( -DPLAYREADY2 )
add_definitions( -DPLAYREADY2TEE )
add_definitions( -DPLAYREADY2_5 )
add_definitions( -DPLAYREADY2_5_TEE )
add_definitions( -DPLAYREADY2_5_TEE_LDL )

include("${PLAYREADY_INCLUDE}/playready.cmake")

include_directories(${PLAYREADY_INCLUDE})
include_directories(${PLAYREADY_INCLUDE}/oem/inc)
include_directories(${PLAYREADY_INCLUDE}/oem/ansi/inc)
include_directories(${PLAYREADY_INCLUDE}/oem/common/inc)

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_LIBS 
    ${PLAYREADY_LIBRARIES}
    ${STAGING_DIR}/usr/lib/libplayready.so) # TODO: why is this needed and this will become a static lib

set(DRM_PLUGIN_SOURCES 
    MediaSession.cpp 
    MediaSystem.cpp
    MediaSessionExt.cpp
    MediaSystemExt.cpp
)

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY_INCLUDE_DIRS})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
