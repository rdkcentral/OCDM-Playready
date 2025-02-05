# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 Metrological
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 2.8)
project(DRMPlayready)

if (DEFINED MAKE_VERBOSE)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "Playready")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -w -Wno-psabi ")

if(NOT CMAKE_CROSSCOMPILING)
   set(STAGING_DIR "${CMAKE_INSTALL_PREFIX}")
else()
   set(STAGING_DIR "${CMAKE_FIND_ROOT_PATH}")
endif()

if(DEFINED USE_PLAYREADY_CMAKE)
    find_package(PlayReady REQUIRED)
endif()

find_package(OpenSSL REQUIRED)

file(GLOB DRM_PLUGIN_INCLUDES *.h)

if(DEFINED USE_PLAYREADY_CMAKE)
set(DRM_PLUGIN_LIBS 
    ${PLAYREADY_LIBRARIES})
endif()

set(DRM_PLUGIN_SOURCES 
    MediaSession.cpp 
    MediaSystem.cpp
    MediaSessionExt.cpp)


# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})

if(DEFINED USE_PLAYREADY_CMAKE)
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY_INCLUDE_DIRS})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
endif()

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

# openssl library added
target_link_libraries(${DRM_PLUGIN_NAME} OpenSSL::SSL)

if(DEFINED PLAYREADY_REALTEK)
    target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE playreadypk)
    message(STATUS "PLAYREADY_REALTEK is ON")
elseif(DEFINED PLAYREADY_BROADCOM)
    #target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE NEXUS::NEXUS NXCLIENT::NXCLIENT NexusWidevine::NexusWidevine)
    #message(STATUS "PLAYREADY_BROADCOM is ON")
endif()

# Enable SVP.
#if("${RDK_SVP}" STREQUAL "ENABLED")
    message(STATUS "Using RDK_SVP")
    add_definitions (-DUSE_SVP)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/gstreamer-1.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/glib-2.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/lib/glib-2.0/include)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/WPEFramework)
    target_link_libraries(${DRM_PLUGIN_NAME} gstsvpext)
#endif()

if("${DYNAMIC_SVP_DECRYPTION}" STREQUAL "ON")
    add_definitions( -DDYNAMIC_SVP_DECRYPTION )
    message(STATUS "DYNAMIC_SVP_DECRYPTION is ON")
else()
    message(STATUS "DYNAMIC_SVP_DECRYPTION is OFF")
endif()

if("${RESOLUTION_CHECK_ENABLED}" STREQUAL "ON")
    add_definitions( -DRESOLUTION_CHECK_ENABLED )
    message(STATUS "RESOLUTION_CHECK_ENABLED is ON")
else()
    message(STATUS "DYNAMIC_SVP_DECRYPTION is OFF")
endif()

if("${NO_PERSISTENT_LICENSE_CHECK}" STREQUAL "ON")
    add_definitions( -DNO_PERSISTENT_LICENSE_CHECK=1 )
    message(STATUS "NO_PERSISTENT_LICENSE_CHECK is ON")
else()
    message(STATUS "NO_PERSISTENT_LICENSE_CHECK is OFF")
endif()

if("${TEE_CONFIG_NEED}" STREQUAL "ON")
    add_definitions( -DTEE_CONFIG_NEED=1 )
    message(STATUS "TEE_CONFIG_NEED is ON")
else()
    message(STATUS "TEE_CONFIG_NEED is OFF")
endif()

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)