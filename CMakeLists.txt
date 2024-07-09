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

cmake_minimum_required(VERSION 3.3)
project(DRMPlayready)

find_package(Thunder)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(MODULE_NAME Playready)


find_package(${NAMESPACE}Core REQUIRED)
find_package(PlayReady REQUIRED)

add_library(${MODULE_NAME} SHARED
    MediaSession.cpp
    MediaSystem.cpp
    MediaSessionExt.cpp)

set_target_properties(${MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES)

target_compile_definitions(${MODULE_NAME} 
    PRIVATE 
        BSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE
        DRM_BUILD_PROFILE=900
)

target_include_directories(${MODULE_NAME}
    PRIVATE
    "${CMAKE_SYSROOT}/usr/include"
    "${CMAKE_SYSROOT}/usr/include/${NAMESPACE}"
    ${PLAYREADY_INCLUDE_DIRS})

target_link_libraries(${MODULE_NAME}
    ${NAMESPACE}Core::${NAMESPACE}Core
    ${PLAYREADY_LIBRARIES})

# Library installation section
set_target_properties(${MODULE_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${MODULE_NAME} PROPERTIES PREFIX "")

install(TARGETS ${MODULE_NAME}
    PERMISSIONS OWNER_READ GROUP_READ
    DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

if(NOT "${CMAKE_FIND_ROOT_PATH}" STREQUAL "")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink /etc/playready  ${CMAKE_CURRENT_BINARY_DIR}/playready)")
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/../${PERSISTENT_PATH}/OCDM)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/playready DESTINATION ${CMAKE_INSTALL_PREFIX}/../${PERSISTENT_PATH}/OCDM/)
endif()
