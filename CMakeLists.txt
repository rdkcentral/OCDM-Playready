cmake_minimum_required(VERSION 3.3)
project(DRMPlayready)

find_package(WPEFramework)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(PLUGIN_NAME Playready)
set(MODULE_NAME ${PLUGIN_NAME})

find_package(PlayReady REQUIRED)

add_library(${MODULE_NAME} SHARED
    MediaSession.cpp
    MediaSystem.cpp
    MediaSessionExt.cpp
    MediaSystemExt.cpp)

set_target_properties(${MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES)

include("${PLAYREADY_INCLUDE}/playready.cmake")

target_include_directories(${MODULE_NAME}
    PUBLIC
    "${CMAKE_SYSROOT}/usr/include"
    "${CMAKE_SYSROOT}/usr/include/WPEFramework"
    ${PLAYREADY_INCLUDE}
    ${PLAYREADY_INCLUDE_DIRS}
    "${PLAYREADY_INCLUDE}/oem/inc")


target_compile_definitions(${MODULE_NAME}
        PRIVATE
            PLAYREADY=ON
            PLAYREADY2=ON
            PLAYREADY2TEE=ON
            PLAYREADY2_5=ON
            PLAYREADY2_5_TEE=ON
            PLAYREADY2_5_TEE_LDL=ON
            ${PLAYREADY_FLAGS})

target_link_libraries(${MODULE_NAME}
    PRIVATE
        PlayReady::PlayReady)

# Library installation section
set_target_properties(${MODULE_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${MODULE_NAME} PROPERTIES PREFIX "")

install(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)
write_config(${PLUGIN_NAME})
