# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

cmake_minimum_required(VERSION 2.8)
project(qrlfast)

set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -std=c++11 -O3")
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BUILD_GO OFF CACHE BOOL "Enables go wrapper")
set(BUILD_PYTHON ON CACHE BOOL "Enables python wrapper")

message(STATUS "GOLANG WRAPPER" ${BUILD_GO})
message(STATUS "PYTHON WRAPPER" ${BUILD_PYTHON})

# Work around for OSX/brew
if (APPLE)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif ()

find_package(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})
unset(SWIG_LANG_TYPE)
find_package(OpenSSL REQUIRED)

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt
        ${OPENSSL_INCLUDE_DIR}
        #        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference
)

set(SWIG_INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/api.i)
file(GLOB_RECURSE LIB_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.cpp")
file(GLOB_RECURSE LIBTEST_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp")

set(LIBXMSSALT_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/algsxmss.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/hash_address.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/xmss_commons.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/randombytes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/wots.c
        #${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/xmss_core.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/fips202.c
        )

set(LIBXMSSREF_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/hash_address.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/xmss_commons.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/randombytes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/wots.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/xmss_core.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/fips202.c
        )

# Forcing XMSS to be compiled as C++
#add_definitions("-x c++")
SET_SOURCE_FILES_PROPERTIES(${LIB_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIBTEST_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIBXMSSALT_SRC} PROPERTIES LANGUAGE CXX)
#SET_SOURCE_FILES_PROPERTIES( ${LIBXMSSREF_SRC} PROPERTIES LANGUAGE CXX )

add_custom_target(
        prepareXMSSParams
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/params.h.py XMSS_SHAKE256_W16_H10 > ${CMAKE_CURRENT_SOURCE_DIR}/xmss-reference/params.h
)

##############################
# Google Test
# Based on instructions in https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download)
if (result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif ()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download)
if (result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif ()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_BINARY_DIR}/googletest-src
        ${CMAKE_BINARY_DIR}/googletest-build)

# The gtest/gtest_main targets carry header search path
# dependencies automatically when using CMake 2.8.11 or
# later. Otherwise we have to add them here ourselves.
if (CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include")
endif ()


# LIBRARY RELATED

# Google tests
add_executable(qrlfast_test
        ${LIBTEST_SRC}
        ${LIB_SRC}
        ${LIBXMSSALT_SRC}
        #        ${LIBXMSSREF_SRC}
        )
target_link_libraries(qrlfast_test gtest_main)
add_dependencies(qrlfast_test prepareXMSSParams)


## SWIG + API - Python related stuff
if (BUILD_PYTHON)
    message(STATUS ¨Python wrapper enabled¨)
    set(language python)
    find_package(PythonLibs 2.7 REQUIRED)
    include_directories(${PYTHON_INCLUDE_PATH})
    set(SWIG_LANG_LIBRARIES ${PYTHON_LIBRARIES})
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/pyqrlfast)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing")
    SWIG_ADD_LIBRARY(pyqrlfast
            LANGUAGE "${language}"
            ${SWIG_LANG_TYPE}
            SOURCES ${SWIG_INTERFACE}
            src/api/api.cxx
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
            #        ${LIBXMSSREF_SRC}
            )
    SWIG_LINK_LIBRARIES(pyqrlfast ${SWIG_LANG_LIBRARIES} ${OPENSSL_LIBRARIES})
    add_dependencies(${SWIG_MODULE_pyqrlfast_REAL_NAME} prepareXMSSParams)
    add_custom_command(TARGET ${SWIG_MODULE_pyqrlfast_REAL_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan $<TARGET_FILE:${SWIG_MODULE_pyqrlfast_REAL_NAME}>
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${SWIG_MODULE_pyqrlfast_REAL_NAME}> ${CMAKE_CURRENT_SOURCE_DIR}/pyqrlfast
            )
    # Get python packages destination
    #execute_process(COMMAND python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()"
    #                OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
    # Use CPack to create wheel packages
    #install(TARGETS _target DESTINATION ${PYTHON_SITE_PACKAGES})
    #install(FILES ${CMAKE_BINARY_DIR}/src/target.py DESTINATION ${PYTHON_SITE_PACKAGES})
endif ()

# SWIG + API - Golang related stuff
if (BUILD_GO)
    message(STATUS ¨golang wrapper enabled¨)
    set(language go)
    #find_package(go 1.5 REQUIRED)
    #include_directories(${PYTHON_INCLUDE_PATH})
    set(SWIG_LANG_LIBRARIES ${PYTHON_LIBRARIES})
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/goqrlfast)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-intgosize" "64")
    SWIG_ADD_LIBRARY(goqrlfast
            LANGUAGE "${language}"
            ${SWIG_LANG_TYPE}
            SOURCES ${SWIG_INTERFACE}
            src/api/api.cxx
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
            #${LIBXMSSREF_SRC}
            )
    SWIG_LINK_LIBRARIES(goqrlfast ${SWIG_LANG_LIBRARIES} ${OPENSSL_LIBRARIES})
    add_dependencies(${SWIG_MODULE_goqrlfast_REAL_NAME} prepareXMSSParams)
    add_custom_command(TARGET ${SWIG_MODULE_goqrlfast_REAL_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan $<TARGET_FILE:${SWIG_MODULE_goqrlfast_REAL_NAME}>
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${SWIG_MODULE_goqrlfast_REAL_NAME}> ${CMAKE_CURRENT_SOURCE_DIR}/goqrlfast
            )
endif ()
