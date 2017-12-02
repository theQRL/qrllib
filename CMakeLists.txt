# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

cmake_minimum_required(VERSION 3.5)
project(qrllib)

set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -std=c++14 -O3")

set(CMAKE_VERBOSE_MAKEFILE FALSE)
set(CMAKE_ERROR_DEPRECATED FALSE)
set(CMAKE_WARN_DEPRECATED FALSE)

set(BUILD_TESTS ON CACHE BOOL "Enables tests")
set(BUILD_GO OFF CACHE BOOL "Enables go wrapper")
set(BUILD_PYTHON OFF CACHE BOOL "Enables python wrapper")
set(BUILD_PYTHON_LOCALDEPLOY OFF CACHE BOOL "Deploys python locally")
set(BUILD_WEBASSEMBLY OFF CACHE BOOL "Enables emscripten build")

message(STATUS "GOLANG WRAPPER " ${BUILD_GO})
message(STATUS "PYTHON WRAPPER " ${BUILD_PYTHON})
message(STATUS "WEBASSEMBLY " ${BUILD_WEBASSEMBLY})

if (BUILD_PYTHON OR BUILD_GO)
    find_package(SWIG REQUIRED)
    INCLUDE(${SWIG_USE_FILE})
    unset(SWIG_LANG_TYPE)
endif()

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt
        ${CMAKE_CURRENT_SOURCE_DIR}/PicoSHA2
)

file(GLOB_RECURSE LIB_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.cpp")

file(GLOB_RECURSE LIBTEST_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp")

set(LIBXMSSALT_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/algsxmss_fast.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/algsxmss.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/hash_address.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/xmss_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/wots.c
        #${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/xmss_core.c
        ${CMAKE_CURRENT_SOURCE_DIR}/xmss-alt/fips202.c
        )

# Forcing XMSS to be compiled as C++
SET_SOURCE_FILES_PROPERTIES(${LIB_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIBTEST_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIBXMSSALT_SRC} PROPERTIES LANGUAGE CXX)


if (BUILD_TESTS)
    message(STATUS "Python wrapper enabled")

    ##############################
    # Google Test
    # Based on instructions in https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
    # Download and unpack googletest at configure time
    configure_file(CMakeLists.txt.gtest.in googletest-download/CMakeLists.txt)
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

    # Prevent overriding the parent project's compiler/linker settings on Windows
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

    # Google tests
    add_executable(qrllib_test
            ${LIBTEST_SRC}
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
            )

    target_link_libraries(qrllib_test gtest_main)

    include(CTest)
    enable_testing()

    add_test(gtest ${PROJECT_BINARY_DIR}/qrllib_test)
endif()

## SWIG + API - Python related stuff
if (BUILD_PYTHON)
    message(STATUS "Python wrapper enabled")

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR} )
    endif()

    set(SWIG_INTERFACE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/api/api.i)

    set(language python)
    find_package(PythonLibs 3.4 REQUIRED)
    include_directories(${PYTHON_INCLUDE_PATH})

    set(SWIG_LANG_LIBRARIES ${PYTHON_LIBRARIES})

    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)

    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing")

    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)

    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    # Intentionally use a deprecated version to provide support for the raspberry pi
    SWIG_ADD_MODULE( pyqrllib
            ${language}
            ${SWIG_INTERFACE}
            src/api/api.cxx
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
            )

    SWIG_LINK_LIBRARIES(pyqrllib ${SWIG_LANG_LIBRARIES} )

    add_custom_command(TARGET ${SWIG_MODULE_pyqrllib_REAL_NAME}
            POST_BUILD
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${SWIG_MODULE_pyqrllib_REAL_NAME}> ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_pyqrllib_REAL_NAME}>
            )

    add_custom_command(TARGET ${SWIG_MODULE_pyqrllib_REAL_NAME}
            POST_BUILD
            COMMENT ${swig_extra_generated_files}
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/pyqrllib.py
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
    set(SWIG_INTERFACE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/api/api.i)

    message(STATUS "golang wrapper enabled")
    set(language go)
    #find_package(go 1.5 REQUIRED)
    set(SWIG_LANG_LIBRARIES ${PYTHON_LIBRARIES})
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-intgosize" "64")

    SWIG_ADD_MODULE( goqrllib
            ${language}
            ${SWIG_INTERFACE}
            src/api/api.cxx
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
            )

    SWIG_LINK_LIBRARIES(goqrllib ${SWIG_LANG_LIBRARIES} )

    add_custom_command(TARGET ${SWIG_MODULE_goqrllib_REAL_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan $<TARGET_FILE:${SWIG_MODULE_goqrllib_REAL_NAME}>
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${SWIG_MODULE_goqrllib_REAL_NAME}> ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib
            )
endif ()

if (BUILD_WEBASSEMBLY)
    set(JS_INTERFACE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jswrapper.cpp
            )

    message(STATUS "webassembly enabled")
    add_library(jsqrl SHARED
            ${JS_INTERFACE}
            ${LIB_SRC}
            ${LIBXMSSALT_SRC}
    )

    target_link_libraries(jsqrl)

endif ()
