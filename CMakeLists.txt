# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

cmake_minimum_required(VERSION 3.5)

# macOS-specific compiler detection
# Apple Clang has compatibility issues with Google Test on macOS.
# Automatically use gcc-13 if available (install via: brew install gcc@13)
if(APPLE AND NOT DEFINED CMAKE_C_COMPILER AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(GCC13 gcc-13)
    find_program(GXX13 g++-13)

    if(GCC13 AND GXX13)
        set(CMAKE_C_COMPILER ${GCC13})
        set(CMAKE_CXX_COMPILER ${GXX13})
        message(STATUS "macOS detected: Using gcc-13/g++-13 for better Google Test compatibility")
    else()
        message(WARNING "macOS detected: gcc-13 not found. Install with 'brew install gcc@13' to avoid build issues with Google Test.")
    endif()
endif()

project(qrllib)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic")

# Fix for GCC on macOS - ensure SDK is set for proper compilation
# Note: If you encounter errors about missing FILE, stdio.h, etc., you may need to
# rename the broken include-fixed directory:
#   mv /usr/local/Cellar/gcc@13/*/lib/gcc/*/gcc/x86_64-apple-darwin23/*/include-fixed{,.bak}
if(APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # Ensure SDK is set
    if(NOT CMAKE_OSX_SYSROOT)
        execute_process(COMMAND xcrun --show-sdk-path
                        OUTPUT_VARIABLE CMAKE_OSX_SYSROOT
                        OUTPUT_STRIP_TRAILING_WHITESPACE)
        message(STATUS "Setting macOS SDK: ${CMAKE_OSX_SYSROOT}")
    endif()
endif()

if(${CMAKE_VERSION} VERSION_GREATER "3.10.3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wno-deprecated-declarations")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Wno-deprecated")
if(${CMAKE_VERSION} VERSION_GREATER "3.13")
    cmake_policy(SET CMP0078 OLD)
endif()

set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_ERROR_DEPRECATED FALSE)
set(CMAKE_WARN_DEPRECATED FALSE)

option(BUILD_TESTS "Enable tests" ON)
option(BUILD_GO "Enable go wrapper" OFF)
option(BUILD_PYTHON "Enable python wrapper" OFF)
option(BUILD_WEBASSEMBLY "Enable emscripten build" OFF)

if (BUILD_WEBASSEMBLY)
    message(WARNING "webassembly enabled. Disabling other modules")
    set(BUILD_PYTHON 0)
    set(BUILD_GO 0)
    set(BUILD_TESTS 0)
endif ()

message(STATUS "BUILD_TESTS    " ${BUILD_TESTS})
message(STATUS "GOLANG WRAPPER " ${BUILD_GO})
message(STATUS "PYTHON WRAPPER " ${BUILD_PYTHON})
message(STATUS "WEBASSEMBLY    " ${BUILD_WEBASSEMBLY})

if (BUILD_PYTHON OR BUILD_GO)
    find_package(SWIG REQUIRED)
    INCLUDE(${SWIG_USE_FILE})
    unset(SWIG_LANG_TYPE)
endif ()

if (BUILD_PYTHON)
  # Improved Python Detection ===>
  # Ensures that CMake uses the Python version that invoked pip/setup.py
  # rather than automatically discovering the system Python (which may be wrong)

  # Priority 1: Use Python_EXECUTABLE if explicitly provided via cmake -D
  # Priority 2: Use PYTHON_EXECUTABLE if explicitly provided via cmake -D
  # Priority 3: Use the Python interpreter that's currently running (from environment)
  # Priority 4: Let CMake find Python automatically (fallback)

  if(NOT DEFINED Python_EXECUTABLE AND NOT DEFINED Python3_EXECUTABLE)
      # Try to get the Python executable from environment
      # This is set by pip during install or by setup.py
      if(DEFINED ENV{Python_EXECUTABLE})
          set(Python_EXECUTABLE $ENV{Python_EXECUTABLE})
          message(STATUS "Using Python from environment: ${Python_EXECUTABLE}")
      elseif(DEFINED ENV{PYTHON})
          set(Python_EXECUTABLE $ENV{PYTHON})
          message(STATUS "Using Python from PYTHON env var: ${Python_EXECUTABLE}")
      elseif(DEFINED PYTHON_EXECUTABLE)
          set(Python_EXECUTABLE ${PYTHON_EXECUTABLE})
          message(STATUS "Using Python from PYTHON_EXECUTABLE: ${Python_EXECUTABLE}")
      endif()
  endif()

  # Set hints for CMake's find_package(Python)
  if(DEFINED Python_EXECUTABLE)
      get_filename_component(Python_ROOT_DIR "${Python_EXECUTABLE}" DIRECTORY)
      get_filename_component(Python_ROOT_DIR "${Python_ROOT_DIR}" DIRECTORY)
      set(Python_ROOT_DIR "${Python_ROOT_DIR}" CACHE PATH "Path to Python installation")
      set(Python3_EXECUTABLE "${Python_EXECUTABLE}" CACHE FILEPATH "Path to Python3 executable")
      message(STATUS "Python_ROOT_DIR set to: ${Python_ROOT_DIR}")
  endif()

  # <=== Improved Python Detection

  if(${CMAKE_VERSION} VERSION_GREATER "3.12")
    set(Python_ADDITIONAL_VERSIONS 3 3.7 3.8 3.9 3.6 3.5)
    find_package(Python COMPONENTS Interpreter Development REQUIRED)
    message("Python_FOUND:${Python_FOUND}")
    message("Python_VERSION:${Python_VERSION}")
    message("Python_Development_FOUND:${Python_Development_FOUND}")
    message("Python_LIBRARIES:${Python_LIBRARIES}")
  else ()
    set(Python_ADDITIONAL_VERSIONS 3 3.6 3.5)
    find_package(PythonLibs REQUIRED)
    find_package(PythonInterp REQUIRED)
    set(Python_INCLUDE_DIRS "${Python_INCLUDE_DIRS}")
    set(Python_LIBRARIES "${Python_LIBRARIES}")
  endif ()
endif ()

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps
)

file(GLOB LIB_QRL_INCLUDES
        src/xmss-alt
        ${CMAKE_CURRENT_SOURCE_DIR}/src/qrl
        )

file(GLOB LIB_SHASHA_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/shasha
        )

file(GLOB LIB_DILITHIUM_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dilithium
        )

file(GLOB LIB_KYBER_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kyber
        )

file(GLOB_RECURSE LIB_QRL_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/qrl/*.cpp")

file(GLOB_RECURSE LIB_DILITHIUM_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/dilithium/*.cpp")

file(GLOB_RECURSE LIB_KYBER_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/kyber/*.cpp")

set(LIBXMSSALT_SRC
        src/xmss-alt/algsxmss_fast.c
        src/xmss-alt/algsxmss.c
        src/xmss-alt/hash.c
        src/xmss-alt/hash_address.c
        src/xmss-alt/xmss_common.c
        src/xmss-alt/wots.c
        src/xmss-alt/fips202.c
        )

file(GLOB_RECURSE LIB_SHASHA_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/shasha/*.cpp
        )

set(REF_DILITHIUM_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/randombytes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/polyvec.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/packing.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/poly.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/ntt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/rounding.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/fips202.c
        )

set(REF_KYBER_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/randombytes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/kem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/poly.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/polyvec.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/cbd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/precomp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/ntt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/verify.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/indcpa.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/kex.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/fips202.c
        )

file(GLOB_RECURSE TEST_QRL_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/qrl/*.cpp")

file(GLOB_RECURSE TEST_SHASHA_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/shasha/*.cpp")

file(GLOB_RECURSE TEST_DILITHIUM_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/dilithium/*.cpp")

file(GLOB_RECURSE TEST_KYBER_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/kyber/*.cpp")

# Forcing XMSS to be compiled as C++
SET_SOURCE_FILES_PROPERTIES(${LIB_QRL_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIBXMSSALT_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${LIB_SHASHA_SRC} PROPERTIES LANGUAGE CXX)

SET_SOURCE_FILES_PROPERTIES(${TEST_QRL_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${TEST_DILITHIUM_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${TEST_KYBER_SRC} PROPERTIES LANGUAGE CXX)

SET_SOURCE_FILES_PROPERTIES(${REF_DILITHIUM_SRC} PROPERTIES LANGUAGE CXX)
SET_SOURCE_FILES_PROPERTIES(${REF_KYBER_SRC} PROPERTIES LANGUAGE CXX)

add_library(shasha STATIC
        ${LIB_SHASHA_SRC})
target_include_directories(shasha PRIVATE ${LIB_SHASHA_INCLUDES} )

add_library(qrllib STATIC
        ${LIB_QRL_SRC}
        ${LIBXMSSALT_SRC})
target_include_directories(qrllib PRIVATE
        ${LIB_QRL_INCLUDES}
        ${LIB_SHASHA_INCLUDES})
target_link_libraries(qrllib shasha)

add_library(dilithium STATIC
        ${LIB_DILITHIUM_SRC}
        ${REF_DILITHIUM_SRC})
target_include_directories(dilithium PRIVATE
        ${LIB_DILITHIUM_INCLUDES} )

add_library(kyber STATIC
        ${LIB_KYBER_SRC}
        ${REF_KYBER_SRC})
target_include_directories(kyber PRIVATE
        ${LIB_KYBER_INCLUDES} )

if (BUILD_TESTS)
    message(STATUS "GTests enabled")

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
    add_subdirectory(
            ${CMAKE_BINARY_DIR}/googletest-src
            ${CMAKE_BINARY_DIR}/googletest-build
    )

    # The gtest/gtest_main targets carry header search path
    # dependencies automatically when using CMake 2.8.11 or
    # later. Otherwise we have to add them here ourselves.
    if (CMAKE_VERSION VERSION_LESS 2.8.11)
        include_directories("${gtest_SOURCE_DIR}/include")
    endif ()

    ###########################
    include(CTest)
    enable_testing()

    add_executable(qrllib_test
            ${TEST_QRL_SRC})

    target_include_directories( qrllib_test PRIVATE
            ${LIB_QRL_INCLUDES}
            ${LIB_SHASHA_INCLUDES})
    target_link_libraries(qrllib_test qrllib gtest_main)
    add_test(qrllib_test ${PROJECT_BINARY_DIR}/qrllib_test)

    ###########################

    add_executable(shasha_test
            ${TEST_SHASHA_SRC})

    target_include_directories( shasha_test PRIVATE
            ${LIB_SHASHA_INCLUDES} )
    target_link_libraries(shasha_test shasha qrllib gtest_main)
    add_test(shasha_test ${PROJECT_BINARY_DIR}/shasha_test)

    ###########################

    add_executable(dilithium_test
            ${TEST_DILITHIUM_SRC})

    target_include_directories( dilithium_test PRIVATE
            ${LIB_DILITHIUM_INCLUDES} )

    target_link_libraries(dilithium_test dilithium gtest_main)
    add_test(dilithium_test ${PROJECT_BINARY_DIR}/dilithium_test)

    ###########################

    add_executable(kyber_test
            ${TEST_KYBER_SRC})

    target_include_directories( kyber_test PRIVATE
            ${LIB_KYBER_INCLUDES} )

    target_link_libraries(kyber_test kyber gtest_main)
    add_test(kyber_test ${PROJECT_BINARY_DIR}/kyber_test)

endif ()

## SWIG + API - Python related stuff
if (BUILD_PYTHON)
    message(STATUS "Python wrapper enabled")

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif ()

    set(language python)

    include_directories(
          ${Python_INCLUDE_DIRS}
    )
    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)

    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/pyqrllib.i)
    set(SWIG_LANG_LIBRARIES ${Python_LIBRARIES})
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-py3")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    # Intentionally use a deprecated version to provide support for the raspberry pi
    # Basic pyqrllib - XmssBasic, etc.
    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        SWIG_ADD_MODULE(pyqrllib
                ${language}
                ${SWIG_INTERFACE}
                ${LIB_QRL_SRC}
                ${LIBXMSSALT_SRC}
                )
    else()
        SWIG_ADD_LIBRARY(pyqrllib
                LANGUAGE ${language}
                OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                OUTFILE_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                TYPE MODULE
                SOURCES ${SWIG_INTERFACE}
                ${LIB_QRL_SRC}
                ${LIBXMSSALT_SRC}
                )
    endif()

    SWIG_LINK_LIBRARIES(pyqrllib
            shasha
            ${SWIG_LANG_LIBRARIES})

    include_directories(
            ${PYTHON_INCLUDE_PATH}
            ${LIB_QRL_INCLUDES}
            ${LIB_SHASHA_INCLUDES}
    )
    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        add_custom_command(TARGET ${SWIG_MODULE_pyqrllib_REAL_NAME}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE_pyqrllib_REAL_NAME}>
                ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_pyqrllib_REAL_NAME}>
                )

        add_custom_command(TARGET ${SWIG_MODULE_pyqrllib_REAL_NAME}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/pyqrllib.py
                )
    endif()
    ###################################################
    # Dilithium
    set(SWIG_INTERFACE src/api/dilithium.i)
    set(SWIG_LANG_LIBRARIES ${Python_LIBRARIES})
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-py3")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    set(SWIG_INTERFACE
            src/api/dilithium.i)

    include_directories(
            ${PYTHON_INCLUDE_PATH}
            ${LIB_DILITHIUM_INCLUDES}
    )

    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        SWIG_ADD_MODULE(dilithium
                ${language}
                ${SWIG_INTERFACE}
                ${LIB_DILITHIUM_SRC}
                ${REF_DILITHIUM_SRC}
                )
    else()
        SWIG_ADD_LIBRARY(dilithium
                LANGUAGE ${language}
                OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                OUTFILE_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                TYPE MODULE
                SOURCES ${SWIG_INTERFACE}
                ${LIB_DILITHIUM_SRC}
                ${REF_DILITHIUM_SRC}
                )
    endif()

    SWIG_LINK_LIBRARIES(dilithium
            ${SWIG_LANG_LIBRARIES})

    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        add_custom_command(TARGET ${SWIG_MODULE_dilithium_REAL_NAME}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE_dilithium_REAL_NAME}>
                ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_dilithium_REAL_NAME}>
                )

        add_custom_command(TARGET ${SWIG_MODULE_dilithium_REAL_NAME}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/dilithium.py
                )
    endif()

    # Kyber
    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/kyber.i)
    set(SWIG_LANG_LIBRARIES ${Python_LIBRARIES})
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-py3")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        SWIG_ADD_MODULE(kyber
                ${language}
                ${SWIG_INTERFACE}
                ${LIB_KYBER_SRC}
                ${REF_KYBER_SRC}
                )
    else()
        SWIG_ADD_LIBRARY(kyber
                LANGUAGE ${language}
                OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                OUTFILE_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                TYPE MODULE
                SOURCES ${SWIG_INTERFACE}
                ${LIB_KYBER_SRC}
                ${REF_KYBER_SRC}
                )
    endif()

    SWIG_LINK_LIBRARIES(kyber
            ${SWIG_LANG_LIBRARIES})

    if(${CMAKE_VERSION} VERSION_LESS_EQUAL "3.10.3")
        add_custom_command(TARGET ${SWIG_MODULE_kyber_REAL_NAME}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE_kyber_REAL_NAME}>
                ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_kyber_REAL_NAME}>
                )

        add_custom_command(TARGET ${SWIG_MODULE_kyber_REAL_NAME}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/pyqrllib/kyber.py
                )
    endif()
endif ()

## SWIG + API - Go related stuff
if (BUILD_GO)
    message(STATUS "Go wrapper enabled")

    unset(CMAKE_LIBRARY_OUTPUT_DIRECTORY)

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif ()

    set(language go)

    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/goqrllib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/goqrllib)

    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/pyqrllib.i)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-cgo" "-intgosize" "64" "-c++")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    # Intentionally use a deprecated version to provide support for the raspberry pi
    SWIG_ADD_MODULE(goqrllib
            ${language}
            ${SWIG_INTERFACE}
            ${LIB_QRL_SRC}
            ${LIBXMSSALT_SRC}
            )

    SWIG_LINK_LIBRARIES(goqrllib
            shasha
            ${SWIG_LANG_LIBRARIES})

    include_directories(
            ${LIB_QRL_INCLUDES}
            ${LIB_SHASHA_INCLUDES}
    )

    add_custom_command(TARGET ${SWIG_MODULE_goqrllib_REAL_NAME}
            POST_BUILD
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E
            copy_if_different $<TARGET_FILE:${SWIG_MODULE_goqrllib_REAL_NAME}>
            ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/goqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_goqrllib_REAL_NAME}>
            COMMENT "Updating goqrllib flags"
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/update_goqrllib_flags.sh ${CMAKE_CURRENT_SOURCE_DIR}
            )

    #add_custom_command(TARGET ${SWIG_MODULE_goqrllib_REAL_NAME}
    #        POST_BUILD
    #        COMMENT ${swig_extra_generated_files}
    #        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/pyqrllib.go
    #        )

    ###################################################
    # Dilithium
    unset(CMAKE_LIBRARY_OUTPUT_DIRECTORY)

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif ()

    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/dilithium)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/dilithium)

    
    set(SWIG_INTERFACE src/api/dilithium.i)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-cgo" "-intgosize" "64" "-c++")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    set(SWIG_INTERFACE
            src/api/dilithium.i)

    include_directories(
            ${LIB_DILITHIUM_INCLUDES}
    )

    SWIG_ADD_MODULE(godilithium
            ${language}
            ${SWIG_INTERFACE}
            ${LIB_DILITHIUM_SRC}
            ${REF_DILITHIUM_SRC}
            )

    SWIG_LINK_LIBRARIES(godilithium
            ${SWIG_LANG_LIBRARIES})

    add_custom_command(TARGET ${SWIG_MODULE_godilithium_REAL_NAME}
            POST_BUILD
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E
            copy_if_different $<TARGET_FILE:${SWIG_MODULE_godilithium_REAL_NAME}>
            ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/dilithium/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_godilithium_REAL_NAME}>
            COMMENT "Updating godilithium flags"
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/update_godilithium_flags.sh ${CMAKE_CURRENT_SOURCE_DIR}
            )

    #add_custom_command(TARGET ${SWIG_MODULE_godilithium_REAL_NAME}
    #        POST_BUILD
    #        COMMENT ${swig_extra_generated_files}
    #        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/godilithium.go
    #        )


    # Kyber
    unset(CMAKE_LIBRARY_OUTPUT_DIRECTORY)

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif ()

    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/kyber)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/goqrllib/kyber)
    
    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/kyber.i)
    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
    set_property(SOURCE ${SWIG_INTERFACE} PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing" "-cgo" "-intgosize" "64" "-c++")
    message(STATUS "CMAKE_SWIG_OUTDIR: " ${CMAKE_SWIG_OUTDIR})
    message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY: " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

    SWIG_ADD_MODULE(gokyber
            ${language}
            ${SWIG_INTERFACE}
            ${LIB_KYBER_SRC}
            ${REF_KYBER_SRC}
            )

    SWIG_LINK_LIBRARIES(gokyber
            ${SWIG_LANG_LIBRARIES})

    add_custom_command(TARGET ${SWIG_MODULE_gokyber_REAL_NAME}
            POST_BUILD
            COMMENT "Moving SWIG files to output dir"
            COMMAND ${CMAKE_COMMAND} -E
            copy_if_different $<TARGET_FILE:${SWIG_MODULE_gokyber_REAL_NAME}>
            ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/kyber/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE_gokyber_REAL_NAME}>
            COMMENT "Updating gokyber flags"
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/update_gokyber_flags.sh ${CMAKE_CURRENT_SOURCE_DIR}
            )

    #add_custom_command(TARGET ${SWIG_MODULE_gokyber_REAL_NAME}
    #        POST_BUILD
    #        COMMENT ${swig_extra_generated_files}
    #        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${swig_extra_generated_files} ${CMAKE_CURRENT_SOURCE_DIR}/goqrllib/gokyber.go
    #        )

endif ()

if (BUILD_WEBASSEMBLY)
    set(JS_QRL_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jsqrlwrapper.cpp)

    message(WARNING "webassembly enabled")

    add_library(jsqrl SHARED
            ${JS_QRL_INTERFACE}
            ${LIB_QRL_SRC}
            ${LIB_SHASHA_SRC}
            ${LIBXMSSALT_SRC}
            )

    target_include_directories( jsqrl PRIVATE
            ${LIB_QRL_INCLUDES}
            ${LIB_SHASHA_INCLUDES})

    set_target_properties(jsqrl
            PROPERTIES LINK_FLAGS "-s DISABLE_EXCEPTION_CATCHING=0"
            )


   set(JS_DILITHIUM_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jsdilwrapper.cpp)

   add_library(jsdilithium SHARED
           ${JS_DILITHIUM_INTERFACE}
           ${LIB_DILITHIUM_SRC}
           ${LIBDILITHIUM_SRC}
           ${REF_DILITHIUM_SRC}
           ${LIB_QRL_SRC}
           )
   target_include_directories( jsdilithium PRIVATE
        ${LIB_QRL_INCLUDES}
        ${LIB_DILITHIUM_INCLUDES} )

   set(JS_KYBER_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jskybwrapper.cpp)

   add_library(jskyber SHARED
           ${JS_KYBER_INTERFACE}
           ${LIB_KYBER_SRC}
           ${LIBKYBER_SRC}
           ${REF_KYBER_SRC}
           ${LIB_QRL_SRC}
           )
   target_include_directories( jskyber PRIVATE
           ${LIB_QRL_INCLUDES}
           ${LIB_KYBER_INCLUDES} )

endif ()