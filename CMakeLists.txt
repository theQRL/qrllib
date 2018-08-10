# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

cmake_minimum_required(VERSION 3.5)
project(qrllib)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_ERROR_DEPRECATED FALSE)
set(CMAKE_WARN_DEPRECATED FALSE)

option(BUILD_TESTS "Enable tests" ON )
option(BUILD_GO "Enable go wrapper" OFF )
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

set(DEPS_SOURCE_DIR ${PROJECT_SOURCE_DIR}/deps)

if(WIN32)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -DWIN32_LEAN_AND_MEAN)
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fPIC -Wno-deprecated-declarations")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wno-deprecated")
endif()

if (BUILD_PYTHON OR BUILD_GO)
    find_package(SWIG REQUIRED)
    INCLUDE(${SWIG_USE_FILE})
    unset(SWIG_LANG_TYPE)
endif ()

if (BUILD_PYTHON)
    set(Python_ADDITIONAL_VERSIONS 3 3.6 3.5)
    find_package(PythonLibs REQUIRED)
    find_package(PythonInterp REQUIRED)
endif ()

set(REF_KYBER_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/kem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/poly.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/polyvec.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/cbd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/ntt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/verify.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/indcpa.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/kyber/ref/fips202.c
        )

file(GLOB_RECURSE LIB_KYBER_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/kyber/*.cpp")

set(REF_DILITHIUM_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/polyvec.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/packing.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/poly.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/ntt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/rounding.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/dilithium/ref/fips202.c
        )

file(GLOB_RECURSE LIB_DILITHIUM_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/dilithium/*.cpp")


file(GLOB_RECURSE LIB_SHASHA_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/shasha/*.cpp
        )

set(LIBUTIL_SRC
        src/util/random.cpp
        src/util/hashing.cpp
        )

set(LIBXMSSALT_SRC
        src/xmss-alt/algsxmss_fast.c
        src/xmss-alt/algsxmss.c
        src/xmss-alt/hash.c
        src/xmss-alt/hash_address.c
        src/xmss-alt/xmss_common.c
        src/xmss-alt/wots.c
        src/xmss-alt/fips202.c
        )

set(LIB_QRL_SRC
  src/qrl/misc.cpp
  src/qrl/wordlist.cpp
  src/qrl/xmssBase.cpp
  src/qrl/xmssBasic.cpp
  src/qrl/xmssFast.cpp
  src/qrl/xmssPool.cpp
  )

# TODO: library sources could be reorganized at some point to properly manage
#       interface/implementation headers and remove the intercomponent deps.

add_library(PicoSHA2 INTERFACE IMPORTED)
set_target_properties(PicoSHA2 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${DEPS_SOURCE_DIR}/PicoSHA2")

add_library(shasha STATIC ${LIB_SHASHA_SRC})
target_include_directories(shasha INTERFACE src/shasha)
target_link_libraries(shasha PRIVATE PicoSHA2)

add_library(util STATIC ${LIBUTIL_SRC})
target_include_directories(util
  INTERFACE src
  PRIVATE $<TARGET_PROPERTY:dilithium_ref,INTERFACE_INCLUDE_DIRECTORIES>)
# TODO: remove dilithium_ref circular dep. (fips202.c linkage)
target_link_libraries(util PRIVATE PicoSHA2 dilithium_ref)

if(WIN32)
  target_link_libraries(util PRIVATE bcrypt.lib)
endif()

# NOTE: exporting ${DEPS_SOURCE_DIR} as interface directory
add_library(kyber_ref STATIC ${REF_KYBER_SRC})
target_include_directories(kyber_ref INTERFACE ${DEPS_SOURCE_DIR})
target_link_libraries(kyber_ref PRIVATE util)

add_library(kyber STATIC ${LIB_KYBER_SRC})
target_include_directories(kyber INTERFACE src/kyber)
target_link_libraries(kyber PRIVATE kyber_ref)

# NOTE: exporting ${DEPS_SOURCE_DIR} as interface directory
add_library(dilithium_ref STATIC ${REF_DILITHIUM_SRC})
target_include_directories(dilithium_ref INTERFACE ${DEPS_SOURCE_DIR})
target_link_libraries(dilithium_ref PRIVATE util)

add_library(dilithium STATIC ${LIB_DILITHIUM_SRC})
target_include_directories(dilithium INTERFACE src/dilithium)
target_link_libraries(dilithium PRIVATE dilithium_ref)

add_library(xmss_alt STATIC ${LIBXMSSALT_SRC})
set_source_files_properties(${LIBXMSSALT_SRC} PROPERTIES LANGUAGE CXX)
target_include_directories(xmss_alt INTERFACE src src/xmss-alt)
target_link_libraries(xmss_alt shasha)

add_library(qrllib STATIC ${LIB_QRL_SRC})
target_include_directories(qrllib INTERFACE src src/qrl)
target_link_libraries(qrllib PRIVATE util xmss_alt PicoSHA2)

if (BUILD_TESTS)
    include(CTest)
    message(STATUS "GTests enabled")

    file(GLOB_RECURSE TEST_QRL_SRC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/qrl/*.cpp")

    file(GLOB_RECURSE TEST_SHASHA_SRC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/shasha/*.cpp")

    file(GLOB_RECURSE TEST_DILITHIUM_SRC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/dilithium/*.cpp")

    file(GLOB_RECURSE TEST_KYBER_SRC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/kyber/*.cpp")

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

    add_executable(qrllib_test ${TEST_QRL_SRC})
    target_link_libraries(qrllib_test gtest gtest_main qrllib util xmss_alt PicoSHA2)

    ###########################

    add_executable(shasha_test ${TEST_SHASHA_SRC})
    target_link_libraries(shasha_test gtest gtest_main shasha util qrllib)

    ###########################

    add_executable(dilithium_test ${TEST_DILITHIUM_SRC})
    target_link_libraries(dilithium_test gtest gtest_main dilithium_ref dilithium)

    ###########################

    add_executable(kyber_test ${TEST_KYBER_SRC})
    target_link_libraries(kyber_test gtest gtest_main kyber_ref kyber)

    if(${CMAKE_VERSION} VERSION_LESS 3.10.0)
        add_test(NAME shasha COMMAND  ${PROJECT_BINARY_DIR}/shasha_test)
        add_test(NAME kyber COMMAND ${PROJECT_BINARY_DIR}/kyber_test)
        add_test(NAME dilithium COMMAND ${PROJECT_BINARY_DIR}/dilithium_test)
        add_test(NAME qrllib COMMAND ${PROJECT_BINARY_DIR}/qrllib_test)
    else()
        include(GoogleTest)
        gtest_discover_tests(shasha_test)
        gtest_discover_tests(kyber_test)
        gtest_discover_tests(dilithium_test)
        gtest_discover_tests(qrllib_test)
    endif()
endif ()

## SWIG + API - Python related stuff
if (BUILD_PYTHON)
    message(STATUS "Python wrapper enabled")

    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif ()

    set(CMAKE_SWIG_OUTDIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pyqrllib)

    set(CMAKE_SWIG_FLAGS -includeall -ignoremissing)

    ###########################################################################
    ## qrllib
    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/pyqrllib.i)
    set(SWIG_MODULE_NAME pyqrllib)

    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES
            CPLUSPLUS ON
            SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/src")

    if(${CMAKE_VERSION} VERSION_LESS 3.12.0)
        # Intentionally use a deprecated version to provide support for the raspberry pi
        # Basic pyqrllib - XmssBasic, etc.
        swig_add_module(${SWIG_MODULE_NAME} python ${SWIG_INTERFACE})
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE}>
                ${PROJECT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE}>)

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different ${swig_extra_generated_files}
                ${PROJECT_SOURCE_DIR}/pyqrllib/pyqrllib.py)
    else()
        swig_add_library(${SWIG_MODULE_NAME}
                LANGUAGE python
                OUTPUT_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                OUTFILE_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                SOURCES ${SWIG_INTERFACE}
                )
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})
    endif()

    set_target_properties(${SWIG_MODULE} PROPERTIES DEBUG_POSTFIX "_d")
    target_link_libraries(${SWIG_MODULE} ${PYTHON_LIBRARIES} qrllib util PicoSHA2)
    target_include_directories(${SWIG_MODULE} PRIVATE ${PYTHON_INCLUDE_DIRS})

    ###########################################################################
    ## dilithium
    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/dilithium.i)
    set(SWIG_MODULE_NAME dilithium)

    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES
        CPLUSPLUS ON
        SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/src/dilithium")

    if(${CMAKE_VERSION} VERSION_LESS 3.12.0)
        swig_add_module(${SWIG_MODULE_NAME} python ${SWIG_INTERFACE})
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE}>
                ${PROJECT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE}>)

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different ${swig_extra_generated_files} ${PROJECT_SOURCE_DIR}/pyqrllib/dilithium.py)
    else()
        swig_add_library(${SWIG_MODULE_NAME}
                LANGUAGE python
                OUTPUT_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                OUTFILE_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                SOURCES ${SWIG_INTERFACE}
                )
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})
    endif()

    set_target_properties(${SWIG_MODULE} PROPERTIES DEBUG_POSTFIX "_d")
    target_link_libraries(${SWIG_MODULE} ${PYTHON_LIBRARIES} dilithium_ref dilithium)
    target_include_directories(${SWIG_MODULE} PRIVATE ${PYTHON_INCLUDE_DIRS})

    ###########################################################################
    ## kyber
    set(SWIG_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/api/kyber.i)
    set(SWIG_MODULE_NAME kyber)

    set_source_files_properties(${SWIG_INTERFACE} PROPERTIES
        CPLUSPLUS ON
        SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/src/kyber")

    if(${CMAKE_VERSION} VERSION_LESS 3.12.0)
        swig_add_module(${SWIG_MODULE_NAME} python ${SWIG_INTERFACE})
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT "Moving SWIG files to output dir"
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different $<TARGET_FILE:${SWIG_MODULE}>
                ${PROJECT_SOURCE_DIR}/pyqrllib/$<TARGET_LINKER_FILE_NAME:${SWIG_MODULE}>)

        add_custom_command(TARGET ${SWIG_MODULE}
                POST_BUILD
                COMMENT ${swig_extra_generated_files}
                COMMAND ${CMAKE_COMMAND} -E
                copy_if_different ${swig_extra_generated_files} ${PROJECT_SOURCE_DIR}/pyqrllib/kyber.py)
    else()
        swig_add_library(${SWIG_MODULE_NAME}
                LANGUAGE python
                OUTPUT_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                OUTFILE_DIR ${PROJECT_SOURCE_DIR}/pyqrllib
                SOURCES ${SWIG_INTERFACE}
                )
        set(SWIG_MODULE ${SWIG_MODULE_${SWIG_MODULE_NAME}_REAL_NAME})
    endif()

    set_target_properties(${SWIG_MODULE} PROPERTIES DEBUG_POSTFIX "_d")
    target_link_libraries(${SWIG_MODULE} ${PYTHON_LIBRARIES} kyber_ref kyber)
    target_include_directories(${SWIG_MODULE} PRIVATE ${PYTHON_INCLUDE_DIRS})
endif ()

if (BUILD_WEBASSEMBLY)
    set(JS_QRL_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jsqrlwrapper.cpp)
    set(JS_DILITHIUM_INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jsdilwrapper.cpp)
    set(JS_KYBINTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/jswrapper/jskybwrapper.cpp)

    message(WARNING "webassembly enabled")

    add_library(jsqrl SHARED
            ${JS_QRL_INTERFACE}
            ${LIB_QRL_SRC}
            ${LIB_SHASHA_SRC}
            ${LIBXMSSALT_SRC}
            ${LIBUTIL_SRC}
            )

    set_target_properties(jsqrl PROPERTIES COMPILE_FLAGS "--emscripten-cxx")
    target_include_directories(jsqrl PRIVATE
      $<TARGET_PROPERTY:qrllib,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:util,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:xmss_alt,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:PicoSHA2,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:dilithium_ref,INTERFACE_INCLUDE_DIRECTORIES>
      )

    set_target_properties(jsqrl
            PROPERTIES LINK_FLAGS "-s DISABLE_EXCEPTION_CATCHING=0"
            )

    target_include_directories(jsdilithium PRIVATE
      $<TARGET_PROPERTY:kyber_ref,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:dilithium,INTERFACE_INCLUDE_DIRECTORIES>
      )

    add_library(jskyber SHARED
            ${JS_KYBER_INTERFACE}
            ${LIB_KYBER_SRC}
            ${LIBKYBER_SRC}
            )
    target_include_directories(jskyber PRIVATE
      $<TARGET_PROPERTY:kyber_ref,INTERFACE_INCLUDE_DIRECTORIES>
      $<TARGET_PROPERTY:kyber,INTERFACE_INCLUDE_DIRECTORIES>
      )

endif ()
