cmake_minimum_required(VERSION 2.8)
project(testlib)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE OFF)

find_package(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})
unset(SWIG_LANG_TYPE)

# Python related stuff
set(language python)
find_package(PythonLibs REQUIRED)
include_directories(${PYTHON_INCLUDE_PATH})
set(SWIG_LANG_LIBRARIES ${PYTHON_LIBRARIES})
#############

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
)

set(SWIG_INTERFACE src/api/api.i)
file(GLOB_RECURSE LIB_SRC "src/lib/*.cpp" "src/lib/*.hpp")
file(GLOB_RECURSE LIBTEST_SRC "src/tests/*.cpp")


##############################
# Google Test
# Based on instructions in https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

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
endif()


# LIBRARY RELATED
find_package(OpenSSL REQUIRED)

# Test library
add_executable(testlib ${LIBTEST_SRC} ${LIB_SRC})
target_link_libraries(testlib gtest_main)
#add_test(NAME example_test COMMAND example)

# SWIG + API
set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
set_source_files_properties(${SWIG_INTERFACE} PROPERTIES SWIG_FLAGS "-includeall")
SWIG_ADD_LIBRARY(pyqrl
        LANGUAGE "${language}"
        ${SWIG_LANG_TYPE}
        SOURCES ${SWIG_INTERFACE}
        src/api/api.cxx
        ${LIB_SRC} )
SWIG_LINK_LIBRARIES(pyqrl ${SWIG_LANG_LIBRARIES} ${OPENSSL_LIBRARIES})


# DEPLOYMENT
# Get python packages destination
#execute_process(COMMAND python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()"
#                OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)


# Use CPack to create wheel packages

#install(TARGETS _target DESTINATION ${PYTHON_SITE_PACKAGES})
#install(FILES ${CMAKE_BINARY_DIR}/src/target.py DESTINATION ${PYTHON_SITE_PACKAGES})
