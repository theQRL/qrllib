cmake_minimum_required(VERSION 2.6)
project(testlib)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)


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

file(GLOB_RECURSE LIB_SRC "src/lib/*.cpp" "src/lib/*.hpp")

set(SWIG_INTERFACE src/api/api.i)

set_source_files_properties(${SWIG_INTERFACE} PROPERTIES CPLUSPLUS ON)
set_source_files_properties(${SWIG_INTERFACE} PROPERTIES SWIG_FLAGS "-includeall")

SWIG_ADD_LIBRARY(pyqrl
        LANGUAGE "${language}"
        ${SWIG_LANG_TYPE}
        SOURCES ${SWIG_INTERFACE}
        src/api/api.cxx
        ${LIB_SRC} )

SWIG_LINK_LIBRARIES(pyqrl ${SWIG_LANG_LIBRARIES})

# Get python packages destination
execute_process(COMMAND python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()"
                OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)


# Use CPack to create wheel packages

#install(TARGETS _target DESTINATION ${PYTHON_SITE_PACKAGES})
#install(FILES ${CMAKE_BINARY_DIR}/src/target.py DESTINATION ${PYTHON_SITE_PACKAGES})
