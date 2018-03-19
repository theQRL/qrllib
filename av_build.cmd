IF DEFINED CLANG (
  set CC=clang-cl.exe
  set CXX=clang-cl.exe
) ELSE (
  set CC=cl.exe
  set CXX=cl.exe
)

IF DEFINED PYTHON (
  %PYTHON%\python .\setup.py test
) ELSE (
  mkdir build
  cd build
  cmake -GNinja -DBUILD_TESTS=ON ..\
  cmake --build . --config Release
  ctest
)
