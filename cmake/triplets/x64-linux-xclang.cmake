set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
# Dependencies build with the project's xclang for the same target.
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "$ENV{XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
# The system name makes every build a cross build, where CMake leaves the
# processor unset; port builds read it.
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DXCLANG_TARGET=x86_64-unknown-linux-gnu -DCMAKE_SYSTEM_PROCESSOR=x86_64)
set(VCPKG_ENV_PASSTHROUGH XCLANG_ROOT)
