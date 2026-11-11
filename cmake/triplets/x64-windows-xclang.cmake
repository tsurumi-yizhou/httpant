set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_LOAD_VCVARS_ENV ON)
# Dependencies build with the project's xclang for the same target.
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "$ENV{XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DXCLANG_TARGET=x86_64-pc-windows-msvc)
set(VCPKG_ENV_PASSTHROUGH XCLANG_ROOT)
