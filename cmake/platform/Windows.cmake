# Windows: Asio by default, IORing or IOCP. The Windows unit is an interface unit
# of the engine, and the units that include <windows.h> trim it.
set(HTTPANT_IO_BACKENDS asio ioring iocp)
set(HTTPANT_IO_MODULES windows)
set(HTTPANT_IO_LIBRARIES ws2_32 kernel32)
set(HTTPANT_PLATFORM_DEFINITIONS WIN32_LEAN_AND_MEAN NOMINMAX)
