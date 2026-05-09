set(_securecnet_library_type STATIC)
if(SECURECNET_BUILD_SHARED)
  set(_securecnet_library_type SHARED)
endif()

add_library(securecnet ${_securecnet_library_type}
  lib/socket_init.cpp
  lib/address.cpp
  lib/endpoint.cpp
  lib/bytebuf.cpp
  lib/packet.cpp
  lib/crypto.cpp
  lib/udp_socket.cpp
  lib/client.cpp
  lib/server.cpp
  lib/io_context.cpp
)

add_library(securecnet::securecnet ALIAS securecnet)

set(SECURECNET_LIBSODIUM_ROOT
  "${CMAKE_SOURCE_DIR}/external/libsodium"
  CACHE PATH "Optional root of an extracted libsodium SDK"
)

set(_sodium_include_hints)
set(_sodium_library_hints)
set(_sodium_pkg_include_dirs)
set(_sodium_pkg_library_dirs)
set(_sodium_pkg_libraries)
if(SECURECNET_LIBSODIUM_ROOT)
  list(APPEND _sodium_include_hints
    "${SECURECNET_LIBSODIUM_ROOT}"
    "${SECURECNET_LIBSODIUM_ROOT}/libsodium"
  )
  list(APPEND _sodium_library_hints
    "${SECURECNET_LIBSODIUM_ROOT}"
    "${SECURECNET_LIBSODIUM_ROOT}/libsodium"
  )
endif()

set(_securecnet_header_only_sodium "${CMAKE_SOURCE_DIR}/external/libsodium")
if(EXISTS "${_securecnet_header_only_sodium}/include/sodium.h")
  list(APPEND _sodium_include_hints "${_securecnet_header_only_sodium}")
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_SODIUM QUIET libsodium)
  if(PC_SODIUM_FOUND)
    list(APPEND _sodium_pkg_include_dirs ${PC_SODIUM_INCLUDE_DIRS})
    list(APPEND _sodium_pkg_library_dirs ${PC_SODIUM_LIBRARY_DIRS})
    list(APPEND _sodium_pkg_libraries ${PC_SODIUM_LIBRARIES})
  endif()
endif()

find_path(SODIUM_INCLUDE_DIR
  NAMES sodium.h
  HINTS ${_sodium_include_hints} ${_sodium_pkg_include_dirs}
  PATH_SUFFIXES include
  DOC "Path to libsodium headers"
)

set(_sodium_lib_suffixes)
if(WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_sodium_arch_dirs x64)
  else()
    set(_sodium_arch_dirs Win32 x86)
  endif()

  set(_sodium_toolsets v145 v144 v143 v142 v141)
  foreach(_arch IN LISTS _sodium_arch_dirs)
    foreach(_config Debug Release)
      foreach(_toolset IN LISTS _sodium_toolsets)
        list(APPEND _sodium_lib_suffixes
          "${_arch}/${_config}/${_toolset}/static"
          "${_arch}/${_config}/${_toolset}/dynamic"
        )
      endforeach()
      list(APPEND _sodium_lib_suffixes
        "${_arch}/${_config}/static"
        "${_arch}/${_config}/dynamic"
      )
    endforeach()
    list(APPEND _sodium_lib_suffixes
      "lib/${_arch}"
      "${_arch}"
    )
  endforeach()
else()
  list(APPEND _sodium_lib_suffixes lib lib64)
endif()

find_library(SODIUM_LIBRARY
  NAMES sodium libsodium libsodium.so.23 libsodium.dylib sodium.lib libsodium.lib
  HINTS ${_sodium_library_hints} ${_sodium_pkg_library_dirs}
  PATH_SUFFIXES ${_sodium_lib_suffixes}
  DOC "Path to libsodium library"
)

if(NOT SODIUM_LIBRARY AND _sodium_pkg_libraries)
  foreach(_sodium_pkg_library IN LISTS _sodium_pkg_libraries)
    find_library(SODIUM_LIBRARY
      NAMES ${_sodium_pkg_library}
      HINTS ${_sodium_pkg_library_dirs}
      PATH_SUFFIXES ${_sodium_lib_suffixes}
      DOC "Path to libsodium library"
    )
    if(SODIUM_LIBRARY)
      break()
    endif()
  endforeach()
endif()

if(NOT SODIUM_INCLUDE_DIR)
  find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    DOC "Path to libsodium headers"
  )
endif()

if(NOT SODIUM_LIBRARY)
  find_library(SODIUM_LIBRARY
    NAMES sodium libsodium libsodium.so.23 libsodium.dylib sodium.lib libsodium.lib
    DOC "Path to libsodium library"
  )
endif()

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
  message(FATAL_ERROR
    "libsodium was not found. Set SECURECNET_LIBSODIUM_ROOT to the extracted libsodium folder, "
    "or set SODIUM_INCLUDE_DIR and SODIUM_LIBRARY explicitly.")
endif()

add_library(securecnet_libsodium UNKNOWN IMPORTED)
set_target_properties(securecnet_libsodium PROPERTIES
  IMPORTED_LOCATION "${SODIUM_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
)

set(_securecnet_public_include_dir "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_include_directories(securecnet
  PUBLIC
    "$<BUILD_INTERFACE:${_securecnet_public_include_dir}>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(securecnet PUBLIC securecnet_libsodium)

target_compile_features(securecnet PUBLIC cxx_std_20)
securecnet_enable_target_warnings(securecnet)

if(WIN32)
  target_link_libraries(securecnet PUBLIC ws2_32)
  target_compile_definitions(securecnet PRIVATE NOMINMAX)

  set(_sodium_is_static FALSE)
  if(SODIUM_LIBRARY MATCHES [[(^|[\\/])static([\\/]|$)]])
    set(_sodium_is_static TRUE)
  endif()

  if(_sodium_is_static)
    target_compile_definitions(securecnet PUBLIC SODIUM_STATIC=1)
  endif()
endif()


include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set_target_properties(securecnet PROPERTIES
  EXPORT_NAME securecnet
)

install(TARGETS securecnet
  EXPORT securecnetTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${_securecnet_public_include_dir}/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

set(_securecnet_config_dir ${CMAKE_CURRENT_BINARY_DIR}/cmake)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/securecnetConfig.cmake.in
  ${_securecnet_config_dir}/securecnetConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/securecnet
)

write_basic_package_version_file(
  ${_securecnet_config_dir}/securecnetConfigVersion.cmake
  VERSION 0.3.0
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${_securecnet_config_dir}/securecnetConfig.cmake
  ${_securecnet_config_dir}/securecnetConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/securecnet
)

install(EXPORT securecnetTargets
  NAMESPACE securecnet::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/securecnet
)
