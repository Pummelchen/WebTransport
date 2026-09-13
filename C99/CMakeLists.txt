# WebTransport C99 -- a portable implementation of WebTransport over HTTP/3.
#
# Target protocol: draft-ietf-webtrans-http3-16
# Language: ISO C99, no extensions, no C++.
#
# Two library targets are produced from one set of sources: a static archive for
# embedding and a shared library for the CLI tools and for a caller that wants a
# dynamic dependency. They are separate targets rather than one with an option,
# because a caller may reasonably want both, and CMake's `add_library` cannot
# change its mind after the fact without duplicating the source list.

cmake_minimum_required(VERSION 3.28)

project(webtransport_c99
  VERSION 0.1.0
  DESCRIPTION "WebTransport over HTTP/3 in portable C99"
  LANGUAGES C
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(WTCompilerWarnings)

# The option names are the ones the platform scripts under platform/ already
# pass, so those scripts are the documented interface rather than something that
# has to be kept in step by hand. BUILD_SHARED_LIBS is CMake's own variable for
# the same question and is honoured as well.
# The crypto backend. OpenSSL 3.x is the plan's production dependency for the
# portable platforms; a freestanding target would select a different one, which is
# why the choice is an option rather than a hard-coded find_package. REQUIRED
# because a library that silently built without a crypto backend would fail at the
# first handshake instead of at configure time.
set(WEBTRANSPORT_C99_CRYPTO "openssl" CACHE STRING
  "Cryptographic backend: openssl (a freestanding target would add another)")
set_property(CACHE WEBTRANSPORT_C99_CRYPTO PROPERTY STRINGS openssl)
if(NOT WEBTRANSPORT_C99_CRYPTO STREQUAL "openssl")
  message(FATAL_ERROR
    "WEBTRANSPORT_C99_CRYPTO=${WEBTRANSPORT_C99_CRYPTO} is not implemented; "
    "only openssl is")
endif()
find_package(OpenSSL 3.0 REQUIRED)

option(BUILD_SHARED_LIBS "Build the shared library" ON)
option(WEBTRANSPORT_C99_BUILD_STATIC "Build the static library" ON)
option(WEBTRANSPORT_C99_BUILD_APPS "Build the CLI applications" ON)
option(WEBTRANSPORT_C99_BUILD_TESTS "Build the tests" ON)
option(WEBTRANSPORT_C99_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(NOT BUILD_SHARED_LIBS AND NOT WEBTRANSPORT_C99_BUILD_STATIC)
  message(FATAL_ERROR "BUILD_SHARED_LIBS and WEBTRANSPORT_C99_BUILD_STATIC are both off: nothing would be built")
endif()

# Every source file, one list. A library target that forgot a file would fail to
# link, which is a build error rather than a silent gap, but the list is also
# what the install rules and the compile checks use, so it is defined once.
set(WT_CORE_SOURCES
  src/core/status.c
  src/core/checked.c
  src/core/endian.c
  src/core/cursor.c
  src/core/writer.c
  src/core/buffer.c
  src/core/allocator.c
  src/core/log.c
  src/core/time.c
  src/core/version.c
)

# The QUIC wire core. One list with the core rather than a separate target: it
# is the same library, a consumer links it as a unit, and splitting it would let
# a test link a different build of the QUIC code than the library ships.
set(WT_CRYPTO_SOURCES
  src/crypto/crypto_openssl.c
)

set(WT_QUIC_SOURCES
  src/quic/error.c
  src/quic/varint.c
  src/quic/packet_number.c
  src/quic/frame.c
  src/quic/packet.c
  src/quic/transport_parameters.c
  src/quic/connection_id.c
  src/quic/protection.c
)
set(WT_QUIC_RUNTIME_SOURCES
  src/quic/pn_space.c
  src/quic/loss.c
  src/quic/congestion.c
  src/quic/stream.c
  src/quic/datagram.c
  src/quic/close.c
  src/quic/packet_io.c
  src/quic/connection.c
  src/quic/crypto_stream.c
  src/quic/handshake.c
)
# The runtime is the POSIX part of the tree (WT-13): sockets, poll, the monotonic clock. It is the
# same library because a consumer links one thing and a test must not be able to build a different
# socket layer than the library ships.
set(WT_RUNTIME_SOURCES
  src/runtime/udp.c
)

set(WT_TLS_SOURCES
  src/tls/keyschedule.c
  src/tls/extension.c
  src/tls/handshake.c
  src/tls/keyshare.c
  src/tls/trust.c
  src/tls/session.c
)
list(APPEND WT_CORE_SOURCES ${WT_CRYPTO_SOURCES})
list(APPEND WT_CORE_SOURCES ${WT_QUIC_SOURCES})
list(APPEND WT_CORE_SOURCES ${WT_QUIC_RUNTIME_SOURCES})
list(APPEND WT_CORE_SOURCES ${WT_TLS_SOURCES})
list(APPEND WT_CORE_SOURCES ${WT_RUNTIME_SOURCES})

# The HTTP/3 core. One list with the rest rather than a separate target, for the
# same reason the QUIC wire core is: a consumer links the library as a unit, and a
# test must not be able to link a different build of HTTP/3 than the one that
# ships.
set(WT_HTTP3_SOURCES
  src/http3/frame.c
  src/http3/settings.c
  src/http3/control.c
  src/http3/goaway.c
  src/http3/streams.c
  src/http3/request.c
  src/http3/qpack.c
  src/http3/qpack_primitives.c
  src/http3/qpack_huffman.c
  src/http3/qpack_field.c
)
list(APPEND WT_CORE_SOURCES ${WT_HTTP3_SOURCES})

set(WT_PUBLIC_HEADERS
  include/webtransport/status.h
  include/webtransport/checked.h
  include/webtransport/endian.h
  include/webtransport/cursor.h
  include/webtransport/writer.h
  include/webtransport/buffer.h
  include/webtransport/allocator.h
  include/webtransport/log.h
  include/webtransport/time.h
  include/webtransport/version.h
  include/webtransport/quic/error.h
  include/webtransport/quic/varint.h
  include/webtransport/quic/packet_number.h
  include/webtransport/quic/frame.h
  include/webtransport/quic/packet.h
  include/webtransport/quic/transport_parameters.h
  include/webtransport/quic/connection_id.h
  include/webtransport/quic/protection.h
  include/webtransport/quic/pn_space.h
  include/webtransport/quic/loss.h
  include/webtransport/quic/congestion.h
  include/webtransport/quic/stream.h
  include/webtransport/quic/datagram.h
  include/webtransport/quic/close.h
  include/webtransport/quic/packet_io.h
  include/webtransport/quic/connection.h
  include/webtransport/quic/crypto_stream.h
  include/webtransport/quic/handshake.h
  include/webtransport/http3/frame.h
  include/webtransport/http3/settings.h
  include/webtransport/http3/control.h
  include/webtransport/http3/goaway.h
  include/webtransport/http3/role.h
  include/webtransport/http3/streams.h
  include/webtransport/http3/request.h
  include/webtransport/http3/qpack.h
  include/webtransport/crypto/crypto.h
  include/webtransport/tls/keyschedule.h
  include/webtransport/tls/extension.h
  include/webtransport/tls/handshake.h
  include/webtransport/tls/keyshare.h
  include/webtransport/tls/trust.h
  include/webtransport/tls/session.h
  include/webtransport/runtime/udp.h
)

# The sanitizer flags are added to every target when the option is on, including
# the tests and the apps, so that a run either has them everywhere or nowhere.
# -fno-sanitize=function is required: clang's `undefined` includes it, and it
# fires on the vtable type-punning inside the vendored crypto this library will
# link, which is not a defect in this code. The Darwin symbolizer is disabled at
# run time by the test script for the same reason.
set(WT_SANITIZER_FLAGS "")
if(WEBTRANSPORT_C99_SANITIZE)
  if(MSVC)
    message(FATAL_ERROR "WEBTRANSPORT_C99_SANITIZE is not supported with MSVC; use clang or gcc")
  endif()
  set(WT_SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize=function
                         -fno-omit-frame-pointer)
endif()

# One function that configures a library target identically, so the static and
# shared builds cannot drift in their flags.
function(wt_configure_library target)
  target_include_directories(${target}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:include>
  )
  # OpenSSL is linked PRIVATE: no OpenSSL type appears in a public header, so a
  # consumer of this library does not have to find OpenSSL to use it. A static
  # archive is the exception -- its symbols are unresolved until a final link --
  # which is what INTERFACE_LINK_LIBRARIES below handles.
  target_link_libraries(${target} PRIVATE OpenSSL::Crypto)
  wt_set_c99(${target})
  wt_apply_warnings(${target})
  if(WT_SANITIZER_FLAGS)
    target_compile_options(${target} PRIVATE ${WT_SANITIZER_FLAGS})
    target_link_options(${target} PRIVATE ${WT_SANITIZER_FLAGS})
  endif()
  set_target_properties(${target} PROPERTIES
    OUTPUT_NAME webtransport
    POSITION_INDEPENDENT_CODE ON
  )
endfunction()

if(WEBTRANSPORT_C99_BUILD_STATIC)
  add_library(webtransport_static STATIC ${WT_CORE_SOURCES})
  wt_configure_library(webtransport_static)
  # A static archive carries no link information, so a consumer has to be told
  # about OpenSSL even though no public header mentions it.
  target_link_libraries(webtransport_static INTERFACE OpenSSL::Crypto)
  # EXPORT_NAME is what a consumer writes. The target is called
  # webtransport_static because a target literally named `static` is a trap for
  # anything that treats target names as paths, and the alias and the exported
  # name are both WebTransport::static so that the name used inside this tree
  # and the name used outside it are the same one.
  set_target_properties(webtransport_static PROPERTIES EXPORT_NAME static)
  add_library(WebTransport::static ALIAS webtransport_static)
endif()

if(BUILD_SHARED_LIBS)
  add_library(webtransport_shared SHARED ${WT_CORE_SOURCES})
  wt_configure_library(webtransport_shared)
  set_target_properties(webtransport_shared PROPERTIES EXPORT_NAME shared)
  add_library(WebTransport::shared ALIAS webtransport_shared)
  set_target_properties(webtransport_shared PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
  )
endif()

# The target the apps and tests link: the shared library when it exists,
# otherwise the static one. Defined once here so that a test cannot accidentally
# link a different one from an app.
if(BUILD_SHARED_LIBS)
  set(WT_LINK_TARGET webtransport_shared)
else()
  set(WT_LINK_TARGET webtransport_static)
endif()

if(WEBTRANSPORT_C99_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(WEBTRANSPORT_C99_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Both library targets are installed when both are built, so a consumer that
# built this project can link either. The export name is the namespace a
# consumer writes: WebTransport::static and WebTransport::shared.
set(WT_INSTALL_TARGETS "")
if(WEBTRANSPORT_C99_BUILD_STATIC)
  list(APPEND WT_INSTALL_TARGETS webtransport_static)
endif()
if(BUILD_SHARED_LIBS)
  list(APPEND WT_INSTALL_TARGETS webtransport_shared)
endif()

install(TARGETS ${WT_INSTALL_TARGETS}
  EXPORT webtransport_c99Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
# The headers are installed keeping their subdirectory, so that a public header
# includes its siblings by the path it was written with
# ("webtransport/quic/varint.h") and a consumer's include path is one directory.
foreach(header IN LISTS WT_PUBLIC_HEADERS)
  file(RELATIVE_PATH header_relative "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/${header}")
  get_filename_component(header_dir "${header_relative}" DIRECTORY)
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/${header}"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${header_dir}")
endforeach()

# A package a consumer can find_package(), which is what "consumed as a normal
# CMake package" in the plan's release phase means. Written now rather than
# later because the install rules and the config file have to agree, and the
# cheap time to make them agree is when the install rules are written.
#
# The config file is generated from cmake/webtransport_c99Config.cmake.in rather
# than written out here, because it has to declare this project's own dependency
# on OpenSSL before the targets file names it -- see that file. Writing it as a
# string is what let the static archive install a package whose imported target
# referred to an OpenSSL target a consumer had never been told about.
install(EXPORT webtransport_c99Targets
  FILE webtransport_c99Targets.cmake
  NAMESPACE WebTransport::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/webtransport_c99
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99ConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/webtransport_c99Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99Config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/webtransport_c99
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99Config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99ConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/webtransport_c99
)
