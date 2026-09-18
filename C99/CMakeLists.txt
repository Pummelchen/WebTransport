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

# The version is single-sourced from the repository-root VERSION file.
#
# This library and the Swift one ship together and MUST carry the same number:
# a caller pairing a Swift client with a C99 server has no other way to know the
# pair is compatible. A library with no code change is recompiled and republished
# at the new number rather than left behind on the old one, so the two never skew.
#
# The same value is declared in exactly two other places -- the WT_VERSION_*
# macros in include/webtransport/version.h and the Swift constant in
# Swift/Sources/WebTransport/WebTransportVersion.swift -- and
# Swift/check-version-sync.sh fails if any of the three disagrees. Configure
# fails rather than defaulting, so a missing or malformed file can never produce
# a library whose version nobody can name.
set(WT_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION")
if(NOT EXISTS "${WT_VERSION_FILE}")
  message(FATAL_ERROR "VERSION file not found at ${WT_VERSION_FILE}")
endif()
file(STRINGS "${WT_VERSION_FILE}" WT_VERSION LIMIT_COUNT 1)
string(STRIP "${WT_VERSION}" WT_VERSION)
if(NOT WT_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR
    "VERSION must be MAJOR.MINOR.PATCH (got '${WT_VERSION}' in ${WT_VERSION_FILE})")
endif()

# The header is a MIRROR of that value, so verify it agrees here as well.
#
# Without this check a C99-only build -- which is what the C99 CI does -- would
# happily produce libwebtransport.1.4.0.dylib from a bumped VERSION while
# wt_version_string() still reported the old number, because the macros in the
# header are what the string is built from. The library's filename and its own
# answer to "what version am I" would disagree, and only the Swift job's
# check-version-sync.sh would notice. Failing at configure makes the C99 build
# self-consistent on its own.
set(WT_VERSION_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/webtransport/version.h")
if(NOT EXISTS "${WT_VERSION_HEADER}")
  message(FATAL_ERROR "version header not found at ${WT_VERSION_HEADER}")
endif()
file(READ "${WT_VERSION_HEADER}" WT_VERSION_HEADER_TEXT)
foreach(WT_PART MAJOR MINOR PATCH)
  if(NOT WT_VERSION_HEADER_TEXT MATCHES
     "#define[ \t]+WT_VERSION_${WT_PART}[ \t]+([0-9]+)")
    message(FATAL_ERROR
      "${WT_VERSION_HEADER} declares no WT_VERSION_${WT_PART}")
  endif()
  set(WT_HEADER_${WT_PART} "${CMAKE_MATCH_1}")
endforeach()
set(WT_HEADER_VERSION
  "${WT_HEADER_MAJOR}.${WT_HEADER_MINOR}.${WT_HEADER_PATCH}")
if(NOT WT_HEADER_VERSION STREQUAL WT_VERSION)
  message(FATAL_ERROR
    "version mismatch: ${WT_VERSION_FILE} says ${WT_VERSION} but "
    "${WT_VERSION_HEADER} declares ${WT_HEADER_VERSION}. The macros mirror "
    "VERSION; run Swift/check-version-sync.sh --write to propagate it.")
endif()

project(webtransport_c99
  VERSION ${WT_VERSION}
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
# first handshake instead of at configure time. OpenSSL is Apache-2.0, so a
# redistributed binary owes its notice: the text is in the repository's
# THIRD_PARTY_NOTICES.md and the install rules below place it in the install tree
# (F-repo-ops-18).
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

# An INSTALLED executable must be able to find the INSTALLED shared library.
#
# The executables link the library as `@rpath/libwebtransport.<major>.dylib` (macOS)
# or `libwebtransport.so.<version>` (ELF), and CMake's default build-tree rpath
# points at this build directory. At `cmake --install` time CMake REMOVES that rpath
# because it names a build path -- and nothing put an install rpath in its place, so
# an installed `wt-client-c99` died with:
#
#   dyld: Library not loaded: @rpath/libwebtransport.1.dylib
#   Reason: no LC_RPATH's found
#
# That is a defect in the install tree, not in the tool: the lib/ directory sits
# beside bin/ in the layout this project installs, so the executable's own directory
# plus ../lib is the answer, spelled `@loader_path` on macOS and `$ORIGIN` on ELF.
#
# Set before the applications are added (apps/CMakeLists.txt) because
# CMAKE_INSTALL_RPATH is read when a target is created. Tests are built and run from
# the build tree and are not installed, so this does not affect them.
if(APPLE)
  set(CMAKE_INSTALL_RPATH "@loader_path/../lib")
else()
  set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
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
  src/quic/frame_names.c
  src/quic/frame_encode.c
  src/quic/packet.c
  src/quic/packet_encode.c
  src/quic/transport_parameters.c
  src/quic/connection_id.c
  src/quic/retry_token.c
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
  src/quic/connection_send.c
  src/quic/connection_receive.c
  src/quic/connection_loss.c
  src/quic/connection_stream.c
  src/quic/connection_retry.c
  src/quic/connection_handshake.c
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
  src/tls/self_signed.c
  src/tls/trust.c
  # The handshake's two halves: the client and the server. They share
  # src/tls/tls_session_internal.h (the one ciphersuite both offer), which is not installed.
  src/tls/session_client.c
  src/tls/session_server.c
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
set(WT_RUNTIME_SOURCES
  src/runtime/session.c
  src/runtime/server_retry.c
)
list(APPEND WT_CORE_SOURCES ${WT_RUNTIME_SOURCES})

set(WT_CLI_SOURCES
  src/cli/endpoint.c
  src/cli/options.c
  src/cli/report.c
)
list(APPEND WT_CORE_SOURCES ${WT_CLI_SOURCES})

set(WT_API_SOURCES
  src/api/endpoint.c
  src/api/events.c
  src/api/flow.c
  src/api/session.c
)
list(APPEND WT_CORE_SOURCES ${WT_API_SOURCES})

set(WT_WEBTRANSPORT_SOURCES
  src/webtransport/session_request.c
  src/webtransport/capsule.c
  src/webtransport/error.c
  src/webtransport/protocol.c
  src/webtransport/session.c
  src/webtransport/framing.c
  src/webtransport/buffered.c
)
list(APPEND WT_CORE_SOURCES ${WT_WEBTRANSPORT_SOURCES})

set(WT_HTTP3_SOURCES
  src/http3/frame.c
  src/http3/settings.c
  src/http3/control.c
  # The driver is four translation units: its tables and accessors, the prefix and frame
  # reassembly, the connection-frame routing, and the outbound half. They share
  # src/http3/driver_internal.h, which is not installed.
  src/http3/driver.c
  src/http3/driver_stream.c
  src/http3/driver_route.c
  src/http3/driver_send.c
  src/http3/endpoint.c
  src/http3/quic_transport.c
  src/http3/goaway.c
  src/http3/streams.c
  src/http3/request.c
  src/http3/headers.c
  src/http3/message.c
  src/http3/qpack.c
  src/http3/qpack_primitives.c
  src/http3/qpack_huffman.c
  src/http3/qpack_field.c
  src/http3/qpack_dynamic.c
  src/http3/qpack_encoder_stream.c
  src/http3/qpack_decoder_stream.c
  src/http3/qpack_header_prefix.c
  src/http3/qpack_field_section.c
  src/http3/qpack_field_section_codec.c
  src/http3/qpack_encoder_state.c
)
list(APPEND WT_CORE_SOURCES ${WT_HTTP3_SOURCES})

set(WT_PUBLIC_HEADERS
  include/webtransport/status.h
  include/webtransport/api/endpoint.h
  include/webtransport/cli/endpoint.h
  include/webtransport/cli/options.h
  include/webtransport/cli/report.h
  include/webtransport/api/events.h
  include/webtransport/api/flow.h
  include/webtransport/api/session.h
  include/webtransport/webtransport.h
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
  include/webtransport/http3/driver.h
  include/webtransport/http3/endpoint.h
  include/webtransport/http3/goaway.h
  include/webtransport/http3/role.h
  include/webtransport/http3/streams.h
  include/webtransport/http3/request.h
  include/webtransport/http3/headers.h
  include/webtransport/http3/message.h
  include/webtransport/webtransport/session_request.h
  include/webtransport/webtransport/capsule.h
  include/webtransport/webtransport/protocol.h
  include/webtransport/webtransport/session.h
  include/webtransport/webtransport/framing.h
  include/webtransport/webtransport/buffered.h
  include/webtransport/http3/qpack.h
  include/webtransport/crypto/crypto.h
  include/webtransport/tls/keyschedule.h
  include/webtransport/tls/extension.h
  include/webtransport/tls/handshake.h
  include/webtransport/tls/keyshare.h
  include/webtransport/tls/self_signed.h
  include/webtransport/tls/trust.h
  include/webtransport/tls/session.h
  include/webtransport/runtime/session.h
  include/webtransport/runtime/udp.h
)

# The sanitizer flags are added to every target when the option is on, including
# the tests and the apps, so that a run either has them everywhere or nowhere.
# The Darwin symbolizer is disabled at run time by the test script for the same
# reason.
set(WT_SANITIZER_FLAGS "")
if(WEBTRANSPORT_C99_SANITIZE)
  if(MSVC)
    message(FATAL_ERROR "WEBTRANSPORT_C99_SANITIZE is not supported with MSVC; use clang or gcc")
  endif()
  set(WT_SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
  # Clang's `undefined` includes the indirect-call check, which fires on the
  # vtable type-punning inside the vendored crypto this library links. That is
  # not a defect in this code, so it is turned off -- but the flag that turns it
  # off is clang-only, and GNU C rejects it outright:
  #
  #   cc: error: unrecognized argument to '-fno-sanitize=' option: 'function'
  #
  # Passing it unconditionally made this configuration unbuildable with gcc,
  # which the MSVC message above has always offered as an option. GNU C has no
  # such check to turn off, so there is nothing to substitute for it there.
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND WT_SANITIZER_FLAGS -fno-sanitize=function)
  endif()
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
  # A SHARED library on Windows carries an IMPORT library beside the DLL, and the MSVC toolchains name it after
  # the DLL: `webtransport.lib`. The static archive is named `webtransport.lib` as well, so the two targets claim
  # one file and the build graph is refused before anything is compiled -- Ninja's "multiple rules generate
  # webtransport.lib", which is what the first MSVC run of the Windows compiler probe reported (WT-260). mingw
  # does not collide, because its import library is `libwebtransport.dll.a`, so this moves the STATIC archive's
  # name only where the collision exists, and leaves the DLL and its import library under the names a Windows
  # consumer expects.
  get_target_property(_wt_library_type ${target} TYPE)
  if(WIN32 AND NOT MINGW AND _wt_library_type STREQUAL "STATIC_LIBRARY")
    set_target_properties(${target} PROPERTIES OUTPUT_NAME webtransport_static)
  endif()
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
  # Nothing in this tree carries an export annotation, and on Windows a DLL exports only what it is told to:
  # mingw passes `--export-all-symbols` by itself, which is why both mingw legs have linked against this
  # library's import library for as long as they have existed, and the MSVC toolchains link against an import
  # library with no symbols at all -- every app and test failed with "undefined symbol: wt_cli_options_parse",
  # and `link.exe` did not even write the import library, so the apps also failed with LNK1104 "cannot open file
  # 'webtransport.lib'" (WT-260). This property makes CMake generate the module-definition file from the objects,
  # which is the portable answer: the same property works for MSVC and clang-cl, and it changes nothing where the
  # linker already exports everything.
  # NOT on mingw: that toolchain exports every symbol by itself (`--export-all-symbols`), and asking CMake for a
  # module definition as well REPLACES the implicit export-all with the generated list, which left internal
  # functions such as `wt_udp_close` and `wt_runtime_session_clear` unexported and broke the link of the
  # conformance tool on both mingw legs (WT-260).
  if(WIN32 AND NOT MINGW)
    set_target_properties(webtransport_shared PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    # The one decoration CMake cannot generate: a DATA symbol's consumer has to know it is importing, so this
    # reaches every target that links the DLL -- tests, apps and a consumer of the installed package -- and the
    # library's own compilation never sees it. See `webtransport/quic/protection.h`.
    target_compile_definitions(webtransport_shared INTERFACE WT_LINKING_SHARED_LIBRARY)
    target_compile_definitions(webtransport_shared PRIVATE WT_BUILDING_SHARED_LIBRARY)
  endif()
endif()

# The target the apps and tests link: the shared library when it exists,
# otherwise the static one. Defined once here so that a test cannot accidentally
# link a different one from an app.
if(BUILD_SHARED_LIBS)
  set(WT_LINK_TARGET webtransport_shared)
else()
  set(WT_LINK_TARGET webtransport_static)
endif()

# enable_testing() runs BEFORE the subdirectories, because a test can be registered from
# the apps directory too (the public API sample) and add_test in a tree where testing has
# not been enabled yet is silently dropped -- CTest then reports a clean run of one fewer
# test, which is the kind of failure that looks like success.
if(WEBTRANSPORT_C99_BUILD_TESTS)
  enable_testing()
endif()

# A Windows loader looks for an imported DLL beside the EXECUTABLE and in PATH, and nowhere else. A test in
# `tests/` or an app in `apps/` therefore cannot find a `libwebtransport.dll` left at the build root: every
# binary fails to LOAD -- status c0000135, whose low byte is the silent `rc=53` the first Wine run reported for
# every test -- and `ctest` on a Windows runner reports a load failure instead of a test result. Staging the DLL
# beside each executable is what makes this build tree RUNNABLE rather than merely linked; before the helper
# existed, `scripts/check-windows-wine.sh` copied it by hand, which is how the defect was found.
#
# The OpenSSL DLLs are not staged here: they belong to the OpenSSL prefix, which is on PATH for a native Windows
# build and staged by the Wine script for a cross one.
#
# Defined before the subdirectories, because a function used by a subdirectory has to exist by the time CMake
# reads that subdirectory -- not merely by the end of this file.
function(wt_stage_windows_runtime target)
  if(WIN32 AND BUILD_SHARED_LIBS)
    # ONE copy per output directory, attached to the shared library -- NOT one POST_BUILD copy per
    # target. With no RUNTIME_OUTPUT_DIRECTORY set, every app lands in <build>/apps and every test in
    # <build>/tests, so the per-target form put 90 copies of the same DLL into two directories, all
    # scheduled in parallel by Ninja. The loser of that race failed the build:
    #
    #   Error copying file (if different) from ".../libwebtransport.dll" to ".../apps": Permission denied
    #
    # which is why the native Windows CI leg could not be enforced (WT-224). A target's POST_BUILD
    # commands run inside that target's own build edge, so attaching them to the one shared library
    # makes every dependent executable wait for the copy and removes the race by construction.
    add_dependencies(${target} webtransport_shared)
    set_property(GLOBAL APPEND PROPERTY WT_WINDOWS_RUNTIME_STAGE_DIRS "${CMAKE_CURRENT_BINARY_DIR}")
  endif()
endfunction()

if(WEBTRANSPORT_C99_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(WEBTRANSPORT_C99_BUILD_TESTS)
  add_subdirectory(tests)
endif()

# The other half of wt_stage_windows_runtime: one copy per directory that holds an executable, added
# after the directories have declared their targets. `copy_if_different` keeps a rebuild a no-op.
get_property(WT_WINDOWS_RUNTIME_STAGE_DIRS GLOBAL PROPERTY WT_WINDOWS_RUNTIME_STAGE_DIRS)
if(WT_WINDOWS_RUNTIME_STAGE_DIRS)
  list(REMOVE_DUPLICATES WT_WINDOWS_RUNTIME_STAGE_DIRS)
  foreach(wt_stage_dir IN LISTS WT_WINDOWS_RUNTIME_STAGE_DIRS)
    add_custom_command(TARGET webtransport_shared POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:webtransport_shared> "${wt_stage_dir}")
  endforeach()
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

# The three TOOLS are products: a release artifact carries programs a user runs, and until this rule existed the
# install tree carried the libraries alone -- the tools were products of the BUILD and not of the PACKAGE, which
# is the difference the Swift suite's `release-products` scenario asks about. Its mirror in this tree is
# `scripts/check-package.sh`, which installs with the tools on and asserts the product list.
#
# What is deliberately NOT installed is the rest of the tree: `wt-api-sample` exists to keep the documented
# public API compiling and is not a tool, and no test binary is a product at all. A package is a claim about
# what a user may run, so the rule names the three targets rather than installing a bin/ directory wholesale.
if(WEBTRANSPORT_C99_BUILD_APPS)
  install(TARGETS wt-client-c99 wt-server-c99 wt-conformance-c99
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# OpenSSL is REQUIRED and Apache-2.0, so every install tree that carries this library carries a
# redistribution of it and owes the licence notice. The text is the repository's own
# THIRD_PARTY_NOTICES.md, installed with the package rather than left in the source checkout, and
# `scripts/check-package.sh` asserts it is present (F-repo-ops-18).
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../THIRD_PARTY_NOTICES.md"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/webtransport_c99)

# Winsock is not in a Windows link's default set, so every target that touches the socket layer asks for it.
# Guarded by `TARGET` because either library may be built alone, and written here rather than beside the targets
# so that it reads as one statement about the platform rather than two about the libraries.
if(WIN32)
  foreach(wt_winsock_target webtransport_static webtransport_shared)
    if(TARGET ${wt_winsock_target})
      target_link_libraries(${wt_winsock_target} PUBLIC ws2_32)
    endif()
  endforeach()
endif()
