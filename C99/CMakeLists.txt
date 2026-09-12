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
install(FILES ${WT_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/webtransport)

# A package a consumer can find_package(), which is what "consumed as a normal
# CMake package" in the plan's release phase means. Written now rather than
# later because the install rules and the config file have to agree, and the
# cheap time to make them agree is when the install rules are written.
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
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99Config.cmake"
  "include(\"\${CMAKE_CURRENT_LIST_DIR}/webtransport_c99Targets.cmake\")\n")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99Config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/webtransport_c99ConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/webtransport_c99
)
