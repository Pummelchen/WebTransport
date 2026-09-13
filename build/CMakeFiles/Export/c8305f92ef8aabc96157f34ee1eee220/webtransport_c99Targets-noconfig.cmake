#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "WebTransport::static" for configuration ""
set_property(TARGET WebTransport::static APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(WebTransport::static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libwebtransport.a"
  )

list(APPEND _cmake_import_check_targets WebTransport::static )
list(APPEND _cmake_import_check_files_for_WebTransport::static "${_IMPORT_PREFIX}/lib/libwebtransport.a" )

# Import target "WebTransport::shared" for configuration ""
set_property(TARGET WebTransport::shared APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(WebTransport::shared PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libwebtransport.0.1.0.dylib"
  IMPORTED_SONAME_NOCONFIG "@rpath/libwebtransport.0.dylib"
  )

list(APPEND _cmake_import_check_targets WebTransport::shared )
list(APPEND _cmake_import_check_files_for_WebTransport::shared "${_IMPORT_PREFIX}/lib/libwebtransport.0.1.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
