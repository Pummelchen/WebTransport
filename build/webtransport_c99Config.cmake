
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was webtransport_c99Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

# The installed package's own config file.
#
# WHAT HAS TO HAPPEN BEFORE THE TARGETS FILE IS INCLUDED. An exported target
# carries the names of the imported targets it links, and a consumer that has not
# itself called find_package(OpenSSL) has no `OpenSSL::Crypto` for those names to
# resolve to -- so including the targets file first fails with "the target was not
# found" inside a generated file, which names no cause.
#
# Only the static archive needs it. A shared library links OpenSSL privately and
# its consumer links nothing extra, so the dependency is declared only when a
# static library was installed: a consumer of the shared library alone should not
# be made to find a crypto library it will never call.
include(CMakeFindDependencyMacro)
if(ON)
  find_dependency(OpenSSL 3.0)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/webtransport_c99Targets.cmake")
