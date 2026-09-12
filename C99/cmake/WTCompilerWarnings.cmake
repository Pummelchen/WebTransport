# Compiler selection and the warning set for every target this project builds.
#
# Warnings are errors everywhere, including in the tests: a test that is allowed
# to warn is a test whose warnings nobody reads. The set below is deliberately
# larger than -Wall -Wextra, because two of the plan's hardening requirements --
# "no unchecked integer narrowing" and "no unbounded peer-controlled memory
# growth" -- are only enforced by the compiler if the flags that report them are
# on. -Wconversion is the one that turns every implicit narrowing into a build
# failure, which is why this library's length arithmetic is written with the
# checked helpers rather than with casts.
#
# A compiler that does not know a flag is not an error: the flags are grouped
# and probed, so GCC, Clang and MSVC each get what they understand.

include(CheckCCompilerFlag)

# Applies the project's warning set to the target named by the first argument.
function(wt_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
    target_compile_options(${target} PRIVATE /permissive-)
  else()
    set(_wt_candidates
      -Wall
      -Wextra
      -Werror
      -Wpedantic
      -Wconversion
      -Wsign-conversion
      -Wshadow
      -Wcast-qual
      -Wcast-align
      -Wstrict-prototypes
      -Wmissing-prototypes
      -Wmissing-declarations
      -Wold-style-definition
      -Wredundant-decls
      -Wundef
      -Wwrite-strings
      -Wpointer-arith
      -Wfloat-equal
      -Wswitch-enum
      -Wvla
      -Wformat=2
      -Wnull-dereference
      -Wdouble-promotion
      -Wno-unused-parameter
    )
    foreach(_flag IN LISTS _wt_candidates)
      string(MAKE_C_IDENTIFIER "wt_flag${_flag}" _varname)
      check_c_compiler_flag(${_flag} ${_varname})
      if(${_varname})
        target_compile_options(${target} PRIVATE ${_flag})
      endif()
    endforeach()
  endif()
endfunction()

# C99 with no compiler extensions. `-pedantic` is part of the warning set above,
# so a construct outside ISO C99 fails the build rather than compiling on one
# platform and not the next.
function(wt_set_c99 target)
  set_target_properties(${target} PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
  )
  # clock_gettime and the rest of POSIX are not in ISO C99. Two places call a
  # platform API: the monotonic clock in src/core/time.c and the UDP socket layer
  # in src/runtime/udp.c (WT-13), and both need the feature macro to be visible on
  # Linux. It is set for the whole library rather than per file because it decides
  # which names the libc exposes, and a header that changed meaning depending on
  # which translation unit included it would be a worse hazard than the macro.
  # Deliberately not set on Apple, where the default is already the full set and
  # setting it once removed INADDR_LOOPBACK (WT-14).
  if(UNIX AND NOT APPLE)
    target_compile_definitions(${target} PRIVATE _POSIX_C_SOURCE=200809L)
  endif()
endfunction()
