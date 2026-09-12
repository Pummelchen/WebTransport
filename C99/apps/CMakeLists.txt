# The three CLI applications named by the C99 plan. Each is a single main.c for
# now; the phases that implement the protocols fill them in, and until then each
# prints its usage and exits with the status a caller can act on: 2 for a usage
# error, 3 for "built without the feature", which is distinct from success so
# that a script cannot mistake a stub for a working tool.

foreach(app wt-client-c99 wt-server-c99 wt-conformance-c99)
  add_executable(${app} ${app}/main.c)
  wt_set_c99(${app})
  wt_apply_warnings(${app})
  target_link_libraries(${app} PRIVATE ${WT_LINK_TARGET})
  if(WT_SANITIZER_FLAGS)
    target_compile_options(${app} PRIVATE ${WT_SANITIZER_FLAGS})
    target_link_options(${app} PRIVATE ${WT_SANITIZER_FLAGS})
  endif()
endforeach()
