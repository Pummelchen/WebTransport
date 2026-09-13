# The three CLI applications named by the C99 plan. Each is a single main.c for
# now; the phases that implement the protocols fill them in, and until then each
# prints its usage and exits with the status a caller can act on: 2 for a usage
# error, 3 for "built without the feature", which is distinct from success so
# that a script cannot mistake a stub for a working tool.

foreach(app wt-client-c99 wt-server-c99 wt-conformance-c99)
  set(WT_APP_EXTRA_SOURCES)
  if(app STREQUAL "wt-conformance-c99")
    # The session scenarios: two endpoints in one process, over loopback. They need the self-signed identity
    # generator and the runtime session driver, so they are the tool's own code rather than a copy of a test.
    set(WT_APP_EXTRA_SOURCES ${app}/scenario_session.c)
  endif()
  add_executable(${app} ${app}/main.c ${WT_APP_EXTRA_SOURCES})
  wt_set_c99(${app})
  wt_apply_warnings(${app})
  target_link_libraries(${app} PRIVATE ${WT_LINK_TARGET})
  if(WT_SANITIZER_FLAGS)
    target_compile_options(${app} PRIVATE ${WT_SANITIZER_FLAGS})
    target_link_options(${app} PRIVATE ${WT_SANITIZER_FLAGS})
  endif()
endforeach()

# The public API sample. It is not one of the three CLI tools the plan names: it has no
# command line and no protocol of its own, and its job is the plan's Phase 8 completion
# criterion -- a program that uses the public API from outside the library, compiled on
# every target, so a public declaration that moves fails HERE rather than in a consumer's
# project. It is registered with CTest so the promise is checked, not just compiled.
add_executable(wt-api-sample wt-api-sample/main.c)
wt_set_c99(wt-api-sample)
wt_apply_warnings(wt-api-sample)
target_link_libraries(wt-api-sample PRIVATE ${WT_LINK_TARGET})
if(WT_SANITIZER_FLAGS)
  target_compile_options(wt-api-sample PRIVATE ${WT_SANITIZER_FLAGS})
  target_link_options(wt-api-sample PRIVATE ${WT_SANITIZER_FLAGS})
endif()
# The project's own switch, not CTest's BUILD_TESTING: this tree does not include CTest,
# so the standard variable is never defined here and a guard on it would drop the test
# silently.
if(WEBTRANSPORT_C99_BUILD_TESTS)
  add_test(NAME wt_api_sample COMMAND wt-api-sample)
  # The conformance tool's own scenarios, including the two print sessions over loopback: registered so that
  # "the tools run local IPv4 and IPv6 packet sessions" is CHECKED rather than demonstrated by hand. The
  # machine-readable report is the contract, so the test asserts the tool's exit status -- 0 only when every
  # scenario passed.
  add_test(NAME wt_conformance_scenarios COMMAND wt-conformance-c99 --scenario all --json)
endif()
