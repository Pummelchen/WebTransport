# The three CLI applications named by the C99 plan. Each is a single main.c for
# now; the phases that implement the protocols fill them in, and until then each
# prints its usage and exits with the status a caller can act on: 2 for a usage
# error, 3 for "built without the feature", which is distinct from success so
# that a script cannot mistake a stub for a working tool.

foreach(app wt-client-c99 wt-server-c99 wt-conformance-c99)
  set(WT_APP_EXTRA_SOURCES)
  set(WT_APP_NEEDS_SUPPORT FALSE)
  if(app STREQUAL "wt-client-c99" OR app STREQUAL "wt-server-c99")
    # The one-sided loops both tools use: one side of a real socket pair, where the conformance tool drives both.
    # The support is three translation units -- the shared machinery, the client loop and the server loop --
    # sharing apps/support/session_loop_internal.h, which is not installed.
    set(WT_APP_EXTRA_SOURCES ${app}/../support/session_loop.c ${app}/../support/session_loop_client.c
                              ${app}/../support/session_loop_server.c ${app}/../support/capsule_stream.c)
    set(WT_APP_NEEDS_SUPPORT TRUE)
  endif()
  if(app STREQUAL "wt-conformance-c99")
    # The session scenarios: two endpoints in one process, over loopback. They need the self-signed identity
    # generator and the runtime session driver, so they are the tool's own code rather than a copy of a test.
    set(WT_APP_EXTRA_SOURCES ${app}/scenario_pair.c ${app}/scenario_session.c ${app}/scenario_refusals.c ${app}/scenario_refusal_wire.c
                              ${app}/scenario_capsules.c ${app}/../support/capsule_stream.c
                              ${app}/scenario_control.c ${app}/scenario_headers.c
                              ${app}/scenario_isolation.c ${app}/scenario_matrix.c
                              ${app}/scenario_datagram.c ${app}/scenario_flow.c
                              ${app}/scenario_protocol.c ${app}/scenario_connection_ids.c
                              ${app}/hostile_peer.c)
    # The support headers, because the capsule stream is shared with the CLI tools rather than copied here.
    set(WT_APP_NEEDS_SUPPORT TRUE)
  endif()
  add_executable(${app} ${app}/main.c ${WT_APP_EXTRA_SOURCES})
  if(WT_APP_NEEDS_SUPPORT)
    # AFTER add_executable: a target_* call before the target exists fails configure, which is how this line
    # first went in -- and a failed configure leaves the previous binaries in place, so the tools kept their old
    # behaviour and the build looked clean.
    target_include_directories(${app} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  endif()
  wt_set_c99(${app})
  wt_apply_warnings(${app})
  target_link_libraries(${app} PRIVATE ${WT_LINK_TARGET})
  # The tools are spawned by the CLI process tests, so they need the shared library beside them on Windows.
  wt_stage_windows_runtime(${app})
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
wt_stage_windows_runtime(wt-api-sample)
if(WT_SANITIZER_FLAGS)
  target_compile_options(wt-api-sample PRIVATE ${WT_SANITIZER_FLAGS})
  target_link_options(wt-api-sample PRIVATE ${WT_SANITIZER_FLAGS})
endif()
# The project's own switch, not CTest's BUILD_TESTING: this tree does not include CTest,
# so the standard variable is never defined here and a guard on it would drop the test
# silently.
if(WEBTRANSPORT_C99_BUILD_TESTS)
  # The CLI scenarios below are POSIX SHELL SCRIPTS. A test whose COMMAND names a `.sh` file works where the
  # kernel honours its shebang and nowhere else: on Windows CTest reports `BAD_COMMAND` for every one of them,
  # which is what the first native-Windows run did for all ten. Naming the interpreter explicitly makes the same
  # test run on both platforms, and `find_program(... REQUIRED)` says so at CONFIGURE time on a machine without
  # one instead of at test time with no explanation. It is inside this branch because a shell is only needed when
  # these tests are built.
  find_program(WT_CLI_SHELL NAMES sh bash REQUIRED)
  set(WT_CLI_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../scripts)

  add_test(NAME wt_api_sample COMMAND wt-api-sample)
  # The conformance tool's own scenarios, including the two print sessions over loopback: registered so that
  # "the tools run local IPv4 and IPv6 packet sessions" is CHECKED rather than demonstrated by hand. The
  # machine-readable report is the contract, so the test asserts the tool's exit status -- 0 only when every
  # scenario passed.
  add_test(NAME wt_conformance_scenarios COMMAND wt-conformance-c99 --scenario all --json)
  # Exit 3 is the report's own statement that something was not attempted (WT-137's measured spec gap, or IPv6 on
  # a machine without it), and a FAILED scenario is exit 1. CTest's skip code makes that distinction visible
  # instead of turning "not attempted" into either a pass or a failure.
  set_tests_properties(wt_conformance_scenarios PROPERTIES SKIP_RETURN_CODE 3)
  # The two TOOLS against each other, in two processes: the client tool and the server tool run real sessions
  # over a real socket, which is what the plan's CLI criteria ask for and what one process cannot prove.
  # Both exchange modes, because they are different code paths in both tools.
  add_test(NAME wt_cli_session_stream
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-session.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45417 stream)
  add_test(NAME wt_cli_session_datagram
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-session.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45419 datagram)
  # A client that sends BEFORE its CONNECT (WT-189): the only order that reaches the SERVER's section 4.6 parking
  # path from the tools, since every other script drives a well-ordered client whose CONNECT arrives first. Both
  # exchange modes, because a stream and a datagram are parked by the same object through different paths.
  add_test(NAME wt_cli_early_stream
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-early-stream.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45431 stream)
  add_test(NAME wt_cli_early_stream_datagram
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-early-stream.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45433 datagram)
  # The same exchange with the SERVER validating the client's address first (WT-168): the client has to accept the
  # Retry, adopt the connection ID it named, echo the token, and start a session on it. Every one of those is a
  # step the no-Retry path does not take, so this is the case that keeps the flow working.
  add_test(NAME wt_cli_session_retry
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-session.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45423 stream "127.0.0.1" "" retry)
  # `--trust` decides how the peer is validated, and it used to decide nothing: the client took the loopback
  # development bypass whatever the option said, while its report still claimed `"trust":"system"` (WT-193). This
  # is the case that cannot pass unless the option is honoured, because the two modes must DISAGREE about a
  # self-signed leaf -- the bypass accepts it and the platform store refuses it.
  add_test(NAME wt_cli_trust
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-trust.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45441 45443)
  # The process CONTRACT: exit statuses, refused command lines and the JSON report, checked without a peer.
  # And the same session over IPv6, where the machine has it: 77 is CTest's SKIP_RETURN_CODE, which the script
  # returns when the conformance tool reports that this machine has no IPv6 loopback -- a fact about the machine
  # rather than a failure of the tools.
  add_test(NAME wt_cli_session_ipv6
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-session.sh
            $<TARGET_FILE:wt-server-c99> $<TARGET_FILE:wt-client-c99> 45421 stream "[::1]"
            $<TARGET_FILE:wt-conformance-c99>)
  set_tests_properties(wt_cli_session_ipv6 PROPERTIES SKIP_RETURN_CODE 77)

  # A peer that BREAKS A RULE, against the client tool (WT-147): the refusal path of a shipped tool, asserted on
  # both sides of a real socket -- the client's report says what it sent, and the peer's says what it received.
  add_test(NAME wt_cli_hostile_peer
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-hostile.sh
            $<TARGET_FILE:wt-conformance-c99> $<TARGET_FILE:wt-client-c99> 45427 max-streams-decrease)
  # The second act: a WebTransport DATAGRAM whose quarter stream ID names a session this endpoint does not have.
  # The client must refuse it with HTTP/3's ID_ERROR and must NOT count it as a received message (WT-179).
  add_test(NAME wt_cli_hostile_datagram
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-hostile.sh
            $<TARGET_FILE:wt-conformance-c99> $<TARGET_FILE:wt-client-c99> 45428 datagram-for-another-session)

  # 77 is CTest's SKIP_RETURN_CODE, set for every script here that parses the tools' JSON with `python3`: a machine
  # without that interpreter skips the check with its reason rather than reporting a broken protocol, which is what
  # a FreeBSD (no python3 in base) or MSYS2 run did before WT-201. A skip is visible in the CTest summary; an exit
  # 0 would have been counted as a pass.
  set_tests_properties(wt_cli_session_stream wt_cli_session_datagram wt_cli_session_retry wt_cli_trust
                       wt_cli_early_stream wt_cli_early_stream_datagram
                       wt_cli_hostile_peer wt_cli_hostile_datagram
                       PROPERTIES SKIP_RETURN_CODE 77)

  add_test(NAME wt_cli_contract
    COMMAND ${WT_CLI_SHELL} ${WT_CLI_TEST_DIR}/check-cli-contract.sh
            $<TARGET_FILE:wt-client-c99> $<TARGET_FILE:wt-server-c99>
            $<TARGET_FILE:wt-conformance-c99>)
endif()
