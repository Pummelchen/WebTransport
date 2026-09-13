# Unit tests, one executable per file, registered with CTest individually so a
# failure names the file that failed. A single test runner that calls every
# suite would report one result for all of them, which is exactly the thing that
# makes a CI log useless.
#
# The tests link the same library the apps do, so a test cannot pass against a
# different build of the code than the one that ships.

set(WT_UNIT_TESTS
  test_status
  test_checked
  test_endian
  test_cursor
  test_writer
  test_buffer
  test_allocator
  test_log
  test_time
  test_version
  test_quic_error
  test_quic_varint
  test_quic_packet_number
  test_quic_frame
  test_quic_packet
  test_quic_transport_parameters
  test_quic_connection_id
  test_quic_retry_token
  test_quic_malformed
  test_quic_pn_space
  test_quic_loss
  test_quic_congestion
  test_quic_stream
  test_quic_datagram
  test_quic_close
  test_quic_packet_io
  test_quic_connection
  test_quic_crypto_stream
  test_quic_handshake
  test_quic_peer_limits
  test_crypto
  test_quic_protection
  test_tls13_keyschedule
  test_tls13_handshake
  test_tls13_keyshare
  test_tls13_trust
  test_tls13_session
  test_tls13_server
  test_runtime_udp
  test_http3_frame
  test_http3_settings
  test_http3_control
  test_http3_goaway
  test_http3_streams
  test_http3_request
  test_http3_headers
  test_http3_message
  test_webtransport_session_request
  test_webtransport_capsule
  test_webtransport_flow
  test_webtransport_session
  test_webtransport_framing
  test_public_api
  test_api_endpoint
  test_cli_endpoint
  test_runtime_session
  test_tls_self_signed
  test_runtime_session_pair
  test_runtime_server_retry
  test_cli_options
  test_cli_report
  test_http3_driver
  test_http3_driver_streams
  test_http3_endpoint
  test_http3_limits
  test_http3_malformed
  test_api_events
  test_api_flow
  test_api_session
  test_qpack_static
  test_qpack_primitives
  test_qpack_huffman
  test_qpack_huffman_encode
  test_qpack_field
  test_qpack_dynamic
  test_qpack_encoder_stream
  test_qpack_decoder_stream
  test_qpack_header_prefix
  test_qpack_field_section
  test_webtransport_protocol
  test_qpack_field_section_codec
  test_qpack_encoder_state
)

foreach(test IN LISTS WT_UNIT_TESTS)
  add_executable(${test} unit/${test}.c)
  wt_set_c99(${test})
  wt_apply_warnings(${test})
  # `vectors` holds the generated RFC vectors, which tests include by plain name
  # so that moving a file does not mean editing every test that reads it.
  target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} unit
    vectors ${CMAKE_CURRENT_SOURCE_DIR}/../tests)
  target_link_libraries(${test} PRIVATE ${WT_LINK_TARGET})
  if(WT_SANITIZER_FLAGS)
    target_compile_options(${test} PRIVATE ${WT_SANITIZER_FLAGS})
    target_link_options(${test} PRIVATE ${WT_SANITIZER_FLAGS})
  endif()
  add_test(NAME ${test} COMMAND ${test})
endforeach()

# Parser fuzzing (WT-175): the plan's "parser fuzzing for QUIC varints, QUIC frames, transport parameters, HTTP/3
# frames, QPACK, capsules, and WebTransport stream prefixes", in one harness (`tests/fuzz/fuzz_parsers.c` picks a
# family by the input's first byte).
#
# TWO TARGETS, and the reason is that libFuzzer ships with clang only:
#
#   - `fuzz_smoke` is the harness plus `fuzz_driver.c`, a deterministic pseudo-random driver, so the fuzz run
#     happens on EVERY toolchain and under the sanitizers this project already builds with. Its corpus of inputs
#     is generated, so it always runs; that is the half a CI leg can depend on.
#   - `fuzz_parsers` is the same harness linked against libFuzzer's driver, built only when the compiler can link
#     one (probed, because a probe with its own `main` fails for a reason that has nothing to do with fuzzing:
#     libFuzzer supplies main). That is the coverage-guided search, run where the toolchain allows it.
#
# Neither is installed: they are test artifacts, like the unit binaries.
add_executable(fuzz_smoke fuzz/fuzz_parsers.c fuzz/fuzz_driver.c)
wt_set_c99(fuzz_smoke)
wt_apply_warnings(fuzz_smoke)
target_include_directories(fuzz_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} unit
  vectors ${CMAKE_CURRENT_SOURCE_DIR}/../tests)
target_link_libraries(fuzz_smoke PRIVATE ${WT_LINK_TARGET})
if(WT_SANITIZER_FLAGS)
  target_compile_options(fuzz_smoke PRIVATE ${WT_SANITIZER_FLAGS})
  target_link_options(fuzz_smoke PRIVATE ${WT_SANITIZER_FLAGS})
endif()
# 200,000 generated inputs: measured at 0.6 s on the development host, which is cheap enough that the smoke run is
# a real search rather than a token one, and small enough to sit in a suite that also builds a library.
add_test(NAME fuzz_parsers_smoke COMMAND fuzz_smoke --runs 200000)
set_tests_properties(fuzz_parsers_smoke PROPERTIES TIMEOUT 300)

# The driver probe: compile AND link a libFuzzer program that has no `main` of its own, which is exactly what the
# target needs. `execute_process` rather than a check module because the flag has to reach the link line, which
# `CMAKE_REQUIRED_FLAGS` does not.
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/fuzz_driver_probe.c
  "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { (void)data; (void)size; return 0; }\n")
execute_process(
  COMMAND ${CMAKE_C_COMPILER} -fsanitize=fuzzer ${CMAKE_CURRENT_BINARY_DIR}/fuzz_driver_probe.c
          -o ${CMAKE_CURRENT_BINARY_DIR}/fuzz_driver_probe
  RESULT_VARIABLE WT_FUZZER_PROBE_RESULT
  OUTPUT_QUIET ERROR_QUIET)
if(WT_FUZZER_PROBE_RESULT EQUAL 0 AND NOT WT_SANITIZER_FLAGS)
  add_executable(fuzz_parsers fuzz/fuzz_parsers.c)
  wt_set_c99(fuzz_parsers)
  wt_apply_warnings(fuzz_parsers)
  target_include_directories(fuzz_parsers PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} unit
    vectors ${CMAKE_CURRENT_SOURCE_DIR}/../tests)
  target_link_libraries(fuzz_parsers PRIVATE ${WT_LINK_TARGET})
  target_compile_options(fuzz_parsers PRIVATE -fsanitize=fuzzer,address -g)
  target_link_options(fuzz_parsers PRIVATE -fsanitize=fuzzer,address)
  add_test(NAME fuzz_parsers_libfuzzer
    COMMAND fuzz_parsers -runs=50000 -max_len=1024 -artifact_prefix=${CMAKE_CURRENT_BINARY_DIR}/)
  set_tests_properties(fuzz_parsers_libfuzzer PROPERTIES TIMEOUT 600)
else()
  message(STATUS "parser fuzzing: the deterministic smoke run only (this compiler cannot link a libFuzzer driver)")
endif()

# One test validates certificate chains, so it needs the path to the fixtures it validates
# against. Passed at configure time rather than guessed from the working directory, which
# differs between ctest and a direct run.
target_compile_definitions(test_tls13_trust PRIVATE
  WT_TRUST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors/trust")
# The server test needs the same fixtures, because the certificate it sends is the one the
# client validates.
target_compile_definitions(test_tls13_server PRIVATE
  WT_TRUST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors/trust")
# And the handshake test runs a whole handshake over sockets, so it needs the same identity to
# serve and the same CA to validate it.
target_compile_definitions(test_quic_handshake PRIVATE
  WT_TRUST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors/trust")
# And the session pair test drives two of those handshakes through the runtime session driver, so it
# needs the same identity and the same CA.
target_compile_definitions(test_runtime_session_pair PRIVATE
  WT_TRUST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors/trust")
