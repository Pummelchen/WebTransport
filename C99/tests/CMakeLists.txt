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
