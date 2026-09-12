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
)

foreach(test IN LISTS WT_UNIT_TESTS)
  add_executable(${test} unit/${test}.c)
  wt_set_c99(${test})
  wt_apply_warnings(${test})
  target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} unit
    ${CMAKE_CURRENT_SOURCE_DIR}/../tests)
  target_link_libraries(${test} PRIVATE ${WT_LINK_TARGET})
  if(WT_SANITIZER_FLAGS)
    target_compile_options(${test} PRIVATE ${WT_SANITIZER_FLAGS})
    target_link_options(${test} PRIVATE ${WT_SANITIZER_FLAGS})
  endif()
  add_test(NAME ${test} COMMAND ${test})
endforeach()
