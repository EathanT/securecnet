add_executable(scn_tests
  scn_tests_main.cpp
  test_bytebuf.cpp
  test_message.cpp
  test_address.cpp
  test_packet.cpp
  test_udp.cpp
  test_protocol.cpp
  test_reliability_ext.cpp
  test_mtu.cpp
  test_abuse.cpp
  test_soak.cpp
  test_nat_stream.cpp
  test_config.cpp
  test_fragmentation.cpp
  test_channels.cpp
  test_client_server.cpp
  test_fragment_transport.cpp
  test_reliability.cpp
  test_security.cpp
  test_resumption.cpp
  test_fuzz.cpp
  test_validation_hardening.cpp
  test_async.cpp
  test_api_ergonomics.cpp
  test_app_helpers.cpp
  test_router_request_reply.cpp
)

target_link_libraries(scn_tests PRIVATE securecnet::securecnet)
securecnet_enable_target_warnings(scn_tests)

add_test(NAME scn_tests COMMAND scn_tests)
