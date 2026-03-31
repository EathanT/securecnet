add_executable(scn_tests
  scn_tests_main.cpp
  test_bytebuf.cpp
  test_message.cpp
  test_address.cpp
  test_packet.cpp
  test_udp.cpp
  test_client_server.cpp
)

target_link_libraries(scn_tests PRIVATE securecnet)

add_test(NAME scn_tests COMMAND scn_tests)

add_executable(net_smoketest
  net_smoketest.cpp
)
target_link_libraries(net_smoketest PRIVATE securecnet)
 

