add_library(securecnet STATIC
  lib/socket_init.cpp
  lib/address.cpp
  lib/endpoint.cpp
  lib/bytebuf.cpp
  lib/packet.cpp
  lib/udp_socket.cpp
  lib/client.cpp
  lib/server.cpp
<<<<<<< HEAD
  "lib/io_context.cpp")
=======
 "include/util/util.h")
>>>>>>> origin/main

target_include_directories(securecnet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
  target_link_libraries(securecnet PUBLIC ws2_32)
  target_compile_definitions(securecnet PRIVATE NOMINMAX)
endif()

<<<<<<< HEAD
target_compile_features(securecnet PUBLIC cxx_std_20)

=======
target_compile_features(securecnet PUBLIC cxx_std_20)
>>>>>>> origin/main
