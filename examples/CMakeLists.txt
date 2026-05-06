set(SECURECNET_EXAMPLE_TARGETS
  secure_echo_example
  secure_chat_example
  state_sync_example
  large_message_example
  async_echo_example
)

add_executable(secure_echo_example secure_echo_example.cpp)
add_executable(secure_chat_example secure_chat_example.cpp)
add_executable(state_sync_example state_sync_example.cpp)
add_executable(large_message_example large_message_example.cpp)
add_executable(async_echo_example async_echo_example.cpp)

foreach(target IN LISTS SECURECNET_EXAMPLE_TARGETS)
  target_link_libraries(${target} PRIVATE securecnet::securecnet)
  target_compile_features(${target} PRIVATE cxx_std_20)
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  securecnet_enable_target_warnings(${target})
endforeach()
