set(SECURECNET_BENCH_TARGETS
  bench_packet_encode_decode
  bench_reliable_loss
  bench_fragmented_transfer
  bench_allocation_profile
  bench_async_io_context
)

add_executable(bench_packet_encode_decode bench_packet_encode_decode.cpp)
add_executable(bench_reliable_loss bench_reliable_loss.cpp)
add_executable(bench_fragmented_transfer bench_fragmented_transfer.cpp)
add_executable(bench_allocation_profile bench_allocation_profile.cpp)
add_executable(bench_async_io_context bench_async_io_context.cpp)

foreach(target IN LISTS SECURECNET_BENCH_TARGETS)
  target_link_libraries(${target} PRIVATE securecnet::securecnet)
  target_compile_features(${target} PRIVATE cxx_std_20)
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  securecnet_enable_target_warnings(${target})
endforeach()
