add_executable(net_smoketest
  net_smoketest.cpp
)

target_link_libraries(net_smoketest PRIVATE securecnet::securecnet)

target_compile_features(net_smoketest PRIVATE cxx_std_20)
securecnet_enable_target_warnings(net_smoketest)

if(MSVC)
  set_target_properties(net_smoketest PROPERTIES
    VS_DEBUGGER_COMMAND_ARGUMENTS "--server 27015"
  )
endif()
