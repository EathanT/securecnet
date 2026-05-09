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

if(WIN32)
  add_executable(securecnet_win32_shooter WIN32
    win32_shooter_demo.cpp
  )

  target_link_libraries(securecnet_win32_shooter PRIVATE
    securecnet::securecnet
    user32
    gdi32
    shell32
  )

  target_compile_features(securecnet_win32_shooter PRIVATE cxx_std_20)
  target_compile_definitions(securecnet_win32_shooter PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  securecnet_enable_target_warnings(securecnet_win32_shooter)

  if(MSVC)
    set_target_properties(securecnet_win32_shooter PROPERTIES
      VS_DEBUGGER_COMMAND_ARGUMENTS "--host 27015"
    )
  endif()
endif()
