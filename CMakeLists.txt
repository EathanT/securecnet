# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.10)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()


<<<<<<< HEAD

=======
>>>>>>> origin/main
project(SECURECNET LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
<<<<<<< HEAD
=======

>>>>>>> origin/main
option(SECURECNET_BUILD_DEMO "Build demo" ON)
option(SECURECNET_BUILD_TESTS "Build tests" ON)

add_subdirectory(src/securecnet)
if(SECURECNET_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
endif()
