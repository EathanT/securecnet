cmake_minimum_required(VERSION 3.21)

project(SECURECNET LANGUAGES CXX)

# MSVC debug info / hot reload handling
if(POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
    "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,\
$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,\
$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SECURECNET_BUILD_DEMO "Build demo targets" ON)
option(SECURECNET_BUILD_TESTS "Build tests" ON)
option(SECURECNET_BUILD_EXAMPLES "Build example targets" ON)
option(SECURECNET_BUILD_BENCHMARKS "Build benchmark targets" ON)
option(SECURECNET_BUILD_DOC_SNIPPETS "Build documentation snippet targets" ON)
option(SECURECNET_WARNINGS_AS_ERRORS "Treat warnings as errors for securecnet targets" ON)
option(SECURECNET_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan on supported toolchains" OFF)
option(SECURECNET_BUILD_SHARED "Build securecnet as a shared library" OFF)

function(securecnet_enable_target_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
    if(SECURECNET_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(SECURECNET_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

if(SECURECNET_ENABLE_SANITIZERS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
  else()
    message(WARNING "SECURECNET_ENABLE_SANITIZERS is ON, but the current compiler does not support the configured sanitizer flags.")
  endif()
endif()

add_subdirectory(src/securecnet)

if(SECURECNET_BUILD_DEMO AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/demo/CMakeLists.txt")
  add_subdirectory(src/demo)
endif()

if(SECURECNET_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()

if(SECURECNET_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
  add_subdirectory(examples)
endif()

if(SECURECNET_BUILD_BENCHMARKS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bench/CMakeLists.txt")
  add_subdirectory(bench)
endif()

if(SECURECNET_BUILD_DOC_SNIPPETS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docs/snippets/CMakeLists.txt")
  add_subdirectory(docs/snippets)
endif()
