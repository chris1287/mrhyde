cmake_minimum_required(VERSION 3.10)

project(mrhyde
  VERSION 0.0.1.0
)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(SOURCE_FILES
  src/main.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)

target_compile_options(${PROJECT_NAME} PRIVATE -O2 -Wfatal-errors -Wall -Wpedantic)

target_link_libraries(${PROJECT_NAME} ${CONAN_LIBS})

configure_file (src/config.h.in ${CMAKE_BINARY_DIR}/config.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR})
