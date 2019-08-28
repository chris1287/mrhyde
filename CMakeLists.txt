cmake_minimum_required(VERSION 3.10)
project(mrhyde
  VERSION 0.0.1.0
)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

include(ExternalProject)

set(GLOG_REVISION v0.4.0)

message("-- glog: ${GLOG_REVISION}")

ExternalProject_Add(
  project_glog

  GIT_REPOSITORY
    https://github.com/google/glog.git

  GIT_TAG
    ${GLOG_REVISION}

  PREFIX
    glog

  SOURCE_DIR
    glog/src/glog

CMAKE_ARGS
  -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/glog-install
  ${CMAKE_EXTRA_ARGS}
)

link_directories(${CMAKE_BINARY_DIR}/glog-install/lib)

set(SOURCE_FILES
  src/main.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
add_dependencies(${PROJECT_NAME} project_glog)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 11)

target_compile_options(${PROJECT_NAME} PRIVATE -O2 -Wfatal-errors -Wall -Wpedantic)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/glog-install/include)

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC pthread glog)

configure_file (src/config.h.in ${CMAKE_BINARY_DIR}/config.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR})
