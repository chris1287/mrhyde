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

set(SODIUM_REVISION 1.0.18-RELEASE)

message("-- libsodium: ${SODIUM_REVISION}")

ExternalProject_Add(
  project_libsodium

  GIT_REPOSITORY
    https://github.com/jedisct1/libsodium.git

  GIT_TAG
    ${SODIUM_REVISION}

  PREFIX
    sodium

  SOURCE_DIR
    libsodium/src/libsodium

  BINARY_DIR
    libsodium/src/libsodium

  CONFIGURE_COMMAND
    ./configure --prefix=${CMAKE_BINARY_DIR}/sodium-install/ --disable-shared

  BUILD_COMMAND 
    make -j4

  INSTALL_COMMAND
    make install
)

link_directories(${CMAKE_BINARY_DIR}/sodium-install/lib)

set(GFLAGS_REVISION v2.2.2)

message("-- gflags: ${GFLAGS_REVISION}")

ExternalProject_Add(
  project_gflags

  GIT_REPOSITORY
    https://github.com/gflags/gflags.git

  GIT_TAG
    ${GFLAGS_REVISION}

  PREFIX
    gflags

  SOURCE_DIR
    gflags/src/gflags
  
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/gflags-install
    ${CMAKE_EXTRA_ARGS}
)

link_directories(${CMAKE_BINARY_DIR}/gflags-install/lib)

set(SOURCE_FILES
  src/main.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
add_dependencies(${PROJECT_NAME} project_glog project_libsodium project_gflags)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 11)

target_compile_options(${PROJECT_NAME} PRIVATE -O2 -Wfatal-errors -Wall -Wpedantic)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/glog-install/include)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/sodium-install/include)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/gflags-install/include)

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC pthread glog sodium gflags pthread)

configure_file (src/config.h.in ${CMAKE_BINARY_DIR}/config.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR})
