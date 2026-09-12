# A consumer of the installed package, which is the only way to know that the
# install rules, the exported targets and the config file actually work
# together. A library that builds and installs but cannot be found by
# find_package is a library nobody can use, and nothing else in this project's
# tests would notice.

cmake_minimum_required(VERSION 3.28)
project(webtransport_c99_package_consumer C)

find_package(webtransport_c99 REQUIRED)

add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE WebTransport::static)
