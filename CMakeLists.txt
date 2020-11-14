cmake_minimum_required(VERSION 3.5)

project(crypto-tester LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

find_package(PkgConfig)

pkg_check_modules (LIBSODIUM libsodium)
if (NOT LIBSODIUM_FOUND)
	message(FATAL_ERROR "libsodium not found")
else()
	message(STATUS "LIBSODIUM FOUND -> ${LIBSODIUM_FOUND}")
	message(STATUS "LIBSODIUM LIBRARIES ${LIBSODIUM_LIBRARIES}")
	message(STATUS "LIBSODIUM LINK_LIBRARIES ${LIBSODIUM_LINK_LIBRARIES}")
	message(STATUS "LIBSODIUM LIBRARY_DIRS ${LIBSODIUM_LIBRARY_DIRS}")
	message(STATUS "LIBSODIUM INCLUDE_DIRS ${LIBSODIUM_INCLUDE_DIRS}")
endif()

add_executable(crypto-tester main.cpp)
target_link_libraries(crypto-tester pthread ${LIBSODIUM_LINK_LIBRARIES})

add_executable(get-hashes get-hashes.cpp)
target_link_libraries(get-hashes ${LIBSODIUM_LINK_LIBRARIES})
