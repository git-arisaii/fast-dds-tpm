# Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified by Paul Wagner, Fraunhofer IOSB, 2024

cmake_minimum_required(VERSION 3.20)

project(PerformanceTestWithTPMExample VERSION 1 LANGUAGES CXX)

# Find requirements
if(NOT fastcdr_FOUND)
    find_package(fastcdr 2 REQUIRED)
endif()

if(NOT foonathan_memory_FOUND)
    find_package(foonathan_memory REQUIRED)
endif()

if(NOT fastrtps_FOUND)
    find_package(fastrtps 2.12 REQUIRED)
endif()

#Check C++11
include(CheckCXXCompilerFlag)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    check_cxx_compiler_flag(-std=c++11 SUPPORTS_CXX11)
    if(NOT SUPPORTS_CXX11)
        message(FATAL_ERROR "Compiler doesn't support C++11")
    endif()
endif()

message(STATUS "Configuring DDSPerformanceTestWithTPMExample example...")
file(GLOB DDS_PERFORMANCE_TEST_WITH_TPM_EXAMPLE_SOURCES_CXX "*.cxx")
file(GLOB DDS_PERFORMANCE_TEST_WITH_TPM_EXAMPLE_SOURCES_CPP "*.cpp")

add_executable(DDSPerformanceTestWithTPMExample ${DDS_PERFORMANCE_TEST_WITH_TPM_EXAMPLE_SOURCES_CXX} ${DDS_PERFORMANCE_TEST_WITH_TPM_EXAMPLE_SOURCES_CPP})
target_compile_definitions(DDSPerformanceTestWithTPMExample PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    $<$<BOOL:${INTERNAL_DEBUG}>:__INTERNALDEBUG> # Internal debug activated.
    )
target_include_directories(DDSPerformanceTestWithTPMExample PRIVATE)
target_link_libraries(DDSPerformanceTestWithTPMExample fastrtps fastcdr foonathan_memory)
install(TARGETS DDSPerformanceTestWithTPMExample
    RUNTIME DESTINATION examples/cpp/dds/PerformanceTestWithTPMExample/${BIN_INSTALL_DIR})
install(DIRECTORY ${PROJECT_SOURCE_DIR}/certs
    DESTINATION examples/cpp/dds/PerformanceTestWithTPMExample/${BIN_INSTALL_DIR})
install(DIRECTORY ${PROJECT_SOURCE_DIR}/results
    DESTINATION examples/cpp/dds/PerformanceTestWithTPMExample/${BIN_INSTALL_DIR})
install(FILES ${PROJECT_SOURCE_DIR}/generate_quoting_key.sh
    PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ WORLD_READ
    DESTINATION examples/cpp/dds/PerformanceTestWithTPMExample/${BIN_INSTALL_DIR})
install(FILES ${PROJECT_SOURCE_DIR}/perform_test.sh
    PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ WORLD_READ
    DESTINATION examples/cpp/dds/PerformanceTestWithTPMExample/${BIN_INSTALL_DIR})

add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${PROJECT_SOURCE_DIR}/certs
            ${PROJECT_BINARY_DIR}/certs)
add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${PROJECT_SOURCE_DIR}/results
            ${PROJECT_BINARY_DIR}/results)
add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${PROJECT_SOURCE_DIR}/generate_quoting_key.sh
            ${PROJECT_BINARY_DIR})
add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND chmod +x ${PROJECT_BINARY_DIR}/generate_quoting_key.sh)
add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${PROJECT_SOURCE_DIR}/perform_test.sh
            ${PROJECT_BINARY_DIR})
add_custom_command(TARGET DDSPerformanceTestWithTPMExample POST_BUILD
    COMMAND chmod +x ${PROJECT_BINARY_DIR}/perform_test.sh)