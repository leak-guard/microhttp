cmake_minimum_required(VERSION 3.20)
project(microhttp)
set(CMAKE_CXX_STANDARD 20)

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_SOURCE_DIR}/include)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TEST_NAME ${PROJECT_NAME}_test)
    add_executable(${TEST_NAME} ${CMAKE_SOURCE_DIR}/test/linux_test.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE ${PROJECT_NAME})
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
