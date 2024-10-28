cmake_minimum_required(VERSION 3.20)
project(microhttp)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(external/static-collections)

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} INTERFACE static_collections)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TEST_NAME ${PROJECT_NAME}_test)
    add_executable(${TEST_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/test/linux_test.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE ${PROJECT_NAME} static_collections)
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
