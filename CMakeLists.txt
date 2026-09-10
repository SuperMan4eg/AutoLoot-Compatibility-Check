cmake_minimum_required(VERSION 3.20)
project(AutoLootCompatibilityCheck LANGUAGES CXX)

add_executable(AutoLootCompatibilityCheck compatibility_check.cpp)
target_compile_features(AutoLootCompatibilityCheck PRIVATE cxx_std_20)
target_compile_definitions(AutoLootCompatibilityCheck PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(AutoLootCompatibilityCheck PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(AutoLootCompatibilityCheck PRIVATE bcrypt)
target_link_options(AutoLootCompatibilityCheck PRIVATE -municode -static-libgcc -static-libstdc++)

