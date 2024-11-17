cmake_minimum_required(VERSION 3.22)
project(30_socket C)

set(CMAKE_C_STANDARD 11)

add_executable(
        server.c
        client.c
        server.c)
