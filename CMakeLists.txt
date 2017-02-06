#-DCMAKE_BUILD_TYPE={Debug|Release}
#-DCMAKE_VERBOSE_MAKEFILE=on
#-DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc

cmake_minimum_required(VERSION 2.8)
project (drvperf)

add_executable(drvperf drvperf.c)
set_target_properties(drvperf PROPERTIES COMPILE_FLAGS 
  "-std=c99 -Wall -Wextra -Wcast-align -Wpointer-to-int-cast -Werror -Wno-deprecated-declarations -fno-math-errno"
)
set_target_properties(drvperf PROPERTIES LINK_FLAGS "-rdynamic")
target_link_libraries(drvperf m)

