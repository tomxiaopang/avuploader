cmake_minimum_required(VERSION 2.8)
project(avyoukuuploader)

find_package(CURL REQUIRED)
find_package(Boost 1.48 REQUIRED COMPONENTS date_time thread locale system program_options filesystem)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(libavyoukuuploader/)

add_library(libavyoukuuploader STATIC libavyoukuuploader/ccurl.cpp libavyoukuuploader/libYoukuUpload.cpp)
target_link_libraries(libavyoukuuploader ${Boost_LIBRARIES} ${CURL_LIBRARIES})
add_executable(avyoukuuploader main.cpp)
target_link_libraries(avyoukuuploader libavyoukuuploader)

install(TARGETS avyoukuuploader RUNTIME DESTINATION bin)
