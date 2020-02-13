cmake_minimum_required(VERSION 3.4.1)           #普通版本的clang

# configure import libs
set(distribution_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../distribution)

add_library(lib_tongfang SHARED IMPORTED)
set_target_properties(lib_tongfang PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/tongfang/lib/${ANDROID_ABI}/libTongfang.so)

add_library( # Sets the name of the library.
             JNIEncrypt

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/JNIEncrypt.c
             src/main/cpp/debugger.h
             src/main/cpp/debugger.c
             src/main/cpp/base64.h
             src/main/cpp/base64.c
             src/main/cpp/transmit.c
             src/main/cpp/log.c
             src/main/cpp/driver.c
             src/main/cpp/gcm128.c
             src/main/cpp/sm3.c
             src/main/cpp/sha1.c
             src/main/cpp/sha256.c
             src/main/cpp/sha384.c
             src/main/cpp/sha512.c
             src/main/cpp/simclist.c
             src/main/cpp/operation.c
             src/main/cpp/tmc_spi.c
             src/main/cpp/tmc_se_card.c
			 src/main/cpp/cryptoki.c
			 src/main/cpp/framework.c
             )

# 搜索指定的预构建库并将路径存储为变量。 因为默认情况下，CMake在搜索路径中包含系统库，
# 所以您只需要指定公共NDK库的名称你想添加。 在完成构建之前，CMake验证库存在。

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# 指定CMake应链接到目标库的库。 您可以链接多个库，例如在此构建脚本中定义的库，预构建的第三方库或系统库。

target_include_directories(JNIEncrypt PRIVATE
                           ${distribution_DIR}/tongfang/include)

target_link_libraries( # Specifies the target library.
                       JNIEncrypt
                       lib_tongfang
                       # included in the NDK.
                       ${log-lib} )
