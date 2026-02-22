add_library(honey_crypto_c_merkle OBJECT)

target_compile_features(honey_crypto_c_merkle PUBLIC c_std_99)

target_sources(honey_crypto_c_merkle
    PRIVATE
        isal_memory_arena.c
        isal_memory_arena.h
        isal_message.c
        isal_message.h
        isal_rs_codec.c
        isal_rs_codec.h
        isal_rs_tables.c
        isal_rs_tables.h
        merkle_hash.c
        merkle_hash.h
)

# INTERFACE: propagates lib/ as an include root to consumers (honey_crypto),
# so C++ files can use #include "merkle/xxx.h".
# PRIVATE: makes include/ visible to compile isal_memory_arena.h → isal_fwd.hpp.
target_include_directories(honey_crypto_c_merkle
    INTERFACE
        "${CMAKE_SOURCE_DIR}/lib"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(honey_crypto_c_merkle
    PRIVATE
        ISAL::isal
        OpenSSL::Crypto
)
