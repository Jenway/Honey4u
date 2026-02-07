if(WIN32)
    add_library(ISAL::isal INTERFACE IMPORTED GLOBAL)

    target_include_directories(ISAL::isal INTERFACE
        "${CMAKE_SOURCE_DIR}/.pixi/envs/default/Library/include"
    )

    target_link_libraries(ISAL::isal INTERFACE
        isa-l
    )

    target_link_directories(ISAL::isal INTERFACE
        "${CMAKE_SOURCE_DIR}/.pixi/envs/default/Library/lib"
    )

    message(STATUS "Using ISA-L from pixi environment (Windows)")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ISAL REQUIRED libisal)

    add_library(ISAL::isal INTERFACE IMPORTED GLOBAL)
    target_include_directories(ISAL::isal INTERFACE ${PC_ISAL_INCLUDE_DIRS})
    target_link_libraries(ISAL::isal INTERFACE ${PC_ISAL_LINK_LIBRARIES})
    target_link_directories(ISAL::isal INTERFACE ${PC_ISAL_LIBRARY_DIRS})
endif()
