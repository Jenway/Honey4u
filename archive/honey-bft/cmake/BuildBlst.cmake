find_package(PkgConfig REQUIRED)
pkg_check_modules(PC_BLST REQUIRED libblst)

if(NOT TARGET blst::blst)
    add_library(blst::blst INTERFACE IMPORTED GLOBAL)
    set_target_properties(blst::blst PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${PC_BLST_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES "${PC_BLST_LINK_LIBRARIES}"
        INTERFACE_LINK_DIRECTORIES "${PC_BLST_LIBRARY_DIRS}"
    )

    message(STATUS "Found BLST: version \"${PC_BLST_VERSION}\"")
    message(STATUS "  BLST include directories: ${PC_BLST_INCLUDE_DIRS}")
    message(STATUS "  BLST library directories: ${PC_BLST_LIBRARY_DIRS}")
    message(STATUS "  BLST link libraries: ${PC_BLST_LINK_LIBRARIES}")
endif()
