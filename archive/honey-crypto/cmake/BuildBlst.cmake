function(add_blst_library BLST_RELATIVE_PATH)

    get_filename_component(BLST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/${BLST_RELATIVE_PATH}" ABSOLUTE)
    
    set(BLST_LIB_FILE "${BLST_ROOT}/libblst.a")
    set(BLST_INC_DIR  "${BLST_ROOT}/bindings")

    if(NOT EXISTS "${BLST_ROOT}/build.sh")
        message(FATAL_ERROR "Could not find build.sh in ${BLST_ROOT}. Please check the submodule path.")
    endif()

    add_custom_command(
        OUTPUT ${BLST_LIB_FILE}
        COMMAND ./build.sh
        WORKING_DIRECTORY ${BLST_ROOT}
        COMMENT "Building BLST library via build.sh..."
        VERBATIM
    )

    add_custom_target(blst_build_driver DEPENDS ${BLST_LIB_FILE})

    add_library(blst::blst STATIC IMPORTED GLOBAL)

    set_target_properties(blst::blst PROPERTIES
        IMPORTED_LOCATION "${BLST_LIB_FILE}"
        INTERFACE_INCLUDE_DIRECTORIES "${BLST_INC_DIR}"
    )

    add_dependencies(blst::blst blst_build_driver)

    message(STATUS "Configured BLST target at: ${BLST_ROOT}")

endfunction()