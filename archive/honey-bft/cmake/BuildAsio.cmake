# Configure ASIO library
find_package(asio CONFIG QUIET)

if(asio_FOUND)
    message(STATUS "Found asio via pkg-config")
else()
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(ASIO_INCLUDE_DIR)
        message(STATUS "Found Asio headers at: ${ASIO_INCLUDE_DIR}")
        add_library(asio INTERFACE)
        target_include_directories(asio INTERFACE ${ASIO_INCLUDE_DIR})
        add_library(asio::asio ALIAS asio)
    else()
        message(STATUS "Asio not found in system, downloading via CPM...")
        CPMAddPackage(
            NAME asio
            GITHUB_REPOSITORY chriskohlhoff/asio
            GIT_TAG asio-1-30-2
            GIT_SHALLOW TRUE
            OPTIONS "ASIO_INCLUDE_ONLY ON"
        )
    endif()
endif()
