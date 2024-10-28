cmake_minimum_required(VERSION 3.6)
project(rptree C)

set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Install path prefix")

set(src rptree.c rpshell.c procfs.c cJSON.c libxopt.c)

add_compile_options(-Wall)
add_compile_options(-fstack-protector)
add_compile_options(-Werror)
add_compile_options(-Wfatal-errors)
add_compile_options(-Wno-unused-result)
add_compile_options(-Wsign-compare)

if (NOT DEFINED VERSION)
        set(SCMVERSION "")

        execute_process(
                COMMAND cat .scmversion
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                ERROR_QUIET
                OUTPUT_VARIABLE SCMVERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        execute_process(
                COMMAND git describe --tags
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                ERROR_QUIET
                OUTPUT_VARIABLE GIT_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        execute_process(
                COMMAND git rev-parse --short=20 HEAD
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                ERROR_QUIET
                OUTPUT_VARIABLE GIT_COMMIT
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        if (SCMVERSION)
                set(VERSION "${SCMVERSION}")
                message(STATUS "scmversion: ${VERSION}")
        elseif(GIT_VERSION)
                set(VERSION "${GIT_VERSION}")
                message(STATUS "Auto generated version: ${VERSION}")
        else()
                set(VERSION "${GIT_COMMIT}")
                message(STATUS "Auto generated commit version: ${VERSION}")
        endif()
endif()

add_compile_options(-DRPTREE_VERSION="${VERSION}")

option(DEBUG "Compile in debug mode" OFF)
if (DEBUG)
        add_compile_options(-O0)
        add_compile_options(-g)
else()
        add_compile_options(-O2)
endif()

add_executable(rptree ${src})
install(TARGETS rptree RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Add test functions
enable_testing()

function(add_rptree_shell_test TEST_NAME)
        find_program(BASH_PROGRAM bash)
        if (BASH_PROGRAM)
                add_test(
                        NAME ${TEST_NAME}
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${TEST_NAME}
                        COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.sh ${TEST_NAME}
                )

                set_property(
                        TEST ${TEST_NAME}
                        PROPERTY ENVIRONMENT
                                "CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                )
        endif()
endfunction()

add_rptree_shell_test(smart)
