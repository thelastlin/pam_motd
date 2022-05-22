cmake_minimum_required(VERSION 3.20)
project(bsd_pam_motd C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
if (NOT PAM_INSTALL_PREFIX)
    set(PAM_INSTALL_PREFIX "/usr/local")
endif ()
set(PAM_INSTALL_LIBDIR "${PAM_INSTALL_PREFIX}/lib")
set(PAM_SHARE_DIR "${PAM_INSTALL_PREFIX}/share/man")

find_package(PAM REQUIRED)
find_program(DOCBOOK_TO_MAN NAMES docbook2x-man db2x_docbook2man docbook2man docbook-to-man)
include_directories(. ./include)

#check UNUSED
include(CheckCSourceCompiles)
check_c_source_compiles("
   int main(void)
   {
     int __attribute__((unused)) foo;
     return 0;
   };
" HAVE_ATTRIBUTE_UNUSED)

#check pwn
include(CheckSymbolExists)
check_symbol_exists(getpwnam_r "pwd.h" HAVE_GETPWNAM_R)

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(library_name "pam_motd")
set(pam_motd_SRCS pam_motd.c)
LIST(APPEND pam_motd_SRCS
        pam_openpam.c
        pam_modutil/priv.c
        pam_modutil/getpwnam.c
        pam_modutil/ioloop.c
        pam_modutil/cleanup.c
        )

add_library(${library_name} MODULE ${pam_motd_SRCS})
set_target_properties(${library_name} PROPERTIES PREFIX "")
target_link_libraries(${library_name}
        ${PAM_LIBRARIES}
        )
install(TARGETS ${library_name} DESTINATION ${PAM_INSTALL_LIBDIR}/security)
if (DOCBOOK_TO_MAN)
    add_custom_target(pam_motd.8
            ALL
            COMMAND
            ${DOCBOOK_TO_MAN} "${PROJECT_SOURCE_DIR}/pam_motd.8.xml"
            )
    install(FILES ${CMAKE_BINARY_DIR}/pam_motd.8 DESTINATION ${PAM_SHARE_DIR}/man8/)
    install(FILES man/update-motd.5 DESTINATION ${PAM_SHARE_DIR}/man5/)
endif ()

# support for make uninstall
if(NOT TARGET uninstall)
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)

    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()