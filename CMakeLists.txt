cmake_minimum_required(VERSION 3.20)
project(bsd_pam_motd C)

# options
option(PAM_MOTD_REGEN_MAN "Regenerate manuals of PAM_MOTD.8" OFF)
option(PAM_MOTD_INSTALL_MAN "Install manual" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
if (NOT PAM_INSTALL_PREFIX)
    set(PAM_INSTALL_PREFIX "/usr/local")
endif ()
set(PAM_INSTALL_LIBDIR "${PAM_INSTALL_PREFIX}/lib")
set(PAM_SHARE_DIR "${PAM_INSTALL_PREFIX}/share/man")

find_package(PAM REQUIRED)

if (PAM_MOTD_INSTALL_MAN AND PAM_MOTD_REGEN_MAN)
   find_program(MAN_GEN NAMES xsltproc)
   if (NOT MAN_GEN)
       message(WARNING "It seems that you don't have install xsltproc and other stuff. PAM_MOTD_REGEN_MAN will be turned off.")
       set(PAM_MOTD_REGEN_MAN OFF)
   endif()
endif()

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
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
check_symbol_exists(memset_explicit "string.h" HAVE_MEMSET_EXPLICIT)

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
set(pam_motd_MAN_SRCS pam_motd.8)
set(pam_motd_MAN update-motd.5)

add_library(${library_name} MODULE ${pam_motd_SRCS})
set_target_properties(${library_name} PROPERTIES PREFIX "")
target_link_libraries(${library_name}
        ${PAM_LIBRARIES}
        )
install(TARGETS ${library_name} DESTINATION ${PAM_INSTALL_LIBDIR}/security)

if (PAM_MOTD_INSTALL_MAN)
    if (PAM_MOTD_REGEN_MAN)
        foreach(build_man_file IN LISTS pam_motd_MAN_SRCS)
             add_custom_target(${build_man_file}
                ALL
                COMMAND
                xsltproc -o ${CMAKE_BINARY_DIR}/${build_man_file} --path . --xinclude --stringparam profile.condition 'without_vendordir' --nonet ${PROJECT_SOURCE_DIR}/man/custom-man.xsl ${PROJECT_SOURCE_DIR}/man/${build_man_file}.xml
                )
        endforeach()
    else()
        configure_file(man/pam_motd.8 ${CMAKE_BINARY_DIR}/pam_motd.8 COPYONLY)
    endif ()
        install(FILES ${CMAKE_BINARY_DIR}/pam_motd.8 DESTINATION ${PAM_SHARE_DIR}/man8/)
        install(FILES man/update-motd.5 DESTINATION ${PAM_SHARE_DIR}/man5/)
endif ()

# support for make uninstall
if(NOT TARGET uninstall)
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)

    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake)
endif()