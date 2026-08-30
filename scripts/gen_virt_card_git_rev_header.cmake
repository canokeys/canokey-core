if(NOT DEFINED SOURCE_DIR OR NOT DEFINED OUTPUT_FILE)
    message(FATAL_ERROR "SOURCE_DIR and OUTPUT_FILE are required")
endif()

execute_process(
    COMMAND git describe --always --tags --long --abbrev=8 --dirty --match [0-9]*
    WORKING_DIRECTORY "${SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_REV
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT
)

if(NOT GIT_RESULT EQUAL 0 OR GIT_REV STREQUAL "")
    set(GIT_REV "0.0.0+unknown")
endif()

set(RAW_GIT_REV "${GIT_REV}")
if(GIT_REV MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?)-([0-9]+)-g([0-9a-f]+)(-dirty)?$")
    set(GIT_REV "${CMAKE_MATCH_1}+${CMAKE_MATCH_3}.g${CMAKE_MATCH_4}${CMAKE_MATCH_5}")
    string(REPLACE "-dirty" ".dirty" GIT_REV "${GIT_REV}")
elseif(GIT_REV MATCHES "^[0-9a-f]+(-dirty)?$")
    set(GIT_REV "0.0.0+g${GIT_REV}")
    string(REPLACE "-dirty" ".dirty" GIT_REV "${GIT_REV}")
elseif(NOT GIT_REV MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\\+[0-9A-Za-z][0-9A-Za-z.-]*)?$")
    string(REGEX REPLACE "[^0-9A-Za-z-]+" "." GIT_REV_BUILD "${RAW_GIT_REV}")
    string(REGEX REPLACE "^\\.+|\\.+$" "" GIT_REV_BUILD "${GIT_REV_BUILD}")
    if(GIT_REV_BUILD STREQUAL "")
        set(GIT_REV_BUILD "unknown")
    endif()
    set(GIT_REV "0.0.0+${GIT_REV_BUILD}")
endif()

string(REPLACE "\\" "\\\\" GIT_REV "${GIT_REV}")
string(REPLACE "\"" "\\\"" GIT_REV "${GIT_REV}")

set(HEADER_CONTENT
"/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_VIRT_CARD_GIT_REV_H_
#define CANOKEY_VIRT_CARD_GIT_REV_H_

#define GIT_REV \"${GIT_REV}\"

#endif // CANOKEY_VIRT_CARD_GIT_REV_H_
")

get_filename_component(OUTPUT_DIR "${OUTPUT_FILE}" DIRECTORY)
file(MAKE_DIRECTORY "${OUTPUT_DIR}")
if(EXISTS "${OUTPUT_FILE}")
    file(READ "${OUTPUT_FILE}" EXISTING_CONTENT)
else()
    set(EXISTING_CONTENT "")
endif()

if(NOT EXISTING_CONTENT STREQUAL HEADER_CONTENT)
    file(WRITE "${OUTPUT_FILE}" "${HEADER_CONTENT}")
endif()
