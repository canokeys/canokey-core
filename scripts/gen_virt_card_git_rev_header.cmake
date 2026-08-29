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
    set(GIT_REV "unknown")
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
