include(GetPrerequisites)

get_prerequisites(${TARGET_FILE} prereqs 1 1 "" "${SEARCH_PATHS}" "")

foreach(prereq ${prereqs})
    # Skipping already copied prerequisites
    if(EXISTS "${TARGET_DIR}/${prereq}")
        continue()
    endif()

    gp_resolve_item("" ${prereq} "" "${SEARCH_PATHS}" prereq_path)

    if(prereq_path)
        # A hack: we abuse configure_file()'s method of atomically updating
        # the destination to minimise possible race conditions
        configure_file("${prereq_path}" "${TARGET_DIR}/${prereq}" COPYONLY)
    endif()
endforeach()
