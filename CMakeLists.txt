cmake_minimum_required(VERSION 3.20)
project(systemes3recomp VERSION 0.1.0 LANGUAGES C)

# Runtime for statically recompiled Namco System ES3 games.
#
# The runtime cannot be a plain static library: three of its headers
# (recomp_imports.h, recomp_iat.h, recomp_funcs_list.h) are generated from the
# game's own executable, so the sources only compile in the context of one
# title. Hence a function a game project calls instead:
#
#   add_subdirectory(systemes3recomp)
#   add_executable(mygame src/host.c ${GENERATED})
#   es3_runtime(mygame games/mygame/generated)
#
# The build must be 32-bit, and it must be MSVC. The CPU model in
# pcrecomp/runtime/recomp32_cpu is flat - a guest register holds a real host
# address - and an ES3 image is linked at 0x00400000, which only exists as an
# address in a 32-bit process. MSVC because the lifted <-> real boundary in
# pcrecomp/runtime/hybrid is x86 `__asm`, and because handing the game the
# host's own kernel32 only works on a Windows host in the first place.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(ES3_RUNTIME_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/runtime" CACHE INTERNAL "")
set(ES3_CPU_DIR     "${CMAKE_CURRENT_SOURCE_DIR}/pcrecomp/runtime/recomp32_cpu" CACHE INTERNAL "")
set(ES3_HYBRID_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/pcrecomp/runtime/hybrid" CACHE INTERNAL "")

if(NOT EXISTS "${ES3_CPU_DIR}/cpu.h")
    message(FATAL_ERROR
        "pcrecomp submodule is missing (${ES3_CPU_DIR}/cpu.h).\n"
        "  git submodule update --init --recursive")
endif()

function(es3_runtime target generated_dir)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "${target} is being built 64-bit. Recompiled ES3 code holds guest "
            "addresses in host registers and the game maps at 0x00400000, so "
            "the host must be 32-bit: cmake -B build -A Win32")
    endif()
    if(NOT MSVC)
        message(FATAL_ERROR
            "${target} needs MSVC. The lifted <-> real boundary is x86 __asm, "
            "and forwarding an import to the host's own kernel32 needs a "
            "Windows host to forward it to.")
    endif()
    target_sources(${target} PRIVATE
        "${ES3_RUNTIME_DIR}/guest.c"
        "${ES3_RUNTIME_DIR}/dispatch.c"
        "${ES3_RUNTIME_DIR}/hle.c"
        "${ES3_RUNTIME_DIR}/hle_native.c"
        "${ES3_RUNTIME_DIR}/hle_board.c"
        "${ES3_HYBRID_DIR}/hybrid.c"
    )
    target_include_directories(${target} PRIVATE
        "${ES3_RUNTIME_DIR}"
        "${ES3_CPU_DIR}"
        "${ES3_HYBRID_DIR}"
        "${generated_dir}"
    )
    # Generated code is correct and ugly: it converts between widths on every
    # other line and leaves labels no branch reaches.
    target_compile_options(${target} PRIVATE
        /W1 /wd4244 /wd4267 /wd4018 /wd4102 /wd4101 /wd4146 /wd4996)
    # No ASLR: the image is mapped at the address it was linked for, and none
    # of these titles set DYNAMIC_BASE either. The guest gets its own 8 MB
    # stack, but the host thread runs the dispatcher on top of the recursion
    # the game's own call graph produces, so give it room.
    target_link_options(${target} PRIVATE /DYNAMICBASE:NO /STACK:16777216)
endfunction()

# Self-check: builds the runtime against stub generated headers and exercises
# the parts that do not need a game - the dispatch table, the import sentinel
# range, and the purge table. guest_load() is covered by the first real title.
enable_testing()
add_executable(es3_rt_selftest tests/selftest/selftest.c)
es3_runtime(es3_rt_selftest "${CMAKE_CURRENT_SOURCE_DIR}/tests/selftest")
add_test(NAME es3_rt_selftest COMMAND es3_rt_selftest)

# pcrecomp's own x87 boundary check, built here because this is the project
# that needs it: an ES3 title imports nine of MSVC's `_CI*` helpers, which pass
# their arguments in x87 registers and nothing on the stack.
add_executable(hybrid_fpu_selftest "${ES3_HYBRID_DIR}/hybrid_selftest.c"
                                   "${ES3_HYBRID_DIR}/hybrid.c")
target_include_directories(hybrid_fpu_selftest PRIVATE "${ES3_HYBRID_DIR}")
add_test(NAME hybrid_fpu_selftest COMMAND hybrid_fpu_selftest)
