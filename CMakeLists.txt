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
        "${ES3_RUNTIME_DIR}/hle_callback.c"
        "${ES3_RUNTIME_DIR}/hle_board.c"
        "${ES3_RUNTIME_DIR}/crash.c"
        "${ES3_RUNTIME_DIR}/debug.c"
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
    # C4733 is the SEH prologue: lifted `mov fs:[0], eax` is an __asm write to
    # FS:0, which MSVC cannot register as a safe handler. That is not a defect
    # in the output - the handler is the game's own, at an address only the
    # lifted image knows - so the warning is off and so is /SAFESEH, which
    # would otherwise refuse to link an image containing one.
    target_compile_options(${target} PRIVATE
        /W1 /wd4244 /wd4267 /wd4018 /wd4102 /wd4101 /wd4146 /wd4996 /wd4733)
    # /BASE is the one that is not obvious and is not optional. A 32-bit MSVC
    # executable defaults to ImageBase 0x00400000 - which is exactly where an
    # ES3 title is linked, so the host lands on top of the guest and
    # guest_load() cannot reserve the range it needs. Move the host somewhere
    # the game does not want; 0x20000000 is clear of the image, of the heap the
    # guest grows into, and of the import sentinels at 0xE5300000.
    #
    # /DYNAMICBASE:NO keeps it there: with ASLR the host is relocated on every
    # run and would sometimes be moved back over the low addresses. None of
    # these titles set DYNAMIC_BASE either, which is why nothing relocates.
    #
    # The guest gets its own 8 MB stack, but the host thread runs the
    # dispatcher on top of whatever recursion the game's call graph produces,
    # so give it room.
    target_link_options(${target} PRIVATE
        /DYNAMICBASE:NO /SAFESEH:NO /STACK:16777216)
    # /BASE has to go through LINK_FLAGS and not target_link_options: the
    # Visual Studio generator maps the other three onto MSBuild properties and
    # silently DROPS anything it has no property for, so /BASE never reached
    # the linker and the host kept landing on 0x00400000. LINK_FLAGS lands in
    # AdditionalOptions verbatim. Check it took, do not assume:
    #   dumpbin /headers mygame.exe | findstr "image base"
    #
    # /LARGEADDRESSAWARE for the same reason, and it is not cosmetic. An ES3
    # title was built for a 2 GB address space and uses most of it: Mario Kart
    # reserves seven hundred megabytes in sixteen-megabyte chunks and commits
    # four hundred more. A recompiled one adds this runtime's own image, the
    # guest image mapped as private pages, a guest stack and a callback arena
    # per thread - two hundred megabytes the original never paid - and the game
    # then runs out, which arrives as `operator new` throwing std::bad_alloc,
    # nothing catching it, and the process ending with 0xE06D7363 and an empty
    # log. On 64-bit Windows this flag gives a 32-bit process 4 GB and the
    # whole question goes away. The guest's own code is not large-address
    # aware, so if a title ever misbehaves above 2 GB this is the flag to
    # suspect first.
    set_property(TARGET ${target} APPEND_STRING PROPERTY
                 LINK_FLAGS " /BASE:0x20000000 /LARGEADDRESSAWARE")
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
