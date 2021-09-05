set(BINARY "pei")

set(SRCDIRS "operations" "pe" "utils")

# The list of include directories
set(INCDIRS "include")

# Directories to read metric tests
set(TESTDIRS "tests/feature" "tests/unit")

# The GLOB used to match source files
set(SRCGLOB "*.c")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Werror -Wno-stringop-truncation -O2 -march=native")
set(CMAKE_C_FLAGS_RELEASE "-g0 -s")
set(CMAKE_C_FLAGS_DEBUG "-g3")
