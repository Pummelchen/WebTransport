#!/bin/sh
# Install the C99 library and build a consumer against the installed package.
#
# This is the check that the install tree is usable: it configures a separate
# CMake project that does nothing but find_package(webtransport_c99) and link,
# so a missing header, a target without its include directory, or a config file
# that exports the wrong namespace fails here rather than in a user's build.
#
# Every step's output goes to a log file and is printed only when that step
# fails. The first version of this script discarded the output entirely, which
# turned a Linux-only failure in this exact check into "exit code 1" with no
# cause in the CI log -- the opposite of what a check whose whole job is to
# diagnose the install tree should do.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

case "$(uname -s)" in
  Darwin) platform=macos26 ;;
  Linux) platform=debian ;;
  FreeBSD) platform=freebsd ;;
  *) platform=unknown ;;
esac

build_dir="$c99_root/out/$platform/package-check"
prefix="$build_dir/prefix"
consumer_dir="$build_dir/consumer"
log_dir="$build_dir/logs"

rm -rf "$build_dir"
mkdir -p "$log_dir"

# Run one step with its output captured. On failure the log is printed and the
# script stops, so the reason is in the CI log next to the step that produced it.
run() {
  description=$1
  log=$2
  shift 2
  if "$@" >"$log" 2>&1; then
    return 0
  fi
  echo "webtransport-c99: $description failed; output follows" >&2
  cat "$log" >&2
  exit 1
}

run "configuring the library" "$log_dir/configure-library.log" \
  cmake -S "$c99_root" -B "$build_dir/library" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DWEBTRANSPORT_C99_BUILD_APPS=OFF \
    -DWEBTRANSPORT_C99_BUILD_TESTS=OFF
run "building the library" "$log_dir/build-library.log" \
  cmake --build "$build_dir/library"
run "installing the library" "$log_dir/install-library.log" \
  cmake --install "$build_dir/library"

# The config file is what find_package needs, and its location is part of what
# this check verifies: a package that installs everything except discoverable
# metadata is a package nobody can find.
if [ ! -f "$prefix/lib/cmake/webtransport_c99/webtransport_c99Config.cmake" ] &&
   [ ! -f "$prefix/share/cmake/webtransport_c99/webtransport_c99Config.cmake" ]; then
  echo "webtransport-c99: the installed package has no config file under $prefix" >&2
  find "$prefix" -name '*.cmake' -print >&2
  exit 1
fi

run "configuring a consumer of the installed package" "$log_dir/configure-consumer.log" \
  cmake -S "$c99_root/tests/package" -B "$consumer_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$prefix"
run "building the consumer" "$log_dir/build-consumer.log" \
  cmake --build "$consumer_dir"
run "running the consumer" "$log_dir/run-consumer.log" \
  "$consumer_dir/consumer"

# The products a release artifact carries.
#
# The Swift conformance suite asks this question of its package manifest ("release-products": production CLI
# products present, spikes not). The C99 mirror is the INSTALL TREE, because that is what a release artifact
# is here: install with the tools on and assert the product list, and assert that nothing which exists to test
# the library rather than to be run by a user came along with it.
#
# Tests are configured but only the tool targets are built, which is exact in both directions: the test
# targets EXIST (so "no test binary is installed" is a statement about the install rules rather than about a
# build that never had any), and the install step has everything it is asked to install.
tools_build="$build_dir/tools"
tools_prefix="$tools_build/prefix"
run "configuring the library with the tools" "$log_dir/configure-tools.log" \
  cmake -S "$c99_root" -B "$tools_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$tools_prefix" \
    -DWEBTRANSPORT_C99_BUILD_APPS=ON \
    -DWEBTRANSPORT_C99_BUILD_TESTS=ON
run "building the tools" "$log_dir/build-tools.log" \
  cmake --build "$tools_build" --target wt-client-c99 wt-server-c99 wt-conformance-c99 \
    webtransport_static webtransport_shared
run "installing the tools" "$log_dir/install-tools.log" \
  cmake --install "$tools_build"

missing=""
for product in wt-client-c99 wt-server-c99 wt-conformance-c99; do
  if [ ! -x "$tools_prefix/bin/$product" ]; then
    missing="$missing $product"
  fi
done
if [ -n "$missing" ]; then
  echo "webtransport-c99: the install tree is missing these tools:$missing" >&2
  find "$tools_prefix" -type f | sort >&2
  exit 1
fi

unwanted=$(find "$tools_prefix" \( -name 'test_*' -o -name '*spike*' -o -name '*sample*' \) -print)
if [ -n "$unwanted" ]; then
  echo "webtransport-c99: the install tree carries something that is not a product:" >&2
  echo "$unwanted" >&2
  exit 1
fi

if [ ! -f "$tools_prefix/include/webtransport/webtransport.h" ]; then
  echo "webtransport-c99: installing the tools lost the public headers" >&2
  find "$tools_prefix" -type f | sort >&2
  exit 1
fi

# OpenSSL is REQUIRED and Apache-2.0 (C99/CMakeLists.txt), so an install tree that carries this
# library carries a redistribution of it and owes the licence notice. The install rules put the
# repository's THIRD_PARTY_NOTICES.md under share/doc/webtransport_c99/, and this asserts it
# survived install -- in the library-only tree and in the tree with the tools (F-repo-ops-18).
for installed_prefix in "$prefix" "$tools_prefix"; do
  if ! find "$installed_prefix" -name 'THIRD_PARTY_NOTICES.md' -print | grep -q .; then
    echo "webtransport-c99: $installed_prefix carries no third-party licence notice" >&2
    find "$installed_prefix" -type f | sort >&2
    exit 1
  fi
done

echo "webtransport-c99: the installed package builds a consumer"
echo "webtransport-c99: the install tree carries the three tools and nothing that tests them"
