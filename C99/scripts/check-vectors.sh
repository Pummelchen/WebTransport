#!/bin/sh
# Re-extract the RFC vectors and compare them with the committed headers.
#
# The vectors under tests/vectors/ are generated from RFC text rather than typed
# out, and this is the check that keeps them that way: each extractor re-derives
# every value from the RFC's own hex -- an Initial secret from the version-1 salt
# and the connection ID, a key from its traffic secret, a header protection sample
# as the packet's bytes at pn_offset + 4 -- and refuses to write one that does not
# check out. Running it in CI means a header edited by hand, or regenerated from a
# different document, fails here rather than quietly changing what a test proves.
#
# The RFC text is fetched rather than committed: it is a third party's document,
# and a copy in this repository would be a second source of truth for the vectors
# as well as a large file to keep in step. WEBTRANSPORT_RFC_DIR says where to keep
# the download; the default is the temporary directory.
#
#   C99/scripts/check-vectors.sh
#
# Needs python3 and network access the first time it runs.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

rfc_dir=${WEBTRANSPORT_RFC_DIR:-${TMPDIR:-/tmp}}
rfc_dir=${rfc_dir%/}
rfc="$rfc_dir/rfc9001.txt"

if [ ! -f "$rfc" ]; then
  url=https://www.rfc-editor.org/rfc/rfc9001.txt
  echo "check-vectors: fetching $url"
  if ! curl -fsSL "$url" -o "$rfc"; then
    rm -f "$rfc"
    echo "check-vectors: could not fetch $url" >&2
    exit 2
  fi
fi

python3 "$c99_root/tests/vectors/extract_rfc9001_keys.py" "$rfc" --check
python3 "$c99_root/tests/vectors/extract_rfc9001_client_initial.py" "$rfc" --check
