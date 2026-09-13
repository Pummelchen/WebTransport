/* A deterministic driver for the parser fuzz harness (WT-175).
 *
 * WHY THIS EXISTS BESIDE libFuzzer. `fuzz_parsers.c` is a libFuzzer target, and libFuzzer ships with clang only:
 * a GCC build -- and Apple's clang, whose toolchain does not carry `libclang_rt.fuzzer_osx.a` -- cannot link it.
 * A fuzz suite that runs only where the toolchain happens to have a driver is a fuzz suite that quietly does not
 * run, which is the failure this project refuses elsewhere (a CI job that cannot pass is not added; a check that
 * cannot run says so). So the HARNESS is toolchain-independent and this driver runs it with deterministic
 * pseudo-random inputs under whatever sanitizers the build has, while the libFuzzer target is built as well when
 * the toolchain can, for the deeper search only a coverage-guided fuzzer does.
 *
 * The generator is the same xorshift64 the malformed-input corpora use, seeded from the command line, so a run is
 * reproducible byte for byte and a failure can be replayed by giving the same seed and index. `--corpus DIR`
 * additionally feeds every file in a directory, which is how a crash artifact or an exported corpus is replayed.
 *
 * Usage: fuzz_parsers_smoke [--runs N] [--seed S] [--corpus DIR]
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The corpus is a directory listing, which is POSIX. MinGW provides it (the Windows sweep compiles this file),
 * and a platform without it simply has no corpus option -- said at run time rather than at link time. */
#if defined(_WIN32) && !defined(__MINGW32__)
#define WT_FUZZ_NO_CORPUS 1
#else
#include <dirent.h>
#endif

/* The harness entry point, which is libFuzzer's convention and also this driver's. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define DEFAULT_RUNS 20000U
#define MAX_INPUT 512U

/* The malformed-input corpora's generator, so a seed here and a seed there mean the same sequence. */
static uint64_t next_random(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

/* One file, capped: a corpus is a replay of inputs somebody chose, and a file larger than the parsers will ever
 * see is a slower way to test the same paths. */
static unsigned run_file(const char *path) {
  uint8_t buffer[MAX_INPUT];
  size_t length = 0U;
  FILE *file = fopen(path, "rb");

  if (file == NULL) return 0U;
  length = fread(buffer, 1U, sizeof(buffer), file);
  (void)fclose(file);
  if (length == 0U) return 0U;
  (void)LLVMFuzzerTestOneInput(buffer, length);
  return 1U;
}

#ifdef WT_FUZZ_NO_CORPUS
static unsigned run_corpus(const char *directory) {
  (void)directory;
  fprintf(stderr, "fuzz: no corpus support on this platform\n");
  return 0U;
}
#else
static unsigned run_corpus(const char *directory) {
  unsigned files = 0U;
  DIR *dir = opendir(directory);
  struct dirent *entry;

  if (dir == NULL) {
    fprintf(stderr, "fuzz: the corpus directory %s could not be opened\n", directory);
    return 0U;
  }
  while ((entry = readdir(dir)) != NULL) {
    char path[1024];
    if (entry->d_name[0] == '.') continue; /* "." and "..", and a hidden file is not a corpus entry */
    if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) >= (int)sizeof(path)) continue;
    files += run_file(path);
  }
  (void)closedir(dir);
  return files;
}
#endif

int main(int argc, char **argv) {
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  unsigned runs = DEFAULT_RUNS;
  const char *corpus = NULL;
  unsigned index;
  unsigned files = 0U;
  int i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
      runs = (unsigned)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      state = (uint64_t)strtoull(argv[++i], NULL, 0);
      if (state == 0U) state = 0x9e3779b97f4a7c15ULL;
    } else if (strcmp(argv[i], "--corpus") == 0 && i + 1 < argc) {
      corpus = argv[++i];
    } else {
      fprintf(stderr, "usage: %s [--runs N] [--seed S] [--corpus DIR]\n", argv[0]);
      return 2;
    }
  }

  /* A corpus is a directory in this project's own convention: one input per file, named however the producer
   * likes, because the parsers read bytes and not names. Enumerating it needs a directory listing, which is
   * POSIX; the target is built on the platforms this tree supports, and a directory that cannot be opened is
   * reported rather than silently ignored. */
  if (corpus != NULL) {
    files = run_corpus(corpus);
    printf("fuzz: %u corpus file(s) from %s\n", files, corpus);
  }

  for (index = 0U; index < runs; index++) {
    uint8_t input[MAX_INPUT];
    size_t length = (size_t)(next_random(&state) % (uint64_t)MAX_INPUT);
    size_t byte;

    if (length == 0U) length = 1U; /* the harness ignores an empty input; a run should not be wasted */
    for (byte = 0U; byte < length; byte++) {
      input[byte] = (uint8_t)(next_random(&state) >> 24);
    }
    (void)LLVMFuzzerTestOneInput(input, length);
  }

  printf("fuzz: %u generated input(s) and %u corpus file(s), no crash\n", runs, files);
  return 0;
}
