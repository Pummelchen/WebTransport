# AUDIT — tool-coverage and language-standard proofs

§1 requires that every human check delegated to a tool be shown to reject a deliberate
violation before the delegation counts, and that each language standard be shown to fail
the build on a violation. A tool that stays silent does not cover the check.

Every proof below is a deliberate violation in a scratch file, the tool's own output, and
the file removed afterwards. Nothing here is committed except this record.

## Language-standard proofs

### Swift 6 language mode + complete strict concurrency — ENFORCED

Violation (`Swift/Sources/WebTransportQUICCore/AuditProofScratch.swift`, added, built,
removed):

```swift
final class AuditProofNonSendable { var value = 0 }

func auditProofTakesSendable(_ body: @escaping @Sendable () -> Void) { body() }

func auditProofCaptureNonSendable() {
    let captured = AuditProofNonSendable()
    auditProofTakesSendable { captured.value += 1 }
}
```

`swift build` output (exit 1, build failed):

```
error: capture of 'captured' with non-Sendable type 'AuditProofNonSendable' in a '@Sendable' closure [#SendableClosureCaptures]
```

The flag actually in force, from `swift build -v`: `-swift-version 6`. No
`strict-concurrency=` flag is passed because in Swift 6 language mode complete checking is
the default; the mode is carried by `swift-tools-version: 6.4` (which defaults the language
mode to 6) and warnings-as-errors by `.treatAllWarnings(as: .error)` in both manifests.

**Recorded honestly:** the first violation tried was a plain `Task { captured.value += 1 }`
with a locally created non-Sendable class, and it **compiled**. That is not a hole in the
build — Swift 6's region-based isolation (SE-0414) permits transferring a uniquely
referenced value into a task — but it is a false negative for a proof, so the violation was
replaced with the escaping `@Sendable` form above, which is genuinely illegal. A proof that
passes for the wrong reason is not a proof.

### C99 with no extensions — ENFORCED

Violation 1, implicit declaration (`/tmp/audit-c-proof/implicit.c`):

```c
int main(void) { return audit_proof_undeclared(1); }
```

Compiled with the project's own flags, taken from `ninja -t commands` in
`C99/out/macos26/build` (so this is the real command, not an approximation):

```
/usr/bin/cc -I<repo>/C99/include -isystem <openssl3>/include -g -std=c99 -arch arm64 -fPIC \
  -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
  -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
  -Wold-style-definition -Wredundant-decls -Wundef -Wwrite-strings -Wpointer-arith \
  -Wfloat-equal -Wswitch-enum -Wvla -Wformat=2 -Wnull-dereference -Wdouble-promotion \
  -Wno-unused-parameter -c implicit.c
```

```
error: call to undeclared function 'audit_proof_undeclared'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
```

Violation 2, a GNU extension (`/tmp/audit-c-proof/nested.c`, a nested function):

```c
int main(void) {
  int inner(void) { return 42; }
  return inner();
}
```

```
error: function definition is not allowed here
error: call to undeclared function 'inner'; ISO C99 and later do not support implicit function declarations
```

`typeof` was tried first and is rejected even earlier, at the `-std=c99` parse, where it is
not a keyword at all. The nested function shows the pedantic path: accepted by nothing in
this flag set, and rejected as an error with or without `-Wpedantic`, because `-Werror`
promotes the diagnostic. `-Wpedantic` + `-Werror` is equivalent to the standard's
`-pedantic-errors` for this purpose, which is what `AUDIT/environment.md` records.

## Tool-coverage proofs

| Delegated check | Tool | Violation planted | Tool output | Covered |
| --- | --- | --- | --- | --- |
| Bare `except` | Ruff | `except:` in a function | `E722 Do not use bare \`except\``, exit 1 | yes |
| Mutable default argument | Ruff | `def f(values=[])` | `B006 Do not use mutable data structures for argument defaults` | yes |
| `assert` as validation | Ruff | `assert value is not None` outside a test path | `S101 Use of \`assert\` detected` | yes |
| Broad `pytest.raises` | Ruff | `pytest.raises(ValueError)` | `PT011 ... is too broad, set the \`match\` parameter` | yes |
| Formatting | swift-format | misindented, unspaced Swift | `error: [Indentation] unindent by 2 spaces`, `error: [Spacing] add 1 space`, exit 1 | yes |
| Secret scanning | gitleaks | fabricated RSA private-key block in `/tmp` | `WRN leaks found: 1`, exit 1 | yes |
| Swift linting | SwiftLint | force-unwrap, force-try, short/over-long names, orphaned doc comment | config added and 471 of 556 findings fixed; the force-unwrap proof is below | **yes** |
| C SAST | cppcheck | out-of-bounds write + leak in `/tmp/audit-sast/defect.c` | `error: Array 'buffer[4]' accessed at index 7, which is out of bounds. [arrayIndexOutOfBounds]` and `error: Memory leak: buffer [memleak]` | yes |
| C SAST | clang `--analyze` | null dereference in the same file | `warning: Dereference of null pointer (loaded from variable 'pointer') [core.NullDereference]` | yes |
| Dependency/config CVE scanning | trivy | fabricated RSA private-key block | `Target id_rsa | Type text | Secrets 1` | yes |
| Swift formatting gate reach | swift-format | see above | the repo already runs this in CI over the four paths; the proof above is on a scratch path | yes |

Two notes on the SAST rows, so the proof is not read as more than it is:

- `clang --analyze` exits 0 even when it reports; it is `C99/scripts/check-static-analysis.sh`
  that turns the report into a failure, and that script's own `static analysis: no findings`
  message is what it prints on a clean run. The proof here is that the analyzer is **not
  silent** on a real defect, which is the part the delegation depends on.
- cppcheck's exit status in the capture above is `141` because `head` closed the pipe
  (`SIGPIPE`); the findings themselves are the evidence, and the repo runs it with
  `--error-exitcode=1`.

The SwiftLint row is proven by the whole of `AUDIT/ledger.json` AUD-0006: the config now
reports 85 findings where an unconfigured run reported 556, every rule deviation in
`.swiftlint.yml` names its ledger task, and `force_unwrapping` — an opt-in rule the audit
standard requires to reject a force-unwrap — reports 10 real force-unwraps that were fixed
in the production sources and the tests.

An unproven delegation is recorded as **no**, not as covered. Each pending row is a task in
the ledger (SwiftLint under AUD-0006; the SAST and trivy proofs under AUD-0005).

## Proofs that a check *fails* where it should — repository gates

`Swift/check-pkcs12-keychain-free.sh` (added in the previous release) was checked the same
way: run against the pre-fix tree it exits 1 with `OSStatus -26276`, and against the fixed
tree it exits 0. That is a gate that has been seen to fail, not one assumed to work.
