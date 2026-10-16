#!/usr/bin/env python3
"""Source tripwire only; ordinary Cargo graphs/binaries and local ACL gates are separate."""
import os
import pathlib
import re
import sys
import tomllib

FEATURE = "a2-local-fixture-generator"
GENERATOR = "consensus/src/endorsement_revocation_v1/local_synthetic_fixture_generator.rs"
TESTS = "consensus/src/endorsement_revocation_v1/tests.rs"
PARENT = "consensus/src/endorsement_revocation_v1.rs"
HOOK = ('#[cfg(all(test, any(windows, target_os="linux"), feature = "a2-local-fixture-generator"))]\n'
        '#[path = "local_synthetic_fixture_generator.rs"]\n'
        'mod local_fixture_generator;')
MARKERS = ("generate_protected_local_synthetic_a2_native_fixture",
           "BUILD8_A2_LOCAL_SOFTWARE_FIXTURE", "PUBLIC TEST VALUE A2 ONLY")


def check(root):
    errors = []

    def require(condition, reason):
        if not condition:
            errors.append(reason)

    def read(rel):
        path = root / rel
        require(path.is_file() and not path.is_symlink(), "missing/nonregular source " + rel)
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    files = []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "vendor"}
                   and not (pathlib.Path(base) / d).is_symlink()]
        files.extend(pathlib.Path(base) / name for name in names)
    declaration = 0
    for path in files:
        if path.name != "Cargo.toml":
            continue
        rel = path.relative_to(root).as_posix()
        text = read(rel)
        try:
            manifest = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            require(False, "invalid manifest " + rel)
            continue
        # Exactly one empty feature; any dependency/default/build/target/feature
        # string referencing it is refused, including multiline/renamed edges.
        if rel == "consensus/Cargo.toml":
            features = manifest.get("features", {})
            require(features.get(FEATURE) == [], "generator feature must be empty nondefault")
            require(text.count(FEATURE) == 1, "generator declaration must have one source site")
            require(bool(re.search(r"^a2-local-fixture-generator = \[\]$", text, re.M)),
                    "generator exact declaration")
            declaration += int(FEATURE in features)
            features.pop(FEATURE, None)

        def forbidden(value):
            if isinstance(value, str):
                return FEATURE in value or "local_synthetic_fixture_generator" in value
            if isinstance(value, list):
                return any(forbidden(x) for x in value)
            if isinstance(value, dict):
                return any(FEATURE in str(k) or forbidden(v) for k, v in value.items())
            return False

        require(not forbidden(manifest), "generator forward/target forbidden in " + rel)
    require(declaration == 1, "exactly one generator feature declaration")
    parent = read(PARENT)
    require(parent.count('mod route_tests;') == 1 and
            '#[cfg(test)]\n#[path = "endorsement_revocation_v1/tests.rs"]\nmod route_tests;' in parent,
            "generator parent must remain private cfg(test)")
    tests = read(TESTS)
    require(tests.count(HOOK) == 1, "exact test/Windows-or-Linux/explicit-feature private hook")
    require(tests.count(FEATURE) == 1 and tests.count("local_synthetic_fixture_generator.rs") == 1,
            "one generator test hook site")
    generator = read(GENERATOR)
    require('const TEST_PASSWORD: &str = "PUBLIC TEST VALUE A2 ONLY";' in generator,
            "generator fixed public TEST value")
    require('std::env::var_os("BUILD8_A2_LOCAL_SOFTWARE_FIXTURE")' in generator,
            "generator mandatory nonsecret destination input")
    require('#[test]\nfn generate_protected_local_synthetic_a2_native_fixture()' in generator,
            "generator explicit test entry")
    require(not re.search(r"#\[ignore(?:\(|\])", generator), "generator test must not be ignored")
    for path in files:
        if path.suffix != ".rs":
            continue
        rel = path.relative_to(root).as_posix()
        text = read(rel)
        if rel != TESTS:
            require(FEATURE not in text and "local_synthetic_fixture_generator.rs" not in text,
                    "extra generator hook/export site " + rel)
        # Integration tests are test roots. Unit-test file inclusion still needs
        # an explicit reviewed cfg(test) parent; this producer has the one pinned
        # parent above. This is a tripwire, not a general Rust graph proof.
        if rel != GENERATOR and "/tests/" not in rel:
            require(not any(marker in text for marker in MARKERS),
                    "generator marker in ordinary/source unit graph " + rel)
    return errors


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1])
    failures = check(root)
    for failure in failures:
        print("FAIL " + failure)
    if not failures:
        print("PASS A2 local generator source tripwire; normal graphs/binaries/ACL/runtime remain separate")
    sys.exit(1 if failures else 0)
