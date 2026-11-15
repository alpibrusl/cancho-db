# The Go verifier

The independent third verifier. It was written from `docs/spec/commit.md` and `docs/spec/token.md` alone, by a separate
agent session that was given a directory holding only those two files, the vectors and the vector runner, and was told not
to read any other implementation. Its tool-call log was checked afterwards: it read the two specs, wrote this file, and ran
the vectors. It is **not sandboxed**, so the isolation rests on the instruction and on that check, and it is the same model
family as the other two, so a misreading the family shares would be shared.

It has no dependency beyond Go's standard library (`crypto/ed25519`, a third Ed25519 implementation next to cancho's own and
OpenSSL's). Its first run failed 66 of 209 vectors on one bug of its own (a block signature taken over the payload without
`next_key`); the spec was clear and the vectors found it. Where it had to decide something the spec left open, it said so,
and those decisions are now written into the specs (commit.md §2, §5, §6; token.md §1, §3).

It was later extended to the statement IR (`docs/spec/ir.md`) the same way: the same agent was shown the new spec and the
refreshed vectors and nothing else, wrote `ir.go` before running any IR vector, and all of them passed without a fix. Its
tool-call log was audited again (no read outside its directory). It listed eight places `ir.md` left open; they are now
written into it. Fuzzing the three verifiers against each other later found one ordering ambiguity in `commit.md` (a list
judged whole or per element); once the spec said which, the agent changed `readEffects` from the clarified text.

    go build -o ../../build/verify-go .
