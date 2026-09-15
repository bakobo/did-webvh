"""The ``didwebvh`` command line: one verb, and one operator contract.

``didwebvh publish --did <did:webvh:...> --log <did.jsonl> [--witness <did-witness.json>]
[--stream <keri.cesr>] --out <dir>`` runs the whole phase-1 pipeline: bound and shape the
submission, clamp what ``did:webvh:1.0`` forbids, walk the log with didwebvh-py, prove any
claimed did:webs sibling against the submitted KEL, and write the artifacts atomically.

**One verb, deliberately** (this.i nmhqxs5q). Minting a DID means signing with the controller's
update key, and Bakobo holds no key in a customer's trust path (this.i 7ca6mlrg), so there is
nothing an operator could be asked to run that would create one. There is deliberately no
``verify`` verb either: it would be a second, weaker notion of "verified" that could drift from
the one the gate enforces.

**The operator contract.** Exit 0 and every artifact exists, or a nonzero exit, nothing published,
and one line on stderr carrying the stable error code and a plain sentence. Exit 1 means a
submission was refused; exit 64 (``EX_USAGE``) means the invocation itself was wrong and no
submission was read. An internal fault reports ``e.self.unknown.f`` rather than letting a
traceback masquerade as a bad submission.

**The order is the design.** Size, then shape, then version policy, then cryptography, then the
binding, then the write. Each step is only trustworthy because the one before it ran, and the
clamp in particular runs before didwebvh-py sees a byte (this.i tvv6dvyn).

**Who is running this.** In phase 1 the operator asserts that the submission is the controller's:
nothing here establishes a submitter-to-DID binding, and none of it is network-facing. Both must
land before any submission surface exists.
"""

from __future__ import annotations

import argparse
import sys

from bakobo.errors import BakoboError

from didwebvh import binding, bounds, clamp, errors, publish, verify
from didwebvh.did import parse as parse_did

__all__ = ["main"]

#: ``EX_USAGE`` from sysexits.h: the command line itself was wrong.
EX_USAGE = 64

#: Any refusal of a submission. One code, because an operator scripts on the error code on
#: stderr, not on a taxonomy of exit statuses.
EX_FAILURE = 1


class _Usage(Exception):
    """A command line this program cannot act on. Never escapes :func:`main`."""


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` that reports a usage error instead of exiting the process.

    argparse's own failure path calls ``sys.exit(2)``, which would make a mistyped flag look like
    an exit status this program never promises. Raising instead lets :func:`main` return
    ``EX_USAGE`` the way every other path returns a status.
    """

    def error(self, message):
        raise _Usage(message)


def _parser() -> _Parser:
    parser = _Parser(prog="didwebvh", description="Publish did:webvh artifacts.")
    verbs = parser.add_subparsers(dest="verb", required=True)
    publishing = verbs.add_parser(
        "publish", help="verify a DID log and write did.jsonl, did.json and did-witness.json"
    )
    publishing.add_argument("--did", required=True, help="the did:webvh DID being published")
    publishing.add_argument("--log", required=True, help="the controller's did.jsonl")
    publishing.add_argument(
        "--witness", help="the controller's did-witness.json; required when the log names witnesses"
    )
    publishing.add_argument(
        "--stream",
        help="the KERI event log of the AID behind a claimed did:webs sibling; required when the "
        "document claims one",
    )
    publishing.add_argument(
        "--out", required=True, help="directory the DID's host serves artifacts from"
    )
    return parser


def _publish(args) -> int:
    """The pipeline, end to end. Any refusal raises; nothing partial is written."""
    did = parse_did(args.did)

    log = _open(bounds.open_log, args.log, "--log", did)
    witness = _open(bounds.open_witness, args.witness, "--witness", did)
    stream = _open(bounds.open_stream, args.stream, "--stream", did)

    clamp.clamp(log.parsed, did)
    if witness is not None:
        clamp.clamp_witness(witness.parsed, did)

    verified = verify.verify(log.raw, did, witness=witness.raw if witness else None)
    _refuse_unused_witness(verified, did, witness)
    binding.bind(verified, did, stream)

    directory = publish.publish(args.out, did, verified, log.raw, witness.raw if witness else None)
    for name in (publish.DID_WITNESS, publish.DID_JSONL, publish.DID_JSON):
        if (directory / name).exists():
            print(directory / name)
    return 0


def _refuse_unused_witness(verified, did, witness) -> None:
    """Refuse a witness file for a log that names no witnesses (this.i nmhqxs5q).

    The same rule binding.bind applies to an unused --stream, for the same reason: an operator who
    passed a file believed it was doing something. Publishing it instead would put a
    did-witness.json under a customer's domain that no resolver has a rule for reading, since
    witness proofs are consulted only when the log's witness parameter names witnesses.
    """
    if witness is not None and not verified.metadata.get("witness"):
        raise errors.WITNESS_EVIDENCE_UNUSED(did=did.canonical)


def _open(door, path: str | None, flag: str, did):
    """Send one submitted file through its door, or report an unreadable path as a usage error.

    A missing or unreadable file is the invocation being wrong rather than the submission being
    bad, and the two carry different exit statuses. The check is the door's own ``open`` failing
    rather than a separate existence test: this module opens nothing itself, so every byte that
    enters the process still does so through exactly one place (this.i 43ukbqca), and the door
    census stays true without an exemption arguing why a second read is harmless.

    ``None`` means the operator did not pass the flag, which is legitimate for both evidence
    arguments; whether its absence is acceptable is decided later, by whoever needs it.
    """
    if path is None:
        return None
    try:
        return door(path, did)
    except OSError as exc:
        raise _Usage(f"{flag} {path} could not be read: {exc.strerror}.") from exc


def main(argv=None) -> int:
    """Run the command line and return its exit status.

    Args:
        argv: arguments after the program name. None means read ``sys.argv``.
    """
    try:
        args = _parser().parse_args(argv)
        return _publish(args)
    except _Usage as usage:
        print(usage, file=sys.stderr)
        return EX_USAGE
    except BakoboError as refused:
        print(refused, file=sys.stderr)
        return EX_FAILURE
    except Exception as fault:  # noqa: BLE001 - an unattributable fault is still ours to report
        print(
            errors.INTERNAL_FAULT(
                did=getattr(args, "did", "the submission"),
                fault=f"{type(fault).__name__}: {fault}",
            ),
            file=sys.stderr,
        )
        return EX_FAILURE
