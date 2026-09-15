"""didwebvh.binding — proving a claimed did:webs sibling rather than repeating it.

A did:webvh document may name a did:webs DID in ``alsoKnownAs``. That assertion is covered by the
entry's Data Integrity proof, which proves the *controller of the log* said it -- and nothing
whatever about whether they control the AID named. Every other did:webvh host publishes it on
that basis. This one does not (this.i k6fiebmm).

**What is actually checked.** The submission carries the AID's key event log. keripy verifies it
from inception in a scratch store, and the binding holds when the log's active ``updateKeys``
contains the multikey form of that AID's **current** signing key. That is a statement about
control today: the same private key that can rotate the AID is the one that can write the next
did:webvh entry, so the two identifiers are under one hand.

**Current key state, never historical.** A key the AID has rotated away from proves nothing about
who controls it now, so a log whose update key matches a prior key is refused. Concretely: the
check reads ``kever.verfers``, which is current key state after the whole KEL is applied, rather
than searching the KEL for any key that ever appeared.

**Unused evidence is a mistake, not a courtesy.** A stream submitted for a document that claims no
sibling is refused rather than ignored, because an operator who supplied one believed it was doing
something, and silently discarding it would leave them believing a binding had been checked.

**What this deliberately does not do.** It does not verify designated-alias ACDCs, TELs, or that
the did:webs DID is authorized by the AID for *that host and path* -- that is the did:webs method's
own rule and the sibling repo's job. The claim here is narrower and is stated in the refusal: one
key, under one controller, at this moment.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import base58
from keri.app import habbing
from keri.kering import Vrsn_1_0 as V1

from didwebvh import errors
from didwebvh.did import WebvhDid
from didwebvh.verify import Verified

__all__ = ["bind", "multikey"]

#: The did:webs method prefix. A sibling claim is any ``alsoKnownAs`` entry that begins with it.
_WEBS = "did:webs:"

#: multicodec ``ed25519-pub``, which is what a did:webvh update key must be under the only
#: cryptosuite v1.0 permits. The leading ``z`` is multibase base58btc.
_ED25519_MULTICODEC = bytes([0xED, 0x01])

#: KERI's derivation code for a transferable Ed25519 key. Anything else cannot be an update key
#: for a `did:webvh:1.0` log, so it cannot satisfy a binding either.
_ED25519_CODE = "D"


def multikey(raw: bytes) -> str:
    """The multikey form of a raw Ed25519 public key, which is how did:webvh names one."""
    return "z" + base58.b58encode(_ED25519_MULTICODEC + raw).decode()


def bind(verified: Verified, did: WebvhDid, stream: bytes | None) -> None:
    """Refuse a publication whose claimed did:webs sibling is not proven by the submitted KEL.

    Args:
        verified: what the library's walk produced, carrying the document and the active
            update keys.
        did: the DID being published, for refusal messages.
        stream: the submitted ``keri.cesr``, or None when none was supplied.

    Raises:
        bakobo.errors.BakoboError: ``e.input.missing.binding-evidence.f`` when a claim has no
            evidence, ``e.rule.binding.unused-evidence.f`` when evidence has no claim,
            ``e.proof.binding.aid.f`` when the AID is unusable or absent from the stream, and
            ``e.proof.binding.key.f`` when it is present but under a different key.
    """
    claims = _claims(verified.document, did)

    if not claims:
        if stream is not None:
            raise errors.BINDING_EVIDENCE_UNUSED(did=did.canonical)
        return
    if stream is None:
        raise errors.BINDING_EVIDENCE_MISSING(did=did.canonical, sibling=claims[0])

    current = _current_keys(stream)
    for claim in claims:
        aid = _aid(claim, did)
        keys = current.get(aid)
        if keys is None:
            raise errors.BINDING_AID_UNPROVEN(
                did=did.canonical,
                sibling=claim,
                problem="the submitted key event log does not verify an AID by that name",
            )
        if not set(keys) & set(verified.update_keys):
            raise errors.BINDING_KEY_MISMATCH(did=did.canonical, sibling=claim)


def _claims(document: dict, did: WebvhDid) -> tuple[str, ...]:
    """Every did:webs DID this document claims to be the same subject as.

    A non-string entry is skipped rather than refused: ``alsoKnownAs`` is an open list that may
    carry any URI, and something we cannot read is not something we are claiming about. An
    ``alsoKnownAs`` that is not a list at all is a different matter -- the document is malformed
    in the one member this check depends on, so it is refused rather than read past.
    """
    aliases = document.get("alsoKnownAs", [])
    if not isinstance(aliases, list):
        raise errors.BINDING_AID_UNPROVEN(
            did=did.canonical,
            sibling="the alsoKnownAs member",
            problem="alsoKnownAs is not an array",
        )
    return tuple(a for a in aliases if isinstance(a, str) and a.startswith(_WEBS))


def _aid(claim: str, did: WebvhDid) -> str:
    """The AID a did:webs DID names, which is always its final colon-delimited segment."""
    aid = claim.rsplit(":", 1)[-1]
    if not aid or not _looks_like_a_said(aid):
        raise errors.BINDING_AID_UNPROVEN(
            did=did.canonical,
            sibling=claim,
            problem="its final segment is not a KERI AID",
        )
    return aid


def _looks_like_a_said(aid: str) -> bool:
    """A cheap shape test, so a malformed claim is refused before keripy is asked about it.

    Deliberately shape-only. Whether this is a *real* AID is settled by whether the submitted KEL
    verifies one by that name, which is the check that carries the weight; this exists so that a
    claim like ``did:webs:example.com`` -- where the final segment is a hostname -- is refused for
    the right reason instead of being reported as an AID missing from the stream.
    """
    return len(aid) == 44 and aid[0] in "EFGHID" and "." not in aid


def _current_keys(stream: bytes) -> dict[str, tuple[str, ...]]:
    """Verify a KEL in a scratch store and return each AID's *current* signing keys.

    keripy accepts what verifies and silently declines what does not, so an AID absent from the
    result is the same answer for a forged stream, a truncated one, and bytes that were never
    CESR. That is the right shape for this check: the caller needs to know the AID was proven,
    not why it was not.

    The store is temporary and removed on the way out, including the roots keripy's own close
    leaves standing -- see :func:`_temp_roots`. Nothing about a submission survives the decision
    it was submitted for.
    """
    hby = habbing.Habery(name="didwebvh-binding", base="", temp=True, version=V1)
    roots = _temp_roots(hby)
    try:
        try:
            hby.psr.parse(bytearray(stream), version=V1)
        except Exception:  # noqa: BLE001 - keripy raises many extraction types; all mean "no"
            return {}
        return {
            aid: tuple(
                multikey(verfer.raw)
                for verfer in kever.verfers
                if verfer.code == _ED25519_CODE
            )
            for aid, kever in hby.kevers.items()
        }
    finally:
        hby.close(clear=True)
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def _temp_roots(hby: habbing.Habery) -> tuple[Path, ...]:
    """The directories keripy will otherwise strand, collected before anything is closed.

    keripy ignores ``headDirPath`` for a temp store -- hio's ``Filer.remake`` substitutes its own
    ``mkdtemp`` -- and its close removes only the store's leaf directory. Each keystore build
    therefore leaves a root behind. Unremoved they accumulate: the sibling repo has stranded
    32,000 of them, about 3.4 GB of tmpfs, and its own suite went nondeterministic as a result.

    Collected here rather than in the ``finally`` because the paths are read off open stores.
    """
    return tuple(
        dict.fromkeys(
            root
            for store in (hby.ks, hby.db, hby.cf)
            if (root := _temp_root(store.path)) is not None
        )
    )


def _temp_root(path: str) -> Path | None:
    """The ancestor of ``path`` sitting directly in the temp directory, or None.

    None whenever ``path`` is not under the temp directory at all, and the caller then removes
    nothing. Returning an option rather than a path is the point: this value is handed to
    ``shutil.rmtree``, and a walk that fell off its assumption would hand it something very much
    larger than a scratch keystore.
    """
    root = Path(tempfile.gettempdir()).resolve()
    walked = Path(path).resolve()
    while walked.parent != root:
        if walked.parent == walked:
            return None
        walked = walked.parent
    return walked
