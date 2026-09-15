"""didwebvh.clamp — what ``did:webvh:1.0`` forbids, refused before the library sees it.

The version-policy half of the method: which cryptosuite, which hash algorithm, which `method`
values, and which parameters may appear. It is *not* a second copy of the walk — hash chains,
proofs and pre-rotation are verified by didwebvh-py against real cryptography, and duplicating
that here would create a second, weaker verifier that could drift from the real one.

**Why this module exists at all** (this.i tvv6dvyn). The library we depend on accepts proofs the
specification forbids: ``did_webvh.provision --algorithm p256`` mints a log whose
``parameters.method`` is ``did:webvh:1.0`` and whose proof cryptosuite is ``ecdsa-jcs-2019``, and
the library's own resolver then accepts it. ``core/proof.py``'s suite table is keyed off the
*key's* codec and never consults the active method parameter; ``core/state.py`` validates
``method`` only as a non-empty string. didwebvh-ts enforces both, so a DID minted that way
resolves nowhere except in Python.

**States the rules, rather than patching the known gaps** (this.i t2jkfguj). A clamp written as a
list of upstream bugs would silently stop covering a rule the day upstream refactored around it.
Everything here is enforced on its own terms; where the library also enforces it, that is
redundancy and not waste.

**On the JSON null.** The specification says ``null`` **MUST NOT** be used for a parameter, and
then tells resolvers they **SHOULD** accept it gracefully and convert it to the default. A
publisher has to pick one. This gate refuses it, because did.jsonl is published byte-for-byte
(this.i gzvt7mpn) -- normalising is the option we do not have, so accepting would mean hosting a
MUST NOT violation under a customer's domain and trusting every future resolver to stay lenient.
The refusal says the log is publishable elsewhere and not here, because for a customer with an
older log that is the true and useful thing to say.
"""

from __future__ import annotations

import base58

from didwebvh import errors
from didwebvh.did import WebvhDid

__all__ = [
    "ACCEPTABLE_METHODS",
    "CRYPTOSUITE",
    "PARAMETERS",
    "PROOF_TYPE",
    "clamp",
    "clamp_witness",
]

#: The `method` values this build will publish. One entry, because v1.0 is the only ratified
#: version; every rule below is keyed to it, so growing this set means revisiting all of them.
ACCEPTABLE_METHODS = frozenset({"did:webvh:1.0"})

#: The only Data Integrity cryptosuite `did:webvh:1.0` permits, for log entry and witness proofs
#: alike. The spec adds that verifying only `proofPurpose` is insufficient.
CRYPTOSUITE = "eddsa-jcs-2022"

#: The only proof type Data Integrity defines for these cryptosuites.
PROOF_TYPE = "DataIntegrityProof"

#: The closed parameter set for v1.0. "The `parameters` object MUST only include properties
#: defined in the version of the specification being used", so an unrecognized key is a refusal
#: rather than something to ignore -- `prerotation`, removed in v0.5, is the one that turns up.
PARAMETERS = frozenset(
    {
        "method",
        "scid",
        "updateKeys",
        "nextKeyHashes",
        "witness",
        "watchers",
        "portable",
        "deactivated",
        "ttl",
    }
)

#: multihash SHA-256: code 0x12, digest length 0x20. The only algorithm v1.0 permits, so a
#: multihash is conformant exactly when it is these two bytes followed by 32 more.
_SHA256 = (0x12, 0x20)
_MULTIHASH_LENGTH = 34

#: The multibase-plus-multicodec prefix of an Ed25519 public key in did:key form. P-256 keys
#: begin `zDn` and P-384 `z82`, neither of which `eddsa-jcs-2022` can verify.
_ED25519_DID_KEY = "did:key:z6Mk"


def clamp(entries: tuple[dict, ...], did: WebvhDid | None = None) -> None:
    """Refuse a DID log that `did:webvh:1.0` does not permit.

    Args:
        entries: the log, shape-checked by :mod:`didwebvh.bounds` but otherwise unexamined.
        did: the DID being published, so the SCID can be checked against it. Optional only so
            the rules that do not need it can be exercised alone.

    Raises:
        bakobo.errors.BakoboError: one of the ``e.rule.conformance.*`` family. Nothing is written
            and nothing is passed onward; a refusal here means the library is never called.
    """
    for number, entry in enumerate(entries, start=1):
        parameters = entry["parameters"]
        _parameters(parameters, number, did)
        _method(parameters, number, did)
        _scid(parameters, number, did)
        _version_id(entry["versionId"], number, did)
        _proofs(entry["proof"], f"entry {number}", did)


def clamp_witness(proofs: tuple[dict, ...], did: WebvhDid | None = None) -> None:
    """Refuse witness proofs that `did:webvh:1.0` does not permit.

    The cryptosuite rule covers witness proofs explicitly, so a witness file is clamped on the
    same terms as the log -- a threshold met by proofs nobody can verify is not a threshold met.
    """
    for position, element in enumerate(proofs, start=1):
        _version_id(element["versionId"], position, did, what="witness proof")
        _proofs(element["proof"], f"witness proof {position}", did)


def _refuse_parameter(problem: str, number: int, did: WebvhDid | None) -> None:
    raise errors.PARAMETER_REFUSED(did=_name(did), entry=number, problem=problem)


def _name(did: WebvhDid | None) -> str:
    return did.canonical if did is not None else "the submitted DID"


def _parameters(parameters: dict, number: int, did: WebvhDid | None) -> None:
    """Every key is one v1.0 defines, and no value is the deprecated JSON null."""
    for key, value in parameters.items():
        if key not in PARAMETERS:
            _refuse_parameter(
                f"{key} is not a parameter this specification version defines", number, did
            )
        if value is None:
            _refuse_parameter(
                f"{key} is the JSON null, which this specification version forbids -- use the "
                "parameter's default or its empty value instead. A log using null may resolve "
                "elsewhere, since resolvers are asked to tolerate it, but it cannot be published "
                "here unchanged",
                number,
                did,
            )
    if "witness" in parameters:
        _witness(parameters["witness"], number, did)


def _witness(witness, number: int, did: WebvhDid | None) -> None:
    """Every witness is a did:key whose key `eddsa-jcs-2022` can actually verify."""
    if not isinstance(witness, dict):
        _refuse_parameter("witness is not an object", number, did)
    listed = witness.get("witnesses")
    if not isinstance(listed, list):
        _refuse_parameter("witness carries no witnesses array", number, did)
    for entry in listed:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            _refuse_parameter("a witness entry has no id string", number, did)
        if not entry["id"].startswith(_ED25519_DID_KEY):
            raise errors.CRYPTOSUITE_FORBIDDEN(
                did=_name(did),
                where=f"the witness {entry['id']} in entry {number}",
                found="a key this cryptosuite cannot verify",
            )


def _method(parameters: dict, number: int, did: WebvhDid | None) -> None:
    """Present and acceptable at genesis; acceptable whenever restated.

    There is deliberately no downgrade check. The spec forbids changing to a *lower* version than
    the active one, but with exactly one acceptable value any other string is already refused by
    the membership test, so a downgrade check would be a branch no submission could reach. Add it
    in the same change that adds a second version to `ACCEPTABLE_METHODS`.
    """
    if "method" not in parameters:
        if number == 1:
            raise errors.METHOD_UNACCEPTABLE(did=_name(did), entry=number, found="nothing")
        return
    value = parameters["method"]
    if not isinstance(value, str) or value not in ACCEPTABLE_METHODS:
        raise errors.METHOD_UNACCEPTABLE(did=_name(did), entry=number, found=repr(value))


def _scid(parameters: dict, number: int, did: WebvhDid | None) -> None:
    """At genesis only, and it must be the SCID of the DID being published."""
    if number == 1:
        if "scid" not in parameters:
            _refuse_parameter("the first entry carries no scid", number, did)
        _multihash(parameters["scid"], "the scid", did)
        if did is not None and parameters["scid"] != did.scid:
            _refuse_parameter(
                f"the scid is not this DID's own, which is {did.scid}", number, did
            )
    elif "scid" in parameters:
        _refuse_parameter("scid may only appear in the first entry", number, did)

    for value in parameters.get("nextKeyHashes", ()):
        _multihash(value, f"a nextKeyHashes entry in entry {number}", did)


def _version_id(version_id: str, number: int, did: WebvhDid | None, what: str = "entry") -> None:
    """``<version number>-<entryHash>``, where the hash is a SHA-256 multihash."""
    prefix, separator, digest = version_id.partition("-")
    if not separator or not prefix.isdigit():
        raise errors.HASH_FORBIDDEN(
            did=_name(did),
            where=f"{what} {number}",
            problem=f"versionId {version_id!r} is not <version number>-<entryHash>",
        )
    _multihash(digest, f"the entry hash of {what} {number}", did)


def _multihash(value, where: str, did: WebvhDid | None) -> None:
    """Refuse anything that is not a base58btc SHA-256 multihash."""
    problem = None
    if not isinstance(value, str) or not value:
        problem = "it is not a non-empty string"
    else:
        try:
            raw = base58.b58decode(value)
        except ValueError:
            problem = "it is not base58btc"
        else:
            if len(raw) < 2 or (raw[0], raw[1]) != _SHA256:
                problem = "its multihash prefix is not SHA-256 (0x12 0x20)"
            elif len(raw) != _MULTIHASH_LENGTH:
                problem = f"it declares 32 digest bytes but carries {len(raw) - 2}"
    if problem is not None:
        raise errors.HASH_FORBIDDEN(did=_name(did), where=where, problem=problem)


def _proofs(proofs, where: str, did: WebvhDid | None) -> None:
    """Every proof is a DataIntegrityProof carrying exactly the permitted cryptosuite."""
    for one in proofs if isinstance(proofs, list) else [proofs]:
        if not isinstance(one, dict):
            raise errors.CRYPTOSUITE_FORBIDDEN(
                did=_name(did), where=where, found="a proof that is not an object"
            )
        if one.get("type") != PROOF_TYPE:
            raise errors.CRYPTOSUITE_FORBIDDEN(
                did=_name(did), where=where, found=f"proof type {one.get('type')!r}"
            )
        if one.get("cryptosuite") != CRYPTOSUITE:
            raise errors.CRYPTOSUITE_FORBIDDEN(
                did=_name(did), where=where, found=repr(one.get("cryptosuite"))
            )
