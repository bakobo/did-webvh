"""The error registry, checked by introspection rather than against a list kept by hand.

The list-kept-by-hand is the failure mode this guards. In the sibling repo the count in the
module docstring went on saying seventeen while two codes were minted, raised and asserted
elsewhere; nothing noticed, because nothing read it back.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest
from bakobo.errors import ErrorCode

from webvh_gate import errors

SOURCE = pathlib.Path(errors.__file__)

#: `<sorter>.<descriptor>[.<sub>...].<disposition>`, disposition being retryable or final.
SHAPE = re.compile(r"^[ew]\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.[rf]$")

#: The closed set of first descriptors from dev/standards/error-codes.md. Adding one is a change
#: to that standard, so a code outside this set is a defect rather than a new category.
DESCRIPTORS = {
    "input",
    "id",
    "grant",
    "feature",
    "proof",
    "party",
    "state",
    "env",
    "self",
    "rule",
}

#: Codes owned by bakobo/did-webs. Ours must not reuse any of them: codes are globally unique
#: across Bakobo, and two web DID methods refusing "a malformed identifier" need two codes so a
#: caller can tell which syntax failed.
DID_WEBS_CODES = {
    "e.feature.unsupported.key.alg.f",
    "e.feature.unsupported.serialization.f",
    "e.feature.unsupported.threshold.f",
    "e.grant.missing.alias.f",
    "e.grant.scope.alias.f",
    "e.input.format.did.f",
    "e.input.format.stream.f",
    "e.input.missing.alias-acdc.f",
    "e.input.missing.delegator.f",
    "e.proof.stream.anchor.f",
    "e.proof.stream.frame.f",
    "e.proof.stream.seal.f",
    "e.proof.stream.sig.f",
    "e.rule.alias.aid.mismatch.f",
    "e.rule.stream.third-party.f",
    "e.self.corrupt.schema.f",
    "e.state.conflict.kel.f",
    "e.state.revoked.alias-acdc.f",
}


def registry() -> dict[str, ErrorCode]:
    """Every ErrorCode the module declares, found by type rather than by name."""
    return {
        name: value
        for name, value in vars(errors).items()
        if isinstance(value, ErrorCode) and not name.startswith("_")
    }


class TestTheRegistryIsWhatItSaysItIs:
    def test_the_documented_count_is_the_actual_count(self):
        """The sentence in the docstring is a gate, not decoration."""
        stated = int(re.search(r"Codes declared here: (\d+)\.", errors.__doc__).group(1))
        assert stated == len(registry())

    def test_every_declaration_is_exported(self):
        assert set(errors.__all__) - {"TOO_LARGE"} == set(registry())

    def test_every_export_exists(self):
        for name in errors.__all__:
            assert hasattr(errors, name), name


class TestEveryCodeIsLegal:
    @pytest.mark.parametrize("name", sorted(registry()))
    def test_shape(self, name):
        assert SHAPE.match(registry()[name].code), registry()[name].code

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_first_descriptor_is_in_the_closed_set(self, name):
        descriptor = registry()[name].code.split(".")[1]
        assert descriptor in DESCRIPTORS, registry()[name].code

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_no_bare_descriptor(self, name):
        """A first descriptor names a category and can never be a code on its own."""
        assert len(registry()[name].code.split(".")) >= 4, registry()[name].code


class TestIdentity:
    def test_no_two_codes_share_a_string(self):
        codes = [code.code for code in registry().values()]
        assert len(codes) == len(set(codes))

    def test_none_collides_with_did_webs(self):
        ours = {code.code for code in registry().values()}
        assert not ours & DID_WEBS_CODES

    def test_no_component_name_appears_in_any_code(self):
        """Codes classify by what the obstacle was, never by which module raised it."""
        for name, code in registry().items():
            assert "webvh_gate" not in code.code.replace("did-webvh", ""), name


class TestEveryCodeIsDeclaredAsALiteral:
    """Static analysis has to be able to extract the catalog, so no code may be computed."""

    def declarations(self) -> list[ast.Call]:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        return [
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and getattr(node.value.func, "id", None) == "ErrorCode"
        ]

    def test_the_walk_finds_every_code(self):
        assert len(self.declarations()) == len(registry())

    def test_the_code_string_is_always_a_plain_literal(self):
        for call in self.declarations():
            first = call.args[0]
            assert isinstance(first, ast.Constant) and isinstance(first.value, str), ast.dump(call)


class TestMessagesAreUsable:
    @pytest.mark.parametrize("name", sorted(registry()))
    def test_a_title_reads_as_a_sentence(self, name):
        title = registry()[name].title
        assert title[0].isupper() and title.endswith("."), title

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_every_detail_placeholder_is_a_declared_arg(self, name):
        code = registry()[name]
        placeholders = set(re.findall(r"\{(\w+)\}", code.detail or ""))
        assert placeholders <= set(code.args), f"{name}: {placeholders - set(code.args)}"

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_every_declared_arg_is_used(self, name):
        code = registry()[name]
        placeholders = set(re.findall(r"\{(\w+)\}", code.detail or ""))
        assert set(code.args) <= placeholders, f"{name} declares args it never renders"

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_every_code_carries_a_hint(self, name):
        """A refusal that does not say what to do next is half an error message."""
        assert registry()[name].hint

    @pytest.mark.parametrize("name", sorted(registry()))
    def test_it_renders_without_the_placeholders_showing(self, name):
        code = registry()[name]
        rendered = str(code(**{arg: f"<{arg}>" for arg in code.args}))
        assert "{" not in rendered.replace("{SCID}", ""), rendered
        assert code.code in rendered


class TestTheFamilies:
    """The prefixes an operator is expected to branch on."""

    def test_conformance_refusals_share_a_prefix(self):
        conformance = {c.code for c in registry().values() if "conformance" in c.code}
        assert len(conformance) >= 4
        assert all(c.startswith("e.rule.conformance.") for c in conformance)

    def test_the_hosting_stance_has_its_own_family(self):
        """e.rule.hosting.* is deliberately separate from e.rule.conformance.*: one says the
        submission breaks the method, the other says the method is fine and we decline anyway.
        An operator scripting on the difference should not have to read the sentence."""
        hosting = {c.code for c in registry().values() if c.code.startswith("e.rule.hosting.")}
        assert hosting
        conformance = {c.code for c in registry().values() if "conformance" in c.code}
        assert not (hosting & conformance)

    def test_everything_is_final_rather_than_retryable(self):
        """Phase 1 has no transient failures: every refusal is about the submission, and the
        one fault that is ours (a failed write) is reported as final because a retry needs an
        operator to have changed something first."""
        assert all(code.code.endswith(".f") for code in registry().values())
