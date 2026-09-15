"""The door census.

dev/standards/input-handling.md requires one test per repo that enumerates the primitives which
bring bytes across a boundary and asserts each call site sits inside a named door or is listed as
an exemption **with a written reason**. This is that test.

It fails on *new* call sites, which is the whole point: a read that bypasses a door never looks
wrong when you write it, and a rule that lives only in a document is one a new call site never
hears about.

**What counts as a boundary primitive** is the list in :data:`PRIMITIVES` below. Two judgments in
it are arguable, and are stated here so a reviewer can disagree with them rather than having to
infer them:

* **Opening a file to write is not an input boundary.** ``open(path, "wb")`` brings no bytes in,
  so ``publish.py`` writing artifacts is out of scope. The mode argument is what distinguishes
  them, and a call whose mode cannot be read statically is treated as a read -- the failing
  direction, so an obfuscated mode does not buy silence.
* **``argparse`` is not itself a door, but it is where argv enters.** When a command line lands,
  its call site is expected to appear here and to be given a reason, not waved through.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).resolve().parent.parent / "src" / "didwebvh"

#: Names whose call or attribute access brings bytes across a boundary.
PRIMITIVES = {
    "open",
    "input",
    "read_bytes",
    "read_text",
    "iterdir",
    "argv",
    "stdin",
    "environ",
    "getenv",
    "urlopen",
    "urlretrieve",
    "get",
    "post",
    "request",
}

#: Every boundary call site that is not itself a door, each with the reason it needs none.
#: A new entry here is a claim somebody can disagree with; that is what it is for.
EXEMPTIONS: dict[str, str] = {}


def _write_mode(node: ast.Call) -> bool:
    """Whether this ``open`` call is opening for writing, and so brings nothing in.

    A mode that is not a plain literal returns False -- treated as a read, which is the failing
    direction, so obfuscating the mode does not exempt a call site.
    """
    mode = None
    if len(node.args) > 1:
        mode = node.args[1]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return bool(set(mode.value) & set("wax"))
    return False


def _enclosing(tree: ast.Module, target: ast.AST) -> str:
    """The name of the function a node sits in, or ``<module>``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for descendant in ast.walk(node):
                if descendant is target:
                    return node.name
    return "<module>"


def boundary_sites() -> list[tuple[str, str, int]]:
    """Every boundary call site in the package, as ``(module, function, line)``."""
    found = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name == "open" and _write_mode(node):
                    continue
            elif isinstance(node, ast.Attribute):
                name = node.attr
            if name in PRIMITIVES:
                found.append((path.name, _enclosing(tree, node), node.lineno))
    return found


def test_the_census_finds_something():
    """Guards the walker: a census that silently matches nothing would pass forever."""
    assert boundary_sites(), "the AST walk found no boundary primitives at all, which is wrong"


def test_every_boundary_read_is_a_door_or_an_argued_exemption():
    from didwebvh import bounds

    doors = {f"open_{door.kind}" for door in bounds.DOORS} | {"_read", "read_bounded"}
    stray = [
        f"{module}:{function}:{line}"
        for module, function, line in boundary_sites()
        if function not in doors and f"{module}:{function}" not in EXEMPTIONS
    ]
    assert not stray, (
        "these call sites bring bytes across a boundary outside any door. Either move the read "
        "inside a door in bounds.py, or add it to EXEMPTIONS with a written reason: "
        f"{stray}"
    )


def test_exemptions_carry_a_real_reason():
    """An exemption with an empty or token reason is worse than no exemption list at all."""
    for site, reason in EXEMPTIONS.items():
        assert len(reason.split()) >= 8, f"{site}'s exemption is not an argument: {reason!r}"


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ('open("x", "wb")', True),
        ('open("x", "w")', True),
        ('open("x", mode="ab")', True),
        ('open("x", "rb")', False),
        ('open("x")', False),
        ("open(path, mode)", False),
    ],
)
def test_write_mode_detection(snippet, expected):
    """The one judgment in the walker that could silently exempt a real read."""
    call = ast.parse(snippet, mode="eval").body
    assert _write_mode(call) is expected
