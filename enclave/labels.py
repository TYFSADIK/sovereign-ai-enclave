"""Security labels and the dominance check (Bell-LaPadula 'no read up').

Canadian scheme: UNCLASSIFIED < PROTECTED A < PROTECTED B < PROTECTED C
                 and CONFIDENTIAL < SECRET < TOP SECRET (classified, national interest).
Here they are put on one ordered scale for the lab; a real system keeps the two
families separate. Compartments (need-to-know) and release caveats (e.g. CAN only,
REL TO CAN/USA) must ALL be satisfied.
"""
from dataclasses import dataclass, field
import re

LEVELS = ["UNCLASSIFIED", "PROTECTED A", "PROTECTED B", "PROTECTED C", "CONFIDENTIAL", "SECRET", "TOP SECRET"]
RANK = {l: i for i, l in enumerate(LEVELS)}


@dataclass(frozen=True)
class Label:
    level: str = "UNCLASSIFIED"
    compartments: frozenset = frozenset()
    releasable_to: frozenset = frozenset({"CAN"})    # nationalities allowed

    def __post_init__(self):
        if self.level not in RANK:
            raise ValueError(f"unknown level {self.level}")

    def key_id(self):
        """Data-key bucket: one encryption key per (level, compartments)."""
        return f"{self.level}|{','.join(sorted(self.compartments))}"


@dataclass
class Subject:
    user: str
    clearance: str
    compartments: set = field(default_factory=set)
    nationality: str = "CAN"


def dominates(s: Subject, l: Label) -> tuple[bool, str]:
    if RANK[s.clearance] < RANK[l.level]:
        return False, "clearance below label"
    missing = set(l.compartments) - s.compartments
    if missing:
        return False, f"missing compartments {sorted(missing)}"
    if s.nationality not in l.releasable_to:
        return False, "not releasable to subject nationality"
    return True, "ok"


PORTION = re.compile(r"^\((U|PA|PB|PC|C|S|TS)(?://([A-Z0-9 ,/-]+))?\)\s*")
ABBR = {"U": "UNCLASSIFIED", "PA": "PROTECTED A", "PB": "PROTECTED B", "PC": "PROTECTED C",
        "C": "CONFIDENTIAL", "S": "SECRET", "TS": "TOP SECRET"}


def portion_label(paragraph: str, doc: Label) -> tuple[Label, str]:
    """Paragraph portion markings like '(PB) ...' or '(S//REL TO CAN, USA) ...' override the doc default.
    A portion can never be marked LOWER than... it can (that is the point of portion marking), but
    never higher than the document banner; that is a marking error and is raised."""
    m = PORTION.match(paragraph)
    if not m:
        return doc, paragraph
    level = ABBR[m.group(1)]
    if RANK[level] > RANK[doc.level]:
        raise ValueError(f"portion {level} above document banner {doc.level}")
    rel = doc.releasable_to
    if m.group(2) and m.group(2).startswith("REL TO"):
        rel = frozenset(x.strip() for x in m.group(2)[6:].split(","))
    return Label(level, doc.compartments, rel), paragraph[m.end():]
