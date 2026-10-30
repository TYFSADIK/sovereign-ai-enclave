package enclave

import rego.v1

# OPA / OpenTDF-style decision for one chunk. Python labels.dominates() mirrors this for tests.
levels := ["UNCLASSIFIED", "PROTECTED A", "PROTECTED B", "PROTECTED C", "CONFIDENTIAL", "SECRET", "TOP SECRET"]

rank(l) := i if levels[i] == l

default allow := false

allow if {
	rank(input.subject.clearance) >= rank(input.resource.level)
	every c in input.resource.compartments { c in input.subject.compartments }
	input.subject.nationality in input.resource.releasable_to
}
