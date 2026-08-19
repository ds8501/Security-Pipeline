package secgate

import rego.v1

# Block/allow decision for the security pipeline verdict.
#
# Input shape:
# {
#   "injectionDetected": bool,
#   "suspiciousClean":   bool,
#   "findings": [ { "severity": "HIGH", "proofStatus": "CONFIRMED" }, ... ]
# }

default block := false

# Prompt-injection / instruction tampering always blocks.
block if input.injectionDetected == true

# An auth/permission change that produced zero findings is suspicious — fail closed.
block if input.suspiciousClean == true

# Any confirmed HIGH/CRITICAL finding blocks the merge.
block if {
	some finding in input.findings
	finding.proofStatus == "CONFIRMED"
	upper(finding.severity) in {"HIGH", "CRITICAL"}
}
