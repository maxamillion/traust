---
description: "Author a property test for a patched sink with an algebraic shape, and optionally prove it witnesses the finding."
---

Author a property test for $ARGUMENTS using the property-test skill. Load the skill at .claude/skills/property-test/SKILL.md and follow its full procedure — Step 1 (decide whether the patched sink has an algebraic shape, and say so plainly when it does not: an example test is a valid answer), Step 2 (author the property from the cited primary literature, generating the input domain rather than the reported example), Step 3 (optional differential via run_property.sh, which emits a typed `property` evidence item only when the property fails on the unpatched revision and passes on the patched one).

A property that passes on the unpatched code is NOT evidence about the fix, however true it is. Never widen a strategy or add an `assume()` to make a property pass.
