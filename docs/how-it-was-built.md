# How this was built

An honest account, because how software gets built is part of engineering, and a role that lists
agentic tooling should be able to talk about it plainly.

## Division of labor

- **Human (me):** the concepts, the architecture, the design decisions, and the review. I chose what
  each module should do, what counts as `ERROR` versus `FAIL`, why drift attribution matches the
  action to the drifted field, and which guardrails an agent needs. I read and can explain every
  module in this repo.
- **Agents:** drafting code and prose to that spec, and the mechanical work (repetitive JSON, porting
  a function, formatting docs) at speed.

The interesting part is not the speed. It is the review. Anything I could not explain, I did not keep.

## Numbers

Approximate, from the OpenRouter dashboard (exact figures live there):

| | |
|---|---|
| Time | roughly two hours of session time |
| Primary model | DeepSeek V4.1 Flash (OpenRouter) |
| Also used | Kimi K3 for the design pass; GLM 5.3 Prime for an independent read |
| Input tokens | a few million (large context, re-read across many turns) |
| Output tokens | a few hundred thousand |
| Cost | about $5 |

The expensive input was the design, not the tokens. A tight spec and a clear set of decisions did
more than raw generation.

## What an agent is good at here, and what it is not

**Good at:** boilerplate, repetitive data, first-draft prose, refactors, and tests for known behavior.
**Not good at:** deciding what a control *means*, where the trust boundaries go, or whether an output
is correct. Those require a human who understands the domain.

## The honest caveat

An agent will confidently produce plausible-but-wrong code. The `ERROR`-versus-`PASS` decision, the
anti-replay window, and the field-level attribution can be reproduced once specified, but the model
does not know they matter on its own. The value here is the specification and the review, and those
are mine.

## What is verified versus approximate

Because the repo makes factual claims, here is how hard each has been checked:

- **Verified against the source.** The NIST CSF 2.0 dataset: all 106 subcategory refs and titles were
  diffed against NIST's official CSF 2.0 reference data (the CSRC reference tool) and matched
  byte-for-byte, with the 22-category set exact. The vendor API specs (Okta, Jamf, GitHub,
  Kubernetes, Wiz) were checked against each vendor's published API docs; several field and endpoint
  names were corrected in review.
- **Runtime-verified.** Every number in this README (test count, control summaries, crosswalk
  counts) is the output of the commands shown, re-run before publishing.
- **Approximate.** The token and cost figures above are estimates from the OpenRouter dashboard, not
  an exact export. The draft API responses in `docs/integrations/` are illustrative shapes from the
  docs, not captured traffic.
