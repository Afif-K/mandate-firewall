"""Capture: the user's instruction -> a Draft, through an LLM.

This is the only package that talks to the LLM and the only one that reads
its API key. The proxy never imports it: tests check both that no module
outside capture/ imports it and that building the proxy app leaves it
unloaded (docs/m3-plan.md, decision 5).

What capture produces is a Draft, which nothing trusts. The compiler
(mandate/compile.py) grounds it in the user's own words, and the user
confirms the result.
"""
