"""Deterministic checks. No LLM calls allowed in this package (see ADR 0001).

Each module registers its checks with the @check decorator; registry.load_all()
imports every module here.
"""
