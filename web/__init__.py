"""Web presentation layer for PRAHARI.

Deliberately separate from the detection path. `prahari/selftest.py` asserts
that no module the engine imports touches a network client; everything in this
package exists to serve a read-only view of what the engine produced, and none
of it is importable from the engine.
"""
