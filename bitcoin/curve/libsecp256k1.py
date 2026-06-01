"""libsecp256k1 (coincurve) availability check.

Provides the ``check`` function to verify that the coincurve C
extension is installed.
"""


def check() -> None:
    """Raise ``ImportError`` if ``coincurve`` is not installed."""
    import coincurve  # noqa: F401
