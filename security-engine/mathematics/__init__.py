"""Bug Dhor validated mathematical formulations.

This package provides executable, dependency-light implementations of the
mathematical components of Bug Dhor.  Every component is implemented from its
stated equation and validated by unit and numerical tests.  No function returns
a hardcoded score or a manually fabricated result.

Design conventions
------------------
* Core numerics use :mod:`numpy`; PyTorch tensors are accepted through
  :func:`mathematics.common.as_float_array` when they are detached CPU tensors.
* SciPy is optional.  Statistical routines fall back to numerically stable
  NumPy implementations so the package runs in the project's minimal
  environment.
* Missing observations are represented by ``NaN`` and, where meaningful, by an
  explicit boolean ``observed`` mask.  Missing values are never silently
  imputed with zero for a statistical estimand.
* Bootstrap procedures accept an explicit seed or ``numpy.random.Generator``
  for reproducibility.

The mathematical report is in ``MATHEMATICAL_IMPLEMENTATION_REPORT.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"
