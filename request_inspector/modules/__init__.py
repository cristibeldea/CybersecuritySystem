"""
The six detection modules of the request inspector.

Each module corresponds one-to-one with a Python file and with a
subsection of Chapter 3 of the thesis:

    M1: Volume threshold          ← m1_volume.py
    M2: Frequency regularity      ← m2_frequency.py
    M3: Sequential pattern        ← m3_sequential.py
    M4: Fingerprint consistency   ← m4_fingerprint.py
    M5: Funnel timing             ← m5_funnel.py
    M6: Distributed botnet        ← m6_botnet.py

The public entry points are the ``check_*`` functions re-exported here.
The main inspector loop in ``inspector.py`` calls them sequentially per
event, in the order above, stopping at the first ban.
"""
from .m1_volume import check_volume
from .m2_frequency import check_frequency_regularity
from .m3_sequential import check_sequential_pattern
from .m4_fingerprint import check_fingerprint
from .m5_funnel import check_funnel_timing
from .m6_botnet import check_distributed_botnet

__all__ = [
    "check_volume",
    "check_frequency_regularity",
    "check_sequential_pattern",
    "check_fingerprint",
    "check_funnel_timing",
    "check_distributed_botnet",
]
