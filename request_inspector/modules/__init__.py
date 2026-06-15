"""Cele sase module de detectie ale inspectorului."""
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
