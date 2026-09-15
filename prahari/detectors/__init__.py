"""The six threat families named in SIH26145, as seven independent detectors.

Each detector consumes flows, keeps its own state, and emits scored detections
with the evidence that produced them. None of them can transmit anything.
"""
from .base import Detector, Detection
from .ddos import DDoSDetector
from .beacon import BeaconDetector
from .dga import DGADetector
from .tunnel import TunnelDetector
from .tls import EncryptedMalwareDetector
from .recon import ReconDetector
from .exfil import ExfilDetector


def all_detectors() -> list[Detector]:
    return [DDoSDetector(), BeaconDetector(), DGADetector(), TunnelDetector(),
            EncryptedMalwareDetector(), ReconDetector(), ExfilDetector()]


__all__ = ["Detector", "Detection", "all_detectors", "DDoSDetector", "BeaconDetector",
           "DGADetector", "TunnelDetector", "EncryptedMalwareDetector",
           "ReconDetector", "ExfilDetector"]
