from api.faulty.idor import IDORTarget
from api.faulty.cross_tenant import CrossTenantTarget
from api.faulty.guest_escalation import GuestEscalationTarget
from api.faulty.stale_share import StaleShareTarget
from api.faulty.transfer_retention import TransferRetentionTarget

__all__ = [
    "IDORTarget",
    "CrossTenantTarget",
    "GuestEscalationTarget",
    "StaleShareTarget",
    "TransferRetentionTarget",
]
