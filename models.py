from enum import Enum


class UserRole(str, Enum):
    admin = "Administrator"
    guard = "Security Guard"
    recep = "Receptionist"


class VisitorStatus(str, Enum):
    active  = "Active"
    blocked = "Blocked"


class ApprovalStatus(str, Enum):
    pending  = "Pending"
    approved = "Approved"
    rejected = "Rejected"


class VisitStatus(str, Enum):
    pending         = "Pending"
    pending_arrival = "Pending Arrival"
    checked_in      = "Checked In"
    checked_out     = "Checked Out"
    rejected        = "Rejected"
