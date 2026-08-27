from enum import Enum


class UserRole(str, Enum):
    super_admin = "Super Admin"
    admin       = "Administrator"
    recep       = "Receptionist"
    employee    = "Employee"
    guard       = "Security Guard"


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


class DestinationType(str, Enum):
    normal     = "Normal"
    restricted = "Restricted"
