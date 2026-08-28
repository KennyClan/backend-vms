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


# ── Module access control ─────────────────────────────────────────
# Every navigable area/module of the app. A staff account's `permissions`
# (JSONB list on staff_users) decides which of these it can open. Anything
# not listed here cannot be granted.
ALL_MODULES = (
    "dashboard",
    "visitors",
    "requests",
    "security",
    "myroom",
    "analytics",
    "audit",
    "restricted",
    "staff",
    "departments",
    "floorplan",
    "visitor-history",
)

# Default module set per role. Used when an account has no explicit
# permissions yet (seed/backfill) and to reset access when a role changes.
# Super Admin is intentionally non-editable (full access).
DEFAULT_MODULES_BY_ROLE = {
    UserRole.super_admin.value: [
        "dashboard", "visitors", "requests", "security", "myroom",
        "analytics", "audit", "restricted", "staff", "departments", "floorplan",
    ],
    UserRole.admin.value: [
        "dashboard", "visitors", "requests", "security",
        "analytics", "audit", "restricted", "staff", "departments", "floorplan",
    ],
    UserRole.recep.value: [
        "dashboard", "visitors", "requests", "analytics", "audit", "floorplan",
    ],
    UserRole.guard.value: [
        "dashboard", "myroom", "visitors", "security", "restricted",
    ],
    UserRole.employee.value: [
        "dashboard", "requests", "visitor-history",
    ],
}
