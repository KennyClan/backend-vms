import uuid
from datetime import date, datetime, time
from typing import Optional
from pydantic import BaseModel, EmailStr
from models import ApprovalStatus


class TokenOut(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         dict


class MfaPendingOut(BaseModel):
    mfa_required: bool = True
    pre_auth_token: str
    registration_required: bool = False
    detail: str = "Password verified. Biometric confirmation required."


class VisitorIn(BaseModel):
    full_name: str
    company:   Optional[str] = None
    phone:     Optional[str] = None
    email:     Optional[EmailStr] = None
    id_type:   str
    id_number: str


class VisitorOut(BaseModel):
    id:         uuid.UUID
    full_name:  str
    company:    Optional[str]
    phone:      Optional[str]
    email:      Optional[str]
    id_type:    str
    id_number:  str
    status:     str
    created_at: datetime


class VisitRequestIn(BaseModel):
    visitor_id:     Optional[uuid.UUID] = None
    visitor_name:   str
    visitor_email:  Optional[EmailStr]  = None
    company:        Optional[str]       = None
    phone:          Optional[str]       = None
    id_type:        Optional[str]       = None
    id_number:      Optional[str]       = None
    host_name:      str
    host_staff_id:  Optional[uuid.UUID] = None
    visit_date:     date
    expected_time:  Optional[time]      = None
    purpose:        str


class VisitRequestOut(BaseModel):
    id:                   uuid.UUID
    visitor_name:         str
    host_name:            str
    visit_date:           date
    expected_time:        Optional[time]
    purpose:              str
    approval_status:      str
    status:               str
    badge_number:         Optional[str]
    visitor_id_verified:  bool
    checked_in_at:        Optional[datetime]
    checked_out_at:       Optional[datetime]
    qr_ref:               str
    created_at:           datetime


class CheckInIn(BaseModel):
    badge_number:         str
    visitor_id_verified:  bool = True


class ApprovalIn(BaseModel):
    action:           ApprovalStatus
    rejection_reason: Optional[str] = None
    destination_post_id: Optional[uuid.UUID] = None  # which room/post this visitor is headed to
