from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.ids import new_revision, utcnow
from app.db.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    photo: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    kind: Mapped[str] = mapped_column(String(32), default="personal", nullable=False)
    # Changes in the same transaction as every write that can change a policy decision. The
    # policy engine's cache is used only while it still matches. See policy_revision.py.
    policy_revision: Mapped[Optional[str]] = mapped_column(String(32), default=new_revision, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    agents = relationship("Agent", back_populates="organization")
    tools = relationship("Tool", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    runs = relationship("Run", back_populates="organization")
    users = relationship("User", back_populates="organization")
    employees = relationship("Employee", back_populates="organization")
    invitations = relationship("Invitation", back_populates="organization")
    mcp_servers = relationship("McpServer", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")
