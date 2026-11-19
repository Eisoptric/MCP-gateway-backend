from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import utcnow
from app.db.database import Base


class McpAllowedHost(Base):
    """A host an organization's admins approved for MCP servers, beside Saturn's own list.

    Only the name is approved. Every connection to it still has to be HTTPS on port 443 and
    resolve to public addresses only, checked again on each request.
    """

    __tablename__ = "mcp_allowed_hosts"
    __table_args__ = (UniqueConstraint("organization_id", "host", name="uq_mcp_allowed_hosts_org_host"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    # Lowercase ASCII (IDNA) form, no trailing dot, at most 253 characters.
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
