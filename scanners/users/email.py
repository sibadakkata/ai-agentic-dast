"""Pluggable email delivery for invites (v1: manual link only)."""
from __future__ import annotations

from abc import ABC, abstractmethod


class EmailSender(ABC):
    """Send invite emails. v1 uses NullEmailSender; swap for SES/SMTP later."""

    @abstractmethod
    def send_invite(self, to_email: str, invite_url: str, role: str) -> None:
        ...


class NullEmailSender(EmailSender):
    """No-op sender — admin copies the invite URL from the UI."""

    def send_invite(self, to_email: str, invite_url: str, role: str) -> None:
        return None
