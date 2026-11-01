"""Compatibility facade for device discovery, directory and notifications."""

from whatsapp_e2ee.addressing import (
    DOMAINS,
    account_parts,
    device_address,
    device_jid,
    participant_hash,
    user_account,
)
from whatsapp_e2ee.device_directory import DeviceDirectory
from whatsapp_e2ee.device_discovery import Device, DeviceResult, discovery_request, parse_discovery
from whatsapp_e2ee.device_discovery import _account as _account
from whatsapp_e2ee.device_discovery import _attrs as _attrs
from whatsapp_e2ee.device_discovery import _integer as _integer
from whatsapp_e2ee.device_discovery import _one as _one
from whatsapp_e2ee.device_notifications import (
    DeviceNotification,
    DeviceNotifications,
    DeviceUpdate,
    parse_device_notification,
)

__all__ = [
    "DOMAINS",
    "account_parts",
    "user_account",
    "device_jid",
    "device_address",
    "participant_hash",
    "Device",
    "DeviceResult",
    "discovery_request",
    "parse_discovery",
    "DeviceDirectory",
    "DeviceNotification",
    "DeviceUpdate",
    "DeviceNotifications",
    "parse_device_notification",
]
