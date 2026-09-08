"""Desktop notification seam for dual-applet card arbitration.

One job: when a card carries both the gate (PIV) and OpenPGP applets,
ask the user which one gets the reader.  Speaks org.freedesktop.
Notifications directly over the session bus (Gio) because notify-send's
--action is unreliable across daemons (libnotify 0.8.6 silently drops
actions on Plasma 6.4.5 even though the daemon advertises and renders
them).  notify-send remains the fallback when Gio is unavailable.  No
desktop (headless boot, SSH session) degrades to "no answer", and the
caller's default applies -- the bridge is a service first.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional

log = logging.getLogger("piv-gate-ui")


def _dbus_env() -> dict:
    """notify-send needs the session bus; user services often run
    without it exported.  The well-known user-bus path is the fallback."""
    env = dict(os.environ)
    env.setdefault(
        "DBUS_SESSION_BUS_ADDRESS",
        f"unix:path=/run/user/{os.getuid()}/bus")
    return env


def notify_ask(title: str, body: str, actions: dict,
               timeout_s: float, **_) -> Optional[str]:
    """Show a notification with buttons; return the chosen action key,
    or None when it expired / was closed / no desktop answered.  The
    caller may pass reader/generation context (ignored here)."""
    try:
        return _gdbus_ask(title, body, actions, timeout_s)
    except Exception as exc:
        log.debug("gdbus ask unavailable: %s", exc)
    return _notify_send_ask(title, body, actions, timeout_s)


def _gdbus_ask(title: str, body: str, actions: dict,
               timeout_s: float) -> Optional[str]:
    """org.freedesktop.Notifications.Notify + ActionInvoked/Notification
    Closed, on a GLib main loop bounded by timeout_s (+3s grace)."""
    import gi
    from gi.repository import Gio, GLib

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    loop = GLib.MainLoop()
    state = {"id": None, "choice": None}

    def on_signal(conn, sender, path, iface, signal, params):
        vals = params.unpack()
        if state["id"] is None or vals[0] != state["id"]:
            return
        if signal == "ActionInvoked":
            state["choice"] = vals[1]
            loop.quit()
        elif signal == "NotificationClosed":
            loop.quit()

    sid = bus.signal_subscribe(
        "org.freedesktop.Notifications", "org.freedesktop.Notifications",
        None, "/org/freedesktop/Notifications", None,
        Gio.DBusSignalFlags.NONE, on_signal)
    try:
        reply = bus.call_sync(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications", "Notify",
            GLib.Variant(
                "(susssasa{sv}i)",
                ("piv-gate", 0, "", title, body,
                 [kv for pair in actions.items() for kv in pair],
                 {}, int(timeout_s * 1000))),
            None, Gio.DBusCallFlags.NONE, 5000, None)
        state["id"] = reply.unpack()[0]
        GLib.timeout_add(int(timeout_s * 1000) + 3000, loop.quit)
        loop.run()
    finally:
        bus.signal_unsubscribe(sid)
        if state["id"] is not None and state["choice"] is None:
            try:  # daemon already closed it on expiry; harmless then
                bus.call_sync(
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications", "CloseNotification",
                    GLib.Variant("(u)", (state["id"],)),
                    None, Gio.DBusCallFlags.NONE, 2000, None)
            except Exception:
                pass
    log.debug("notify_ask -> %r", state["choice"])
    return state["choice"]


def _notify_send_ask(title: str, body: str, actions: dict,
                     timeout_s: float) -> Optional[str]:
    """Fallback for systems without Gio; buttons only if notify-send
    supports --action against the running daemon."""
    argv = ["notify-send",
            f"--expire-time={int(timeout_s * 1000)}",
            "--app-name=piv-gate"]
    for key, label in actions.items():
        argv.append(f"--action={key}={label}")
    argv += [title, body]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout_s + 5, env=_dbus_env())
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("notify_ask unavailable: %s", exc)
        return None
    choice = proc.stdout.strip()
    log.debug("notify_ask -> %r", choice)
    return choice or None


def notify_info(title: str, body: str, timeout_s: float = 10.0) -> None:
    """Fire-and-forget informational notification; failures are silent."""
    argv = ["notify-send",
            f"--expire-time={int(timeout_s * 1000)}",
            "--app-name=piv-gate", title, body]
    try:
        subprocess.run(argv, capture_output=True, timeout=timeout_s + 5,
                       env=_dbus_env())
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("notify_info unavailable: %s", exc)