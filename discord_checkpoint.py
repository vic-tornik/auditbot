"""Read a checkpoint posted by the authenticated AuditBot account."""
from argparse import ArgumentTypeError
from getpass import getpass
from http.client import HTTPSConnection, HTTPException
import json
import os
import re
import sys


class CheckpointError(ValueError):
    pass


def message_link(value):
    match = re.fullmatch(
        r"https://discord\.com/channels/([1-9][0-9]{0,19})/([1-9][0-9]{0,19})/([1-9][0-9]{0,19})",
        value,
    )
    if not match or any(int(part) >= 2**64 for part in match.groups()):
        raise ArgumentTypeError("use Copy Message Link on a Discord server message")
    return match.groups()


def get_object(connection, path, headers):
    connection.request("GET", "/api/v10" + path, headers=headers)
    response = connection.getresponse()
    if response.status != 200:
        hints = {401: "check the AuditBot token", 403: "check channel access and message history permissions",
                 404: "the channel or message is unavailable", 429: "wait before trying again"}
        hint = hints.get(response.status, "retry after checking Discord availability")
        raise CheckpointError(f"Discord returned HTTP {response.status}: {hint}.")
    data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise CheckpointError("Discord response exceeded the size limit.")
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CheckpointError("Discord returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise CheckpointError("Unexpected Discord response.")
    return value


def fetch_checkpoint(link):
    guild_id, channel_id, message_id = link
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token and sys.stdin.isatty():
        token = getpass("AuditBot token (hidden): ")
    if not token or not token.isascii() or not token.isprintable() or any(c.isspace() for c in token):
        raise CheckpointError("Supply the AuditBot token locally via the hidden prompt or DISCORD_BOT_TOKEN.")
    headers = {"Authorization": "Bot " + token, "User-Agent": "DiscordBot (https://discord.com, 1.0)"}
    connection = HTTPSConnection("discord.com", timeout=10)
    try:
        bot = get_object(connection, "/users/@me", headers)
        if bot.get("bot") is not True or not isinstance(bot.get("id"), str) or not bot["id"].isdigit():
            raise CheckpointError("Discord did not identify the authenticated bot.")
        channel = get_object(connection, f"/channels/{channel_id}", headers)
        if channel.get("id") != channel_id or channel.get("guild_id") != guild_id:
            raise CheckpointError("Discord channel does not belong to the requested guild.")
        msg = get_object(connection, f"/channels/{channel_id}/messages/{message_id}", headers)
        if msg.get("id") != message_id or msg.get("channel_id") != channel_id:
            raise CheckpointError("Discord message does not match the supplied link.")
        author = msg.get("author")
        if not isinstance(author, dict) or author.get("id") != bot["id"] or msg.get("webhook_id"):
            raise CheckpointError("Checkpoint was not posted by the authenticated AuditBot.")
        if "edited_timestamp" not in msg or msg["edited_timestamp"] is not None:
            raise CheckpointError("Checkpoint requires an original, unedited message.")
        if not isinstance(msg.get("content"), str) or not msg["content"]:
            raise CheckpointError("Checkpoint has no readable text.")
        return msg["content"]
    except (OSError, HTTPException) as exc:
        raise CheckpointError("Could not complete the HTTPS request to Discord.") from exc
    finally:
        connection.close()
