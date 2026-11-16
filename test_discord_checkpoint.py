import json
import unittest
from unittest.mock import Mock, patch

from discord_checkpoint import CheckpointError, fetch_checkpoint


def response(data, status=200):
    return Mock(status=status, read=Mock(return_value=json.dumps(data).encode()))


class DiscordTests(unittest.TestCase):
    def fetch(self, changes=None, status=200):
        msg = {"id": "3", "channel_id": "2", "author": {"id": "4"},
               "content": "checkpoint", "edited_timestamp": None}
        msg.update(changes or {})
        replies = [response({"id": "4", "bot": True}), response({"id": "2", "guild_id": "1"}),
                   response(msg, status)]
        with patch.dict("os.environ", {"DISCORD_BOT_TOKEN": "fixture"}), patch("discord_checkpoint.HTTPSConnection") as https:
            conn = https.return_value
            conn.getresponse.side_effect = replies
            try:
                return fetch_checkpoint(("1", "2", "3"))
            finally:
                https.assert_called_once_with("discord.com", timeout=10)
                self.assertEqual([c.args[:2] for c in conn.request.call_args_list],
                                 [("GET", "/api/v10/users/@me"), ("GET", "/api/v10/channels/2"),
                                  ("GET", "/api/v10/channels/2/messages/3")])
                conn.close.assert_called_once()

    def test_reads_original_message(self):
        self.assertEqual(self.fetch(), "checkpoint")

    def test_rejects_untrusted_messages(self):
        for changes in ({"edited_timestamp": "today"}, {"author": {"id": "5"}}, {"webhook_id": "6"},
                        {"channel_id": "9"}, {"id": "9"}, {"content": ""}):
            with self.subTest(changes=changes), self.assertRaises(CheckpointError):
                self.fetch(changes)

    def test_http_errors_stop_verification(self):
        for status in (302, 401, 403, 404, 429, 503):
            with self.subTest(status=status), self.assertRaisesRegex(CheckpointError, str(status)):
                self.fetch(status=status)
