# AuditBot incident reporter

This project checks an existing Discord AuditBot ledger against a checkpoint message posted by the bot. It verifies message origin and edit state, then reports whether the database history matches the external checkpoint.

The source is in `attack_bot.py` and `discord_checkpoint.py`; tests are in `test_attack_bot.py` and `test_discord_checkpoint.py`.

Use it only with a Discord server and AuditBot database you administer. Provide the bot token through the local prompt. Do not commit tokens, the audit database, or checkpoint data.

The project is an incident reporting utility, not a deployed service. Review the command line options in `attack_bot.py` before use.
