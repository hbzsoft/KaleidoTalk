# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.

"""Server configuration loader.

Reads config.json from the project root. If the file does not exist,
a default configuration is created automatically.
"""

import json
import os

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 5555,
    "interactive": True,
    "log_level": "INFO",
    "max_packet_size": 2048,
    "security": {
        "ip_ban_duration": 3600,
        "register_limit": 10,
        "login_limit": 20,
        "time_window": 60,
        "session_time_window": 300,
        "max_message_size": 10485760,
    },
}

CONFIG_PATH = "config.json"


def load_config():
    """Load server configuration from config.json.

    If the file does not exist, creates it with default values.
    Returns the configuration dict.
    """
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[Config] Created default configuration: {CONFIG_PATH}")
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[Config] Failed to load {CONFIG_PATH}: {e}, using defaults")
        return DEFAULT_CONFIG.copy()

    # Merge with defaults to ensure all keys exist
    merged = _deep_merge(DEFAULT_CONFIG.copy(), config)
    return merged


def _deep_merge(base, override):
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = _deep_merge(base[key].copy(), value)
        else:
            base[key] = value
    return base
