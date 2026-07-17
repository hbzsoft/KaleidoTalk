# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.

"""Server configuration loader.

Reads config.json from the project root (the directory containing this file).
If the file does not exist, a default configuration is created automatically.
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

# Resolve config.json path relative to this script's directory,
# so it works regardless of the runtime working directory.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # .../src/server
CONFIG_PATH = os.path.join(_BASE_DIR, "..", "..", "config.json")  # project root


def load_config():
    """Load server configuration from config.json.

    The config.json is expected at the project root
    (auto-resolved from the location of this script).
    If the file does not exist, creates it with default values.
    Returns the configuration dict.
    """
    config_path = os.path.abspath(CONFIG_PATH)

    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[Config] Created default configuration: {config_path}")
        return DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        print(f"[Config] Loaded configuration from: {config_path}")
    except (json.JSONDecodeError, OSError) as e:
        print(f"[Config] Failed to load {config_path}: {e}, using defaults")
        return DEFAULT_CONFIG.copy()

    # Merge with defaults to ensure all keys exist
    merged = _deep_merge(DEFAULT_CONFIG.copy(), config)
    host = merged.get("host", "0.0.0.0")
    port = merged.get("port", 5555)
    print(f"[Config] Effective settings → host={host}, port={port}")
    return merged


def _deep_merge(base, override):
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = _deep_merge(base[key].copy(), value)
        else:
            base[key] = value
    return base
