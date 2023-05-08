#!/usr/bin/env python3
"""Module for encrypting passwords"""

import bcrypt

def hashed_password(password: str) -> bytes:
    """Encrypts a password using a random salt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a password against a hashed password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
