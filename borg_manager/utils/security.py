"""
Borg Manager - Security Utilities

Secure passphrase storage using system keyring.
"""

import logging
from typing import Optional

from .constants import KEYRING_SERVICE

logger = logging.getLogger('BorgManager')

# Try to import keyring
HAS_KEYRING = False
try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    logger.info("Keyring not found. Passphrases will be stored in config file.")


def store_passphrase(repo_name: str, passphrase: str) -> bool:
    """Store passphrase securely in system keyring.
    
    Args:
        repo_name: Repository identifier (used as key)
        passphrase: The passphrase to store
        
    Returns:
        True if stored in keyring, False if keyring unavailable
    """
    if not HAS_KEYRING or not passphrase:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, repo_name, passphrase)
        logger.debug(f"Stored passphrase for {repo_name} in keyring")
        return True
    except Exception as e:
        logger.warning(f"Failed to store passphrase in keyring: {e}")
        return False


def retrieve_passphrase(repo_name: str) -> Optional[str]:
    """Retrieve passphrase from system keyring.
    
    Args:
        repo_name: Repository identifier
        
    Returns:
        The passphrase or None if not found/keyring unavailable
    """
    if not HAS_KEYRING:
        return None
    try:
        passphrase = keyring.get_password(KEYRING_SERVICE, repo_name)
        if passphrase:
            logger.debug(f"Retrieved passphrase for {repo_name} from keyring")
        return passphrase
    except Exception as e:
        logger.warning(f"Failed to retrieve passphrase from keyring: {e}")
        return None


def delete_passphrase(repo_name: str) -> bool:
    """Delete passphrase from system keyring.
    
    Args:
        repo_name: Repository identifier
        
    Returns:
        True if deleted, False if not found or keyring unavailable
    """
    if not HAS_KEYRING:
        return False
    try:
        keyring.delete_password(KEYRING_SERVICE, repo_name)
        logger.debug(f"Deleted passphrase for {repo_name} from keyring")
        return True
    except Exception as e:
        logger.debug(f"Failed to delete passphrase from keyring: {e}")
        return False
