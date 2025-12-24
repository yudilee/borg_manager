"""
Borg Manager - Custom Exception Classes

Provides structured exception handling for better error management.
"""


class BorgManagerError(Exception):
    """Base exception for all Borg Manager errors."""
    pass


class ConfigurationError(BorgManagerError):
    """Raised when there's a configuration issue."""
    pass


class ConnectionError(BorgManagerError):
    """Raised when SSH/network connection fails."""
    pass


class BackupError(BorgManagerError):
    """Raised when a backup operation fails."""
    pass


class RestoreError(BorgManagerError):
    """Raised when a restore operation fails."""
    pass


class RepositoryError(BorgManagerError):
    """Raised when there's a repository-related error."""
    pass


class AuthenticationError(BorgManagerError):
    """Raised when authentication fails (SSH key, passphrase, etc.)."""
    pass


class SchedulerError(BorgManagerError):
    """Raised when there's a scheduling-related error."""
    pass


class ValidationError(BorgManagerError):
    """Raised when configuration validation fails."""
    pass
