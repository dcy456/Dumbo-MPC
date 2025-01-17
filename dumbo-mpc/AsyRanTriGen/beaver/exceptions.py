class BeaverError(Exception):
    """Base exception class."""


class ConfigurationError(BeaverError):
    """Raise for configuration errors."""


class BroadcastError(BeaverError):
    """Base class for broadcast errors."""


class RedundantMessageError(BroadcastError):
    """Raised when a rdundant message is received."""


class AbandonedNodeError(BeaverError):
    """Raised when a node does not have enough peer to carry on a distirbuted task."""
