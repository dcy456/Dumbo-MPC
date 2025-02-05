class OptimizedhbmpcError(Exception):
    """Base exception class."""


class ConfigurationError(OptimizedhbmpcError):
    """Raise for configuration errors."""


class BroadcastError(OptimizedhbmpcError):
    """Base class for broadcast errors."""


class RedundantMessageError(BroadcastError):
    """Raised when a rdundant message is received."""


class AbandonedNodeError(OptimizedhbmpcError):
    """Raised when a node does not have enough peer to carry on a distirbuted task."""
