"""Small set of domain exceptions with concrete runtime semantics."""


class ProtocolInvariantError(Exception):
    """Raised when local protocol state violates an invariant."""


class RoutingError(ProtocolInvariantError):
    """Raised when a protocol envelope cannot be routed locally."""


class UnknownTagError(RoutingError):
    """Raised when a protocol envelope cannot be dispatched by channel/instance."""


class SerializationError(ProtocolInvariantError):
    """Raised when protocol messages or envelopes cannot be encoded/decoded."""
