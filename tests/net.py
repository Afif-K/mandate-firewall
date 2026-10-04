import socket


def free_port() -> int:
    """A TCP port that was free a moment ago. Racy, but fine for local tests."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
