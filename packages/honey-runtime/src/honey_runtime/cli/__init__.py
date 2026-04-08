"""Runtime CLI entrypoints."""


def main() -> None:
    from honey_runtime.cli.local import main as local_main

    local_main()


__all__ = ["main"]
