from __future__ import annotations

import argparse
import asyncio

from honey.support.logging_ext import setup_logging
from network.hbbft_runner import (
    run_local_honeybadger_nodes_multiprocess,
    run_local_honeybadger_nodes_single_process,
)

setup_logging("DEBUG")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local HoneyBadgerBFT nodes")
    parser.add_argument("--sid", type=str, default="local-hbft")
    parser.add_argument("--N", type=int, default=4, help="number of nodes")
    parser.add_argument("--f", type=int, default=1, help="fault tolerance")
    parser.add_argument("--B", type=int, default=1, help="batch size")
    parser.add_argument("--K", type=int, default=1, help="number of rounds")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-round timeout seconds")
    parser.add_argument("--global-timeout", type=float, default=30.0, help="overall timeout")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["multiprocess", "single-process"],
        default="multiprocess",
    )
    return parser.parse_args()


def main() -> None:
    import sys
    import traceback

    try:
        args = _parse_args()
        if args.mode == "single-process":
            nodes = asyncio.run(
                run_local_honeybadger_nodes_single_process(
                    sid=args.sid,
                    num_nodes=args.N,
                    faulty=args.f,
                    batch_size=args.B,
                    max_rounds=args.K,
                    round_timeout=args.timeout,
                )
            )
            rounds = [n.round for n in nodes]
        else:
            rounds = run_local_honeybadger_nodes_multiprocess(
                sid=args.sid,
                num_nodes=args.N,
                faulty=args.f,
                batch_size=args.B,
                max_rounds=args.K,
                round_timeout=args.timeout,
                global_timeout=args.global_timeout,
            )
        print(f"Local HoneyBadgerBFT run finished. Rounds per node: {rounds}")
    except Exception as e:
        import logging

        tb_str = traceback.format_exc()
        print(
            f"[FATAL] Uncaught exception in node process: {e}\n{tb_str}",
            file=sys.stderr,
            flush=True,
        )
        logging.error(f"[FATAL] Uncaught exception in node process: {e}\n{tb_str}")
        for handler in logging.root.handlers:
            handler.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
