"""promptwall CLI.

  promptwall eval                      # red-team + benign suites; exits 1 on regression
  promptwall check "some text"         # score a single input for injection / sensitive data
  promptwall serve --port 8080         # run the HTTP gateway
"""

from __future__ import annotations

import argparse
import json
import sys

from promptwall.gateway import load_policy


def cmd_eval(args) -> int:
    from promptwall.evaluate import live_report, report, run_attacks, run_benign

    policy = load_policy(args.policy)
    if args.backend:
        from promptwall.backends import get_backend

        backend = get_backend(args.backend)
        alone = [run_attacks(policy, args.attacks, backend, guarded=False) for _ in range(args.trials)]
        guarded = [run_attacks(policy, args.attacks, backend, guarded=True) for _ in range(args.trials)]
        benign = [run_benign(policy, args.benign, backend) for _ in range(args.trials)]
        print(live_report(alone, guarded, benign, backend.name))
        return 0
    attacks = run_attacks(policy, args.attacks)
    benign = run_benign(policy, args.benign)
    print(report(attacks, benign))
    regressions = [o.id for o in attacks if o.landed and not o.known_gap]
    false_pos = [b[0] for b in benign if not b[1]]
    fixed_gaps = [o.id for o in attacks if o.known_gap and not o.landed]
    if fixed_gaps:
        print(f"\nNote: known gaps now stopped (update the corpus): {fixed_gaps}")
    if regressions or false_pos:
        print(f"\nREGRESSION: attacks landing={regressions} false positives={false_pos}")
        return 1
    return 0


def cmd_check(args) -> int:
    from promptwall.guards import injection, sensitive

    s, findings = injection.score(args.text, "input")
    sens = sensitive.find(args.text)
    print(json.dumps({
        "injection_score": s,
        "would_block_as_user_input": s >= load_policy(args.policy)["injection"]["block_threshold"],
        "findings": [f.kind for f in findings + sens],
    }, indent=2))
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("promptwall.server:app", host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptwall", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy", default="policy.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("eval")
    e.add_argument("--attacks", default="eval/attacks.yaml")
    e.add_argument("--benign", default="eval/benign.yaml")
    e.add_argument("--backend", choices=["anthropic", "ollama"],
                   help="Live run against a real model (default: simulated compromised model)")
    e.add_argument("--trials", type=int, default=1, help="Repeat live runs (real models are non-deterministic)")
    e.set_defaults(func=cmd_eval)
    c = sub.add_parser("check")
    c.add_argument("text")
    c.set_defaults(func=cmd_check)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
