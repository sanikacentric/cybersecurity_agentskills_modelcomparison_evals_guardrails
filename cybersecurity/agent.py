"""
agent.py — Root-level entry point. Delegates to agent/agent.py.

Run:
    python agent.py --demo
    python agent.py --demo --model gpt-4o-mini
    python agent.py --demo --routing
"""

# Re-export everything from the package so this file works as a standalone CLI
from agent.agent import SecurityAgent, DEMO_ALERT, _run_agent, _error_result  # noqa: F401

if __name__ == "__main__":
    import argparse, pprint
    parser = argparse.ArgumentParser(description="cybersecurity SOC Agent CLI")
    parser.add_argument("--demo",    action="store_true", help="Run built-in demo alert")
    parser.add_argument("--model",   default="gpt-4o", choices=["gpt-4o", "gpt-4o-mini"])
    parser.add_argument("--routing", action="store_true", help="Use two-pass routing")
    args = parser.parse_args()

    if args.demo:
        print(f"\ncybersecurity Demo - model={args.model}\n")
        agent  = SecurityAgent(model=args.model)
        result = (agent.analyze_with_routing(DEMO_ALERT) if args.routing
                  else agent.analyze(DEMO_ALERT))
        print("\n" + "=" * 60 + "\nTRIAGE RESULT:\n" + "=" * 60)
        pprint.pprint(result)
    else:
        parser.print_help()
