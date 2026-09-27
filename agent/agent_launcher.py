#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def load_state(path):
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_state(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def safe_release(base, version):
    if not VERSION_RE.fullmatch(str(version or "")):
        raise RuntimeError("invalid release version in activation state")
    releases = (base / "releases").resolve()
    target = (releases / version).resolve()
    try:
        target.relative_to(releases)
    except ValueError as exc:
        raise RuntimeError("release path escapes managed release directory") from exc
    if not (target / "patch_agent.py").is_file():
        raise RuntimeError(f"release {version} is incomplete")
    return target


def atomic_current(current, target):
    relative_target = os.path.relpath(target, current.parent)
    tmp = current.parent / (".current.launcher." + str(os.getpid()) + ".tmp")
    tmp.unlink(missing_ok=True)
    os.symlink(relative_target, tmp)
    os.replace(tmp, current)


def current_version(base):
    current = base / "current"
    if not current.is_symlink():
        raise RuntimeError("managed current symlink is missing")
    target = current.resolve(strict=True)
    releases = (base / "releases").resolve()
    try:
        target.relative_to(releases)
    except ValueError as exc:
        raise RuntimeError("managed current symlink escapes release directory") from exc
    return target.name, target


def reconcile_activation(base, state_path, max_attempts):
    state = load_state(state_path)
    status = str(state.get("status") or "")
    if status not in {"switching", "pending"}:
        return state

    current_name, _ = current_version(base)
    target_version = str(state.get("target_version") or "")
    previous_version = str(state.get("previous_version") or "")

    if status == "switching":
        if current_name == target_version:
            state["status"] = "pending"
            state["recovered_switch_state_at"] = utcnow()
        elif current_name == previous_version:
            state["status"] = "aborted_before_switch"
            state["aborted_at"] = utcnow()
            state["last_error"] = "launcher observed switching state before current symlink changed"
            write_state(state_path, state)
            return state
        else:
            raise RuntimeError("activation state does not match current release")

    attempts = int(state.get("attempts") or 0) + 1
    state["attempts"] = attempts
    state["last_attempt_at"] = utcnow()

    if attempts > max_attempts:
        previous = safe_release(base, previous_version)
        atomic_current(base / "current", previous)
        state["status"] = "rolled_back"
        state["rolled_back_at"] = utcnow()
        state["rollback_reason"] = "startup_attempt_limit"
        state["active_version"] = previous_version
        write_state(state_path, state)
        return state

    write_state(state_path, state)
    return state


def main():
    parser = argparse.ArgumentParser(description="Be Safe Patch Agent launcher/watchdog")
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--base",
        default=os.getenv("PATCH_AGENT_BASE", "/opt/patch-manager-agent"),
    )
    parser.add_argument(
        "--activation-state",
        default=os.getenv(
            "PATCH_AGENT_ACTIVATION_STATE",
            "/var/lib/patch-manager/activation.json",
        ),
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=int(os.getenv("PATCH_AGENT_ACTIVATION_MAX_ATTEMPTS", "3")),
    )
    args = parser.parse_args()

    base = Path(args.base).resolve()
    state_path = Path(args.activation_state)
    max_attempts = min(10, max(1, args.max_attempts))

    try:
        reconcile_activation(base, state_path, max_attempts)
        _, release = current_version(base)
        agent = release / "patch_agent.py"
        os.execv(
            sys.executable,
            [
                sys.executable,
                str(agent),
                "--config",
                str(args.config),
            ],
        )
    except Exception as exc:
        state = load_state(state_path)
        state.update({
            "launcher_error_at": utcnow(),
            "launcher_error": str(exc)[:1000],
        })
        write_state(state_path, state)
        print(f"agent launcher error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
