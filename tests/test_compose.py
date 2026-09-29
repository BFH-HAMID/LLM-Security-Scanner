"""docker-compose.yml, its Dockerfiles and .env.example, checked statically (CI runs `docker compose config`)."""

from __future__ import annotations

import importlib
import re
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
COMPOSE_TEXT = (ROOT / "docker-compose.yml").read_text()
SERVICES = COMPOSE["services"]
ENV_EXAMPLE = {
    line.split("=", 1)[0]: line.split("=", 1)[1]
    for line in (ROOT / ".env.example").read_text().splitlines()
    if line and not line.startswith("#") and "=" in line
}
REQUIRED_SECRETS = {"LLMSCAN_API_KEY", "POSTGRES_PASSWORD"}


def test_expected_services_exist():
    assert {
        "postgres",
        "redis",
        "api",
        "worker",
        "target",
        "dashboard",
        "ollama",
        "ollama-pull",
        "target-ollama",
    } <= set(SERVICES)


def test_build_contexts_and_dockerfiles_exist():
    for name, svc in SERVICES.items():
        build = svc.get("build")
        if not build:
            continue
        context = ROOT / build["context"]
        assert context.is_dir(), name
        assert (context / build.get("dockerfile", "Dockerfile")).is_file(), name


def test_every_variable_is_declared_and_secrets_have_no_default():
    used = set(re.findall(r"\$\{([A-Z_]+)(?:[:?-][^}]*)?\}", COMPOSE_TEXT))
    undocumented = used - set(ENV_EXAMPLE) - {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
    assert not undocumented, f"variables missing from .env.example: {undocumented}"
    for secret in REQUIRED_SECRETS:
        refs = re.findall(r"\$\{" + secret + r"([^}]*)\}", COMPOSE_TEXT)
        assert refs and all(r.startswith(":?") for r in refs), (
            f"{secret} must be a required variable, never defaulted"
        )
        assert ENV_EXAMPLE[secret] == "", "secrets must be empty in .env.example"


def test_no_literal_secrets_in_the_compose_file():
    assert not re.search(
        r"(password|secret|api_key|token)\s*[:=]\s*['\"]?[A-Za-z0-9]{8,}", COMPOSE_TEXT, re.I
    )


def test_every_published_port_is_bound_to_the_configurable_local_address():
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("${BIND_ADDR:-127.0.0.1}:"), (
                f"{name} publishes {port} on all interfaces"
            )
    assert ENV_EXAMPLE["BIND_ADDR"] == "127.0.0.1"


def test_depends_on_references_real_services_with_valid_conditions():
    for name, svc in SERVICES.items():
        for dep, spec in svc.get("depends_on", {}).items():
            assert dep in SERVICES, f"{name} -> {dep}"
            assert spec["condition"] in {
                "service_healthy",
                "service_started",
                "service_completed_successfully",
            }
            if spec["condition"] == "service_healthy":
                dep_svc = SERVICES[dep]
                has_check = "healthcheck" in dep_svc or dep in {
                    "api",
                    "dashboard",
                }  # api: healthcheck baked into the image
                assert has_check, f"{name} waits for {dep}, which has no healthcheck"


def test_services_sharing_the_api_image_do_not_inherit_its_healthcheck():
    """The image's HEALTHCHECK probes :8000/api/v1/health; only the API serves that."""
    for name, svc in SERVICES.items():
        if svc.get("image") == "llmscan-api:local" and name != "api":
            assert "healthcheck" in svc, f"{name} would be reported unhealthy"


def test_ollama_services_are_opt_in():
    for name in ("ollama", "ollama-pull", "target-ollama"):
        assert SERVICES[name]["profiles"] == ["ollama"]
    for name in ("postgres", "redis", "api", "worker", "target", "dashboard"):
        assert "profiles" not in SERVICES[name]


def test_the_api_and_worker_share_configuration_and_use_postgres_and_celery():
    for name in ("api", "worker"):
        env = SERVICES[name]["environment"]
        assert (
            env["DATABASE_URL"].startswith("postgresql://llmscan:")
            and "@postgres:5432/" in env["DATABASE_URL"]
        )
        assert env["LLMSCAN_QUEUE"] == "celery" and env["CELERY_BROKER_URL"].startswith(
            "redis://redis:"
        )
    assert SERVICES["api"]["environment"] == SERVICES["worker"]["environment"]
    # nothing but the named allowlist may be expanded into stored configs
    assert SERVICES["api"]["environment"]["LLMSCAN_ENV_ALLOWLIST"] == "${LLMSCAN_ENV_ALLOWLIST:-}"
    assert ENV_EXAMPLE["LLMSCAN_ENV_ALLOWLIST"] == ""


def test_the_dashboard_reaches_the_api_over_the_compose_network_only():
    env = SERVICES["dashboard"]["environment"]
    assert env["LLMSCAN_API_URL"] == "http://api:8000"
    assert not any("localhost" in str(v) for v in env.values())


def test_commands_reference_importable_entry_points():
    assert callable(importlib.import_module("api.main").create_app)
    assert importlib.import_module("api.jobs.celery_app").celery_app.main == "llmscan"
    assert importlib.import_module("targets.vulnerable_app.main").app.title
    assert SERVICES["worker"]["command"][:4] == ["celery", "-A", "api.jobs.celery_app", "worker"]
    assert SERVICES["target"]["command"][1] == "targets.vulnerable_app.main:app"


def test_api_dockerfile_installs_from_a_wheel_and_runs_unprivileged():
    text = (ROOT / "docker" / "api.Dockerfile").read_text()
    assert (
        "USER llmscan" in text
        and "python -m build --wheel" in text
        and "[server,celery,postgres]" in text
    )
    assert "HEALTHCHECK" in text and "EXPOSE 8000" in text
    for copied in re.findall(r"^COPY (?!--from)(\S+)", text, re.M):
        if copied.startswith("--"):
            continue
        assert (ROOT / copied).exists(), copied


def test_dashboard_dockerfile_uses_standalone_output_and_no_baked_secrets():
    text = (ROOT / "dashboard" / "Dockerfile").read_text()
    assert (
        "NEXT_OUTPUT=standalone" in text
        and "USER llmscan" in text
        and 'CMD ["node", "server.js"]' in text
    )
    assert not re.search(r"ENV\s+\S*(KEY|PASSWORD|SECRET|TOKEN)", text)
    assert "standalone" in (ROOT / "dashboard" / "next.config.ts").read_text()


def test_dockerignore_keeps_secrets_and_junk_out_of_the_build_context():
    lines = (ROOT / ".dockerignore").read_text().split()
    assert {".env", ".git", "*.db", ".venv"} <= set(lines)
    dash = (ROOT / "dashboard" / ".dockerignore").read_text().split()
    assert {"node_modules", ".next", ".env*"} <= set(dash)


def test_init_env_script_generates_private_env_files_and_never_overwrites(tmp_path):
    (tmp_path / "scripts").mkdir()
    for f in (".env.example", "scripts/init-env.sh"):
        (tmp_path / f).write_text((ROOT / f).read_text())
    sh = ["sh", str(tmp_path / "scripts" / "init-env.sh")]
    subprocess.run(sh, check=True, capture_output=True)
    env = tmp_path / ".env"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    values = dict(
        line.split("=", 1)
        for line in env.read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    assert len(values["LLMSCAN_API_KEY"]) > 40 and len(values["POSTGRES_PASSWORD"]) >= 32
    assert values["BIND_ADDR"] == "127.0.0.1" and values["LLMSCAN_ENV_ALLOWLIST"] == ""
    first = env.read_text()
    out = subprocess.run(sh, check=True, capture_output=True, text=True).stdout
    assert "already exists" in out and env.read_text() == first
    other = tmp_path / "second"
    other.mkdir()
    (other / "scripts").mkdir()
    for f in (".env.example", "scripts/init-env.sh"):
        (other / f).write_text((ROOT / f).read_text())
    subprocess.run(["sh", str(other / "scripts" / "init-env.sh")], check=True, capture_output=True)
    assert (other / ".env").read_text() != first, "secrets must be random, not fixed"


def test_makefile_targets_referenced_in_docs_exist():
    makefile = (ROOT / "Makefile").read_text()
    for target in ("env", "up", "down", "test", "lint", "typecheck", "seed", "demo", "wheel"):
        assert re.search(rf"^{target}:", makefile, re.M), target
