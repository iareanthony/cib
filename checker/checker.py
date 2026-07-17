"""
CIB Checker — Compliance in a Box

For each running container image:
  1. Container policy checks (privileged, root user, resource limits, security opts)
  2. SBOM generation via Trivy (CycloneDX) + license compliance
  3. Base image EOL check via endoflife.date
Pushes all results to VictoriaMetrics.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, date, timezone
from pathlib import Path
from urllib.parse import quote

import docker
import requests
import schedule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cib")

_shutdown = threading.Event()


def _handle_sigterm(signum, frame):
    _shutdown.set()


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)

# ── Config ────────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://cib-victoriametrics:8428")
try:
    SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
except ValueError as e:
    logger.error("Invalid SCAN_INTERVAL_HOURS: %s", e)
    sys.exit(1)
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"
try:
    TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "300"))
except ValueError as e:
    logger.error("Invalid TRIVY_TIMEOUT: %s", e)
    sys.exit(1)
ADDITIONAL_IMAGES = [
    i.strip() for i in os.environ.get("ADDITIONAL_IMAGES", "").split(",") if i.strip()
]
SBOM_DIR = Path(os.environ.get("SBOM_DIR", "/data/sboms"))

# Single remote host (backwards-compat). Prefer DOCKER_HOSTS for multi-host.
DOCKER_HOST = os.environ.get("DOCKER_HOST", "")
DISCOVERY_PROVIDER = os.environ.get(
    "DISCOVERY_PROVIDER",
    "docker",
).strip().lower()

if DISCOVERY_PROVIDER not in {"docker", "kubernetes"}:
    logger.error(
        "DISCOVERY_PROVIDER must be 'docker' or 'kubernetes', got %r",
        DISCOVERY_PROVIDER,
    )
    sys.exit(1)

KUBERNETES_CLUSTER_NAME = os.environ.get(
    "KUBERNETES_CLUSTER_NAME",
    "kubernetes",
).strip() or "kubernetes"
# Licenses that violate policy by default (copyleft — problematic for proprietary stacks)
_default_deny = "GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-only,GPL-3.0-or-later,AGPL-3.0-only,AGPL-3.0-or-later"
LICENSE_DENY_LIST = {
    s.strip() for s in os.environ.get("LICENSE_DENY_LIST", _default_deny).split(",") if s.strip()
}

# EOL check: map Trivy OS family names to endoflife.date product names
EOL_PRODUCT_MAP = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "alpine": "alpine",
    "centos": "centos",
    "rhel": "rhel",
    "fedora": "fedora",
    "amazon": "amazon-linux",
    "rockylinux": "rocky-linux",
    "almalinux": "almalinux",
    "sles": "sles",
    "opensuse": "opensuse",
    "oracle": "oracle-linux",
    "photon": "photon",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
}

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "CIB/0.1 (Compliance in a Box)"
SBOM_DIR.mkdir(parents=True, exist_ok=True)


# ── Multi-host parsing ────────────────────────────────────────────────────────

def _parse_docker_hosts() -> list[tuple[str, str]]:
    """Return list of (name, docker_url) to scan.

    Priority:
      1. DOCKER_HOSTS=name1=tcp://host1:port1,name2=tcp://host2:port2
      2. DOCKER_HOST=tcp://host:port  (single host, name="docker")
      3. local socket                 (name="local", url="")
    """
    raw = os.environ.get("DOCKER_HOSTS", "").strip()
    if raw:
        hosts = []
        valid_schemes = ("tcp://", "unix://", "ssh://", "npipe://")
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "=" in entry:
                name, url = entry.split("=", 1)
                name, url = name.strip(), url.strip()
            else:
                name, url = "docker", entry.strip()
            if not name or not url:
                logger.warning("Skipping DOCKER_HOSTS entry with empty name or url: %r", entry)
                continue
            if not url.startswith(valid_schemes):
                logger.warning("Skipping DOCKER_HOSTS entry with invalid scheme: %r", entry)
                continue
            hosts.append((name, url))
        return hosts
    if DOCKER_HOST:
        return [("docker", DOCKER_HOST)]
    return [("local", "")]


# ── Docker client helper ──────────────────────────────────────────────────────

def _docker_client(docker_url: str) -> docker.DockerClient:
    return docker.DockerClient(base_url=docker_url) if docker_url else docker.from_env()


# ── Metric helpers ────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _ts_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _push(lines: list[str]) -> None:
    if not lines:
        return
    payload = "\n".join(lines) + "\n"
    for attempt in range(2):
        try:
            resp = SESSION.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            resp.raise_for_status()
            break
        except requests.exceptions.ConnectionError as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Metric push failed after retry: %s", e)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if 500 <= status < 600 and attempt == 0:
                time.sleep(2)
            else:
                logger.error("Metric push failed (HTTP %s): %s", status, e)
                break
        except Exception as e:
            logger.error("Metric push failed: %s", e)
            break


# ── Docker discovery ──────────────────────────────────────────────────────────

def discover_images(docker_url: str = "", client=None) -> list[str]:
    try:
        if client is None:
            client = _docker_client(docker_url)
        images = set()
        for c in client.containers.list():
            try:
                if c.image and c.image.tags:
                    images.add(c.image.tags[0])
                elif c.image:
                    images.add(c.image.id)
            except Exception:
                continue
        return sorted(images)
    except Exception as e:
        logger.warning("Docker discovery failed: %s", e)
        return []


def get_containers(docker_url: str = "", client=None) -> list[docker.models.containers.Container]:
    try:
        if client is None:
            client = _docker_client(docker_url)
        return client.containers.list()
    except Exception as e:
        logger.warning("Could not list containers: %s", e)
        return []
def discover_kubernetes_inventory() -> tuple[list[str], list[dict]]:
    """Discover running Kubernetes images and container policy records."""
    try:
        from kubernetes import client

        _load_kubernetes_config()

        core_api = client.CoreV1Api()
        apps_api = client.AppsV1Api()
        batch_api = client.BatchV1Api()

        pods = core_api.list_pod_for_all_namespaces(
            field_selector="status.phase=Running",
        )

        replica_sets = {
            (item.metadata.namespace, item.metadata.name): item
            for item in apps_api.list_replica_set_for_all_namespaces().items
        }

        jobs = {
            (item.metadata.namespace, item.metadata.name): item
            for item in batch_api.list_job_for_all_namespaces().items
        }

        images = set()
        containers = []

        for pod in pods.items:
            if not pod.spec:
                continue

            namespace = pod.metadata.namespace or "default"
            workload_kind, workload = _resolve_kubernetes_workload(
                pod,
                replica_sets,
                jobs,
            )

            container_groups = [
                ("container", pod.spec.containers or []),
                ("init", pod.spec.init_containers or []),
                ("ephemeral", pod.spec.ephemeral_containers or []),
            ]

            for container_type, group in container_groups:
                for container in group:
                    if not container.image:
                        continue

                    images.add(container.image)

                    containers.append({
                        "namespace": namespace,
                        "pod": pod.metadata.name,
                        "workload_kind": workload_kind,
                        "workload": workload,
                        "container_type": container_type,
                        "container": container.name,
                        "image": container.image,
                        "checks": check_kubernetes_container_policy(
                            pod,
                            container,
                        ),
                    })
        logger.info(
            "Discovered %d Kubernetes images and %d container records",
            len(images),
            len(containers),
        )
           if namespace in KUBERNETES_EXCLUDED_NAMESPACES:
                continue

            workload_key = f"{namespace}/{workload_kind}/{workload}"

            if workload_key in KUBERNETES_EXCLUDED_WORKLOADS:
                continue
        return sorted(images), containers

    except Exception as e:
        logger.warning("Kubernetes discovery failed: %s", e)
        return [], []

def _load_kubernetes_config():
    """Load in-cluster configuration, falling back to local kubeconfig."""
    from kubernetes import config
    from kubernetes.config.config_exception import ConfigException

    try:
        config.load_incluster_config()
        logger.info("Using in-cluster Kubernetes configuration")
    except ConfigException:
        config.load_kube_config()
        logger.info("Using local kubeconfig")


def _owner_reference(obj):
    references = (
        getattr(getattr(obj, "metadata", None), "owner_references", None)
        or []
    )

    for reference in references:
        if getattr(reference, "controller", False):
            return reference

    return references[0] if references else None


def _resolve_kubernetes_workload(
    pod,
    replica_sets: dict,
    jobs: dict,
) -> tuple[str, str]:
    owner = _owner_reference(pod)

    if owner is None:
        return "Pod", pod.metadata.name

    namespace = pod.metadata.namespace
    kind = owner.kind
    name = owner.name

    if kind == "ReplicaSet":
        replica_set = replica_sets.get((namespace, name))
        parent = _owner_reference(replica_set) if replica_set else None

        if parent:
            return parent.kind, parent.name

    if kind == "Job":
        job = jobs.get((namespace, name))
        parent = _owner_reference(job) if job else None

        if parent and parent.kind == "CronJob":
            return parent.kind, parent.name

    return kind, name


def _effective_security_context(pod, container):
    """Return container security context with pod defaults available."""
    pod_context = pod.spec.security_context
    container_context = container.security_context

    return pod_context, container_context


def check_kubernetes_container_policy(pod, container) -> dict[str, bool]:
    """Evaluate CIS-aligned policy checks for a Kubernetes container."""
    pod_context, container_context = _effective_security_context(
        pod,
        container,
    )

    resources = container.resources
    requests = resources.requests or {} if resources else {}
    limits = resources.limits or {} if resources else {}

    privileged = bool(
        container_context
        and container_context.privileged
    )

    allow_privilege_escalation = (
        container_context.allow_privilege_escalation
        if container_context
        else None
    )

    read_only_rootfs = bool(
        container_context
        and container_context.read_only_root_filesystem
    )

    container_run_as_non_root = (
        container_context.run_as_non_root
        if container_context
        else None
    )

    container_run_as_user = (
        container_context.run_as_user
        if container_context
        else None
    )

    pod_run_as_non_root = (
        pod_context.run_as_non_root
        if pod_context
        else None
    )

    pod_run_as_user = (
        pod_context.run_as_user
        if pod_context
        else None
    )

    run_as_non_root = (
        container_run_as_non_root is True
        or pod_run_as_non_root is True
        or (
            container_run_as_user is not None
            and container_run_as_user != 0
        )
        or (
            container_run_as_user is None
            and pod_run_as_user is not None
            and pod_run_as_user != 0
        )
    )

    capabilities = (
        container_context.capabilities
        if container_context
        else None
    )

    added_capabilities = {
        capability.upper()
        for capability in (
            capabilities.add or []
            if capabilities
            else []
        )
    }

    dangerous_capabilities = {
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "NET_ADMIN",
        "NET_RAW",
    }

        all_checks = {
        "not_privileged": not privileged,
        "non_root_user": run_as_non_root,
        "no_privilege_escalation": allow_privilege_escalation is False,
        "memory_limit": "memory" in limits,
        "cpu_limit": "cpu" in limits,
        "memory_request": "memory" in requests,
        "cpu_request": "cpu" in requests,
        "read_only_rootfs": read_only_rootfs,
        "no_host_network": not bool(pod.spec.host_network),
        "no_host_pid": not bool(pod.spec.host_pid),
        "no_host_ipc": not bool(pod.spec.host_ipc),
        "no_dangerous_capabilities": not bool(
            added_capabilities & dangerous_capabilities
        ),
    }

    return {
        check: passed
        for check, passed in all_checks.items()
        if check in KUBERNETES_ENABLED_CHECKS
     }

KUBERNETES_ENABLED_CHECKS = {
    value.strip()
    for value in os.environ.get(
        "KUBERNETES_ENABLED_CHECKS",
        (
            "not_privileged,"
            "non_root_user,"
            "no_privilege_escalation,"
            "memory_limit,"
            "cpu_limit,"
            "memory_request,"
            "cpu_request,"
            "read_only_rootfs,"
            "no_host_network,"
            "no_host_pid,"
            "no_host_ipc,"
            "no_dangerous_capabilities"
        ),
    ).split(",")
    if value.strip()
}

KUBERNETES_EXCLUDED_NAMESPACES = {
    value.strip()
    for value in os.environ.get(
        "KUBERNETES_EXCLUDED_NAMESPACES",
        "",
    ).split(",")
    if value.strip()
}

KUBERNETES_EXCLUDED_WORKLOADS = {
    value.strip()
    for value in os.environ.get(
        "KUBERNETES_EXCLUDED_WORKLOADS",
        "",
    ).split(",")
    if value.strip()
}


DOCKER_POLICY_CHECKS = [
    "not_privileged",
    "non_root_user",
    "no_new_privileges",
    "memory_limit",
    "cpu_limit",
    "read_only_rootfs",
    "no_host_network",
    "no_host_pid",
]


def check_container_policy(container) -> dict[str, bool]:
    """Return dict of check_name → pass (True=good, False=violation)."""
    hc = container.attrs.get("HostConfig", {})
    cfg = container.attrs.get("Config", {})

    results = {}

    results["not_privileged"] = not hc.get("Privileged", False)

    user = cfg.get("User", "")
    user_id = user.split(":")[0] if user else ""
    results["non_root_user"] = user_id not in ("0", "root", "")

    sec_opts = hc.get("SecurityOpt") or []
    results["no_new_privileges"] = any("no-new-privileges" in o for o in sec_opts)

    results["memory_limit"] = (hc.get("Memory") or 0) > 0

    results["cpu_limit"] = (hc.get("NanoCpus") or 0) > 0 or (hc.get("CpuQuota") or 0) > 0

    results["read_only_rootfs"] = bool(hc.get("ReadonlyRootfs", False))

    results["no_host_network"] = hc.get("NetworkMode", "") != "host"

    results["no_host_pid"] = not hc.get("PidMode", "").startswith("host")

    return results


def push_policy_metrics(container_name: str, checks: dict[str, bool], host: str = "local") -> None:
    ts = _ts_ms()
    lines = []
    passing = 0
    safe_host = _safe_label(host)
    for check, passed in checks.items():
        val = 0 if passed else 1  # 1 = violation
        lines.append(
            f'cib_policy_violation{{container="{_safe_label(container_name)}",'
            f'check="{_safe_label(check)}",host="{safe_host}"}} {val} {ts}'
        )
        if passed:
            passing += 1

    score = (passing / len(checks)) * 100 if checks else 0
    lines.append(
        f'cib_container_policy_score{{container="{_safe_label(container_name)}",'
        f'host="{safe_host}"}} {score:.1f} {ts}'
    )
    _push(lines)

def push_kubernetes_policy_metrics(
    record: dict,
    cluster: str,
) -> int:
    """Push policy metrics for one Kubernetes container."""
    ts = _ts_ms()
    checks = record["checks"]
    lines = []
    passing = 0

    labels = (
        f'cluster="{_safe_label(cluster)}",'
        f'namespace="{_safe_label(record["namespace"])}",'
        f'workload_kind="{_safe_label(record["workload_kind"])}",'
        f'workload="{_safe_label(record["workload"])}",'
        f'pod="{_safe_label(record["pod"])}",'
        f'container_type="{_safe_label(record["container_type"])}",'
        f'container="{_safe_label(record["container"])}",'
        f'image="{_safe_label(record["image"])}"'
    )

    violations = 0

    for check, passed in checks.items():
        value = 0 if passed else 1

        if passed:
            passing += 1
        else:
            violations += 1

        lines.append(
            f'cib_kubernetes_policy_violation{{'
            f'{labels},check="{_safe_label(check)}"'
            f'}} {value} {ts}'
        )

    score = (
        passing / len(checks) * 100
        if checks
        else 0
    )

    lines.append(
        f'cib_kubernetes_policy_score{{{labels}}} '
        f'{score:.1f} {ts}'
    )

    lines.append(
        f'cib_kubernetes_workload_image{{{labels}}} 1 {ts}'
    )

    _push(lines)
    return violations

# ── Trivy SBOM scan ───────────────────────────────────────────────────────────

def scan_sbom(image: str, docker_url: str = "") -> dict | None:
    """Run trivy in CycloneDX mode and return parsed JSON, or None on failure."""
    safe_name = image.replace("/", "_").replace(":", "_")
    out_path = SBOM_DIR / f"{safe_name}.cdx.json"

    cmd = [
        "trivy", "image",
        "--format", "cyclonedx",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--output", str(out_path),
    ]
    if docker_url:
        cmd.extend(["--docker-host", docker_url])
    cmd.append(image)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode != 0:
            logger.warning(
                "trivy sbom exited %d for %s: %s",
                result.returncode, image,
                result.stderr.decode(errors='replace')[:200],
            )
        # still try to parse if output file exists
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return None
        with open(out_path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning("SBOM scan error for %s: %s", image, e)
        return None


def scan_trivy_json(image: str, docker_url: str = "") -> dict | None:
    """Run trivy in JSON mode (for OS metadata + vuln data).

    Trivy returns exit code 1 when vulnerabilities are found — that's still a
    successful scan, so we accept returncodes 0 and 1 and parse stdout either way.
    """
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT}s",
    ]
    if docker_url:
        cmd.extend(["--docker-host", docker_url])
    cmd.append(image)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode not in (0, 1):
            logger.warning(
                "trivy json exited %d for %s: %s",
                result.returncode, image,
                result.stderr.decode(errors='replace')[:200],
            )
        if not result.stdout:
            return None
        return json.loads(result.stdout)
    except Exception as e:
        logger.warning("Trivy JSON scan failed for %s: %s", image, e)
        return None


# ── License compliance ────────────────────────────────────────────────────────

def _split_spdx_expression(expr: str) -> list[str]:
    """Split a simple SPDX expression into individual license identifiers."""
    tokens = [expr]
    for sep in (" OR ", " AND ", " WITH "):
        tokens = [piece for tok in tokens for piece in tok.split(sep)]
    return [t.strip(" ()") for t in tokens if t.strip(" ()")]


def check_licenses(image: str, sbom: dict) -> list[dict]:
    """Return list of license violations: {package, version, license}."""
    violations = []
    for component in sbom.get("components", []):
        name = component.get("name", "")
        version = component.get("version", "")
        for lic_entry in component.get("licenses", []):
            expression = lic_entry.get("expression")
            if expression:
                for lic_id in _split_spdx_expression(expression):
                    if lic_id in LICENSE_DENY_LIST:
                        violations.append({"package": name, "version": version, "license": lic_id})
                continue
            lic = lic_entry.get("license", {})
            lic_id = lic.get("id") or lic.get("name") or ""
            if lic_id in LICENSE_DENY_LIST:
                violations.append({"package": name, "version": version, "license": lic_id})
    return violations


def push_license_metrics(image: str, violations: list[dict], total_components: int, host: str = "local") -> None:
    ts = _ts_ms()
    safe_image = _safe_label(image)
    safe_host = _safe_label(host)
    lines = [
        f'cib_sbom_components_total{{image="{safe_image}",host="{safe_host}"}} {total_components} {ts}',
        f'cib_license_violations_total{{image="{safe_image}",host="{safe_host}"}} {len(violations)} {ts}',
    ]
    for v in violations:
        lines.append(
            f'cib_license_violation{{image="{safe_image}",'
            f'package="{_safe_label(v["package"])}",'
            f'version="{_safe_label(v["version"])}",'
            f'license="{_safe_label(v["license"])}",host="{safe_host}"}} 1 {ts}'
        )
    _push(lines)


# ── EOL check ─────────────────────────────────────────────────────────────────

def _parse_version_cycle(os_name: str) -> str:
    """Extract the major.minor cycle from an OS version string."""
    # Ubuntu: "22.04" → "22.04"; Debian: "12" → "12"; Alpine: "3.19.0" → "3.19"
    parts = os_name.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def check_eol(image: str, trivy_data: dict) -> dict | None:
    """Return EOL info dict if the base OS is EOL or unknown, else None."""
    metadata = trivy_data.get("Metadata", {})
    os_info = metadata.get("OS", {})
    family = (os_info.get("Family") or "").lower()
    os_name = os_info.get("Name") or ""

    if not family or not os_name:
        return None

    product = EOL_PRODUCT_MAP.get(family)
    if not product:
        logger.debug("no EOL data for %s", family)
        return None

    cycle = _parse_version_cycle(os_name)

    try:
        r = SESSION.get(
            f"https://endoflife.date/api/{quote(product)}/{quote(cycle)}.json",
            timeout=10,
        )
        if r.status_code == 404:
            logger.debug("EOL 404 for %s/%s — skipping", product, cycle)
            return None
        if not r.ok:
            return None

        data = r.json()
        eol_raw = data.get("eol")
        if eol_raw is None:
            return None

        if isinstance(eol_raw, bool):
            is_eol = eol_raw
            eol_date = "unknown"
        else:
            try:
                eol_dt = date.fromisoformat(str(eol_raw))
                is_eol = eol_dt <= date.today()
                eol_date = str(eol_raw)
            except ValueError:
                is_eol = False
                eol_date = str(eol_raw)

        return {"family": family, "version": os_name, "cycle": cycle, "eol_date": eol_date, "is_eol": is_eol}

    except Exception as e:
        logger.debug("EOL check failed for %s %s: %s", product, cycle, e)
        return None


def push_eol_metrics(image: str, eol_info: dict | None, host: str = "local") -> None:
    ts = _ts_ms()
    safe_image = _safe_label(image)
    safe_host = _safe_label(host)
    if eol_info is None:
        _push([f'cib_eol_unknown{{image="{safe_image}",host="{safe_host}"}} 1 {ts}'])
        return

    val = 1 if eol_info["is_eol"] else 0
    _push([
        f'cib_image_eol{{image="{safe_image}",'
        f'os="{_safe_label(eol_info["family"])}",'
        f'version="{_safe_label(eol_info["version"])}",'
        f'eol_date="{_safe_label(eol_info["eol_date"])}",host="{safe_host}"}} {val} {ts}'
    ])


# ── Summary metrics ───────────────────────────────────────────────────────────

def push_summary(images_checked: int, containers_checked: int, total_violations: int, eol_count: int) -> None:
    ts = _ts_ms()
    _push([
        f"cib_images_checked_total {images_checked} {ts}",
        f"cib_containers_checked_total {containers_checked} {ts}",
        f"cib_total_policy_violations {total_violations} {ts}",
        f"cib_eol_images_total {eol_count} {ts}",
        f"cib_last_scan_timestamp {ts} {ts}",
    ])


# ── Main scan cycle ───────────────────────────────────────────────────────────

def run_scan() -> None:
    logger.info("─── CIB scan starting ───")
    ts_start = time.time()

    if DISCOVERY_PROVIDER == "kubernetes":
        hosts = [(KUBERNETES_CLUSTER_NAME, "")]
    else:
        hosts = _parse_docker_hosts()

    total_violations = 0
    total_containers = 0
    total_images = 0
    eol_count = 0

    def scan_image_full(
        image: str,
        docker_url: str,
        host_name: str,
    ) -> None:
        nonlocal total_images, eol_count

        logger.info("Scanning image: %s", image)

        trivy_data = scan_trivy_json(image, docker_url)

        eol_info = (
            check_eol(image, trivy_data)
            if trivy_data
            else None
        )

        push_eol_metrics(
            image,
            eol_info,
            host=host_name,
        )

        if eol_info and eol_info["is_eol"]:
            logger.info(
                "  %s — EOL base OS: %s %s (eol: %s)",
                image,
                eol_info["family"],
                eol_info["version"],
                eol_info["eol_date"],
            )
            eol_count += 1

        sbom = scan_sbom(image, docker_url)

        if not sbom:
            push_license_metrics(
                image,
                [],
                0,
                host=host_name,
            )
            return

        total_components = len(sbom.get("components", []))
        violations = check_licenses(image, sbom)

        push_license_metrics(
            image,
            violations,
            total_components,
            host=host_name,
        )

        if violations:
            logger.info(
                "  %s — %d license violations (%s)",
                image,
                len(violations),
                ", ".join(
                    sorted({
                        violation["license"]
                        for violation in violations
                    })
                ),
            )
        else:
            logger.info(
                "  %s — %d components, no license violations",
                image,
                total_components,
            )

        total_images += 1

    if DISCOVERY_PROVIDER == "kubernetes":
        images, kubernetes_containers = (
            discover_kubernetes_inventory()
        )

        total_containers = len(kubernetes_containers)

        for record in kubernetes_containers:
            if _shutdown.is_set():
                logger.info(
                    "Shutdown requested — aborting policy checks"
                )
                break

            failing = [
                check
                for check, passed in record["checks"].items()
                if not passed
            ]

            logger.info(
                "Policy check: %s/%s/%s",
                record["namespace"],
                record["workload"],
                record["container"],
            )

            if failing:
                logger.info(
                    "  policy violations: %s",
                    ", ".join(failing),
                )

            total_violations += (
                push_kubernetes_policy_metrics(
                    record,
                    KUBERNETES_CLUSTER_NAME,
                )
            )

        if not _shutdown.is_set():
            for image in images:
                if _shutdown.is_set():
                    logger.info(
                        "Shutdown requested — aborting image scans"
                    )
                    break

                scan_image_full(
                    image,
                    "",
                    KUBERNETES_CLUSTER_NAME,
                )

        if ADDITIONAL_IMAGES and not _shutdown.is_set():
            logger.info(
                "── Host: additional (extra images) ──"
            )

            for image in ADDITIONAL_IMAGES:
                if _shutdown.is_set():
                    break

                scan_image_full(
                    image,
                    "",
                    "additional",
                )

        push_summary(
            total_images,
            total_containers,
            total_violations,
            eol_count,
        )

        logger.info(
            "─── CIB Kubernetes scan complete in %.0fs: "
            "%d containers, %d images, %d violations ───",
            time.time() - ts_start,
            total_containers,
            total_images,
            total_violations,
        )
        return

    # Docker discovery and policy checks
    for host_name, docker_url in hosts:
        if _shutdown.is_set():
            logger.info(
                "Shutdown requested — aborting scan loop"
            )
            break

        logger.info(
            "── Host: %s (%s) ──",
            host_name,
            docker_url or "local socket",
        )

        try:
            docker_client = _docker_client(docker_url)
        except Exception as exc:
            logger.warning(
                "Could not create Docker client for %s: %s",
                host_name,
                exc,
            )
            docker_client = None

        containers = get_containers(
            docker_url,
            client=docker_client,
        )

        total_containers += len(containers)

        for container in containers:
            if _shutdown.is_set():
                break

            logger.info(
                "Policy check: %s",
                container.name,
            )

            checks = check_container_policy(container)

            failing = [
                check
                for check, passed in checks.items()
                if not passed
            ]

            total_violations += len(failing)

            if failing:
                logger.info(
                    "  %s — policy violations: %s",
                    container.name,
                    ", ".join(failing),
                )

            push_policy_metrics(
                container.name,
                checks,
                host=host_name,
            )

        images = discover_images(
            docker_url,
            client=docker_client,
        )

        for image in images:
            if _shutdown.is_set():
                break

            scan_image_full(
                image,
                docker_url,
                host_name,
            )

    if ADDITIONAL_IMAGES and not _shutdown.is_set():
        logger.info(
            "── Host: additional (extra images) ──"
        )

        for image in ADDITIONAL_IMAGES:
            if _shutdown.is_set():
                break

            scan_image_full(
                image,
                "",
                "additional",
            )

    push_summary(
        total_images,
        total_containers,
        total_violations,
        eol_count,
    )

    logger.info(
        "─── CIB scan complete in %.0fs across %d host(s) ───",
        time.time() - ts_start,
        len(hosts),
    )


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info(
        "CIB checker starting "
        "(provider=%s, interval=%.1fh)",
        DISCOVERY_PROVIDER,
        SCAN_INTERVAL_HOURS,
    )

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(
        SCAN_INTERVAL_HOURS
    ).hours.do(run_scan)

    while not _shutdown.is_set():
        schedule.run_pending()

        if _shutdown.wait(60):
            break

    logger.info(
        "Shutdown signal received, exiting."
    )


if __name__ == "__main__":
    main()
