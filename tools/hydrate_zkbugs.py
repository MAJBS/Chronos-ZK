"""
=============================================================================
CHRONOS-ZK: HIDRATADOR QUIRURGICO DEL CORPUS ZKSECURITY/ZKBUGS
Modulo: tools/hydrate_zkbugs.py
Proposito: Lee `zkbugs_config.json` y `circuit.circom` en cada carpeta de
           `benchmarks/zkbugs/dataset/circom/`, copia los circuitos locales
           desde `dependencies/circomlib` o descarga unicamente los archivos
           `.circom` requeridos (pocos KB) desde `raw.githubusercontent.com`
           en el commit vulnerable exacto.
=============================================================================
"""

import json
import os
import re
import shutil
import urllib.request
import urllib.error


def extract_includes(circom_path: str) -> list:
    if not os.path.exists(circom_path):
        return []
    includes = []
    with open(circom_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.search(r'^\s*include\s+"([^"]+)"', line)
            if m:
                inc = m.group(1).strip()
                if not inc.startswith(".."):
                    includes.append(inc)
    return includes


def parse_github_owner_repo(project_url: str):
    clean = project_url.strip().rstrip("/")
    m = re.search(r"github\.com/([^/]+)/([^/]+)", clean)
    if m:
        return m.group(1), m.group(2).replace(".git", "")
    return None, None


def fetch_raw_github_file(owner: str, repo: str, commit: str, rel_path: str, dest_path: str) -> bool:
    rel_clean = rel_path.lstrip("./").replace("\\", "/")
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{rel_clean}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Chronos-ZK-Audit-Hydrator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read()
            os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
            with open(dest_path, "wb") as out_f:
                out_f.write(content)
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return False


def hydrate_zkbugs_dataset(base_dir: str = os.path.join("benchmarks", "zkbugs", "dataset", "circom")):
    if not os.path.exists(base_dir):
        print(f"[ERROR] No existe el directorio: {base_dir}")
        return

    circomlib_dep_dir = os.path.join(base_dir, "dependencies", "circomlib")
    copied_local = 0
    fetched_remote = 0
    already_present = 0

    print("=" * 85)
    print(f"[*] Iniciando hidratacion quirurgica de circuitos en: {base_dir}")
    print("=" * 85)

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d != "dependencies"]
        if "zkbugs_config.json" not in files:
            continue

        cfg_path = os.path.join(root, "zkbugs_config.json")
        entry_circom = os.path.join(root, "circuit.circom")

        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg_data = json.load(f)
        except Exception:
            continue

        # El primer objeto del JSON contiene la configuracion del bug
        bug_info = next(iter(cfg_data.values())) if isinstance(cfg_data, dict) and cfg_data else {}
        if not isinstance(bug_info, dict):
            continue

        project_url = bug_info.get("Project", "")
        commit_hash = bug_info.get("Commit", "")
        loc_info = bug_info.get("Location", {})
        loc_path = loc_info.get("Path", "") if isinstance(loc_info, dict) else ""

        owner, repo = parse_github_owner_repo(project_url)

        needed_rel_paths = set(extract_includes(entry_circom))
        if loc_path and loc_path.endswith(".circom"):
            needed_rel_paths.add(loc_path)

        for rel_p in sorted(needed_rel_paths):
            local_target = os.path.join(root, rel_p)
            if os.path.exists(local_target):
                already_present += 1
                continue

            # 1. Verificar si existe en dependencies/circomlib
            dep_candidate = os.path.join(circomlib_dep_dir, rel_p)
            if os.path.exists(dep_candidate):
                os.makedirs(os.path.dirname(os.path.abspath(local_target)), exist_ok=True)
                shutil.copy2(dep_candidate, local_target)
                copied_local += 1
                print(f"  [LOCAL]  Copiado desde circomlib: {rel_p}")
                continue

            # 2. Descargar el archivo .circom especifico desde GitHub Raw en el commit exacto
            if owner and repo and commit_hash:
                if fetch_raw_github_file(owner, repo, commit_hash, rel_p, local_target):
                    fetched_remote += 1
                    print(f"  [GITHUB] Descargado ({owner}/{repo}@{commit_hash[:7]}): {rel_p}")

                    # Si circuit.circom no tenia un include hacia loc_path, agregarlo o resolver sub-includes
                    sub_includes = extract_includes(local_target)
                    parent_rel_dir = os.path.dirname(rel_p)
                    for sub_inc in sub_includes:
                        sub_rel = os.path.normpath(os.path.join(parent_rel_dir, sub_inc)).replace("\\", "/")
                        sub_target = os.path.join(root, sub_rel)
                        if not os.path.exists(sub_target) and not sub_rel.startswith(".."):
                            if fetch_raw_github_file(owner, repo, commit_hash, sub_rel, sub_target):
                                fetched_remote += 1

    print("=" * 85)
    print(
        f"[+] Hidratacion completada: {copied_local} copiados de circomlib | "
        f"{fetched_remote} descargados de GitHub Raw | {already_present} ya existentes."
    )
    print("=" * 85)


if __name__ == "__main__":
    hydrate_zkbugs_dataset()