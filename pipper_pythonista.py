#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pipper: Hardened Pythonista Package Installer

Single-file package installer for Pythonista/iOS-style environments.

Highlights:
    - No subprocess requirement: pip is invoked in-process with runpy.
    - Preset package menu with numbered selections.
    - PyPI custom install with optional version/specifier.
    - Exact-version top-level hash mode, with safe fallback prompt.
    - Gist installer with strict filename/path/extension checks.
    - Manifest ledger for uninstall/cleanup.
    - Zip-Slip, symlink, entry-count, compression-ratio, and size checks.
    - Ledger corruption recovery and normalization.
    - Small self-test suite.

Important limits:
    - In-process pip is fragile, but necessary on Pythonista/iOS.
    - Hash mode uses --no-deps because pip requires hashes for every dependency.
    - Manifest uninstall cannot perfectly model shared dependency ownership.
"""

from __future__ import print_function

import os
import sys
import json
import time
import re
import runpy
import hashlib
try:
    import importlib.metadata as importlib_metadata
except ImportError:
    importlib_metadata = None
import traceback
import gc
import shutil
import site
from io import BytesIO, StringIO
from zipfile import ZipFile, BadZipFile
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request
from contextlib import contextmanager

try:
    from packaging.version import Version, InvalidVersion
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    from packaging.requirements import Requirement, InvalidRequirement
    _HAS_PACKAGING = True
except Exception:
    _HAS_PACKAGING = False


# =============================================================================
# Configuration
# =============================================================================

PRESET_PACKAGES = {
    "beautifulsoup4": {"desc": "Web scraping library", "version": "4.12.3"},
    "innertube": {"desc": "YouTube InnerTube API client", "version": None},
    "python-telegram-bot": {"desc": "Telegram Bot API wrapper", "version": "20.1"},
    "pytubefix": {"desc": "YouTube video downloader", "version": "8.13.1"},
    "requests": {"desc": "HTTP library", "version": None},
    "tinydb": {"desc": "Lightweight document-based database", "version": None},
    "tqdm": {"desc": "Extensible terminal progress bars", "version": None},
}

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10000
MAX_COMPRESSION_RATIO = 1000
LOG_RETENTION_LIMIT = 50
LEDGER_SCHEMA_VERSION = 2

FALLBACK_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/90/a9/"
    "1ea3a69a51dcc679724e3512fc2aa1668999eed59976f749134eb02229c8/"
    "pip-21.3-py3-none-any.whl"
)
FALLBACK_WHEEL_SHA256 = (
    "4a1de8f97884ecfc10b48fe61c234f7e7dcf4490a37217011ad9369d899ad5a6"
)
_FALLBACK_WHEEL_VERSION = "21.3"

GIST_ALLOWED_EXTENSIONS = {".py", ".whl", ".zip", ".txt", ".md", ".rst"}
GIST_ALLOWED_RAW_PREFIXES = (
    "https://gist.githubusercontent.com/",
    "https://raw.githubusercontent.com/",
)
SAFE_GIST_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ \-]{0,180}$")
TRANSIENT_HTTP_CODES = {429, 500, 502, 503, 504}

PIP_TARGET_PLACEHOLDER = "__PIPPER_TARGET_PLACEHOLDER__"

# Pythonista often ships/loads older pip internals where `pip install --hash`
# is not available or unreliable in in-process runpy mode. Keep hash mode
# disabled by default for compatibility. Users can still verify bootstrap pip
# because that is handled by Pipper itself before extraction.
ENABLE_PIP_REQUIRE_HASHES = False

# Session-only in-memory cache so preflight/hash logic does not fetch the same
# PyPI metadata twice during one install operation. It is intentionally not
# persisted and is reset whenever Pipper restarts.
_PYPI_METADATA_CACHE = {}

# If False, compatibility preflight only prints details when a package looks risky.
VERBOSE_PREFLIGHT = False

# In-process pip can accumulate imported modules/state in a long Pythonista
# session. We do not try to unload pip internals, but we do track usage and
# provide a safe cleanup/status tool.
PIP_RUN_COUNT = 0
PIP_RUN_WARNING_THRESHOLDS = {5, 10, 15, 20}


# =============================================================================
# Display helpers
# =============================================================================

def _banner(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def _section(text):
    print("\n" + text)
    print("-" * min(len(text), 78))


def _notice(text):
    print("ℹ️  " + str(text))


def _warning(text):
    print("⚠️  " + str(text))


def _error(text):
    print("❌ " + str(text))


def _success(text):
    print("✅ " + str(text))


def _prompt_yes_no(prompt_text, default_no=True):
    suffix = " (y/N): " if default_no else " (Y/n): "
    answer = input(prompt_text + suffix).strip().lower()
    if not answer:
        return not default_no
    return answer in ("y", "yes")


def _warn_degraded_validation():
    _warning(
        "'packaging' library not found. Version/specifier validation is running "
        "in degraded regex-only mode. Install 'packaging' for fuller validation."
    )


# =============================================================================
# Path helpers
# =============================================================================

def _real_abs(path):
    return os.path.abspath(os.path.realpath(path))


def _is_inside_or_equal(path, base):
    path_real = _real_abs(path)
    base_real = _real_abs(base)
    return path_real == base_real or path_real.startswith(base_real + os.sep)


def _is_strictly_inside(path, base):
    path_real = _real_abs(path)
    base_real = _real_abs(base)
    return path_real.startswith(base_real + os.sep)


def _safe_join(base, *parts):
    target = _real_abs(os.path.join(base, *parts))
    if not _is_inside_or_equal(target, base):
        raise PermissionError("Security Defended: unsafe path breakout blocked: {}".format(target))
    return target


def _normalize_rel_path(rel_path):
    return os.path.normpath(rel_path).replace("\\", "/")


def _safe_gist_filename(filename):
    if not filename:
        return False
    if "/" in filename or "\\" in filename:
        return False
    if filename in (".", ".."):
        return False
    if filename.startswith("."):
        return False
    return bool(SAFE_GIST_FILENAME_RE.match(filename))


def _replace_file_atomicish(temp_path, final_path):
    """
    Prefer os.replace. Fall back to shutil.move for older/quirky Pythonista builds.
    Both paths are created in the same directory by callers.
    """
    try:
        os.replace(temp_path, final_path)
    except Exception:
        try:
            if os.path.exists(final_path):
                os.remove(final_path)
        except OSError:
            pass
        shutil.move(temp_path, final_path)


def _atomic_write_json(path, data):
    temp_path = path + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    _replace_file_atomicish(temp_path, path)


def _atomic_write_bytes(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temp_path = path + ".tmp"
    with open(temp_path, "wb") as f:
        f.write(data)
    _replace_file_atomicish(temp_path, path)


def _atomic_write_text(path, text):
    _atomic_write_bytes(path, text.encode("utf-8"))


# =============================================================================
# Package identity and requirement validation
# =============================================================================

class PackageIdentity(object):
    @staticmethod
    def canonicalize(name):
        if name is None:
            return ""
        clean = str(name).strip()
        if clean.startswith("gist:"):
            return "gist:{}".format(clean.split(":", 1)[1].strip().lower())
        return re.sub(r"[-_.]+", "-", clean).lower()

    @staticmethod
    def is_valid_name(name):
        if not name:
            return False
        text = str(name).strip()
        if text.startswith("gist:"):
            text = text.replace("gist:", "", 1)
        return bool(re.match(r"^[A-Za-z0-9_\-\.]+$", text))

    @staticmethod
    def is_valid_version(version):
        if not version:
            return True
        text = str(version).strip()
        if _HAS_PACKAGING:
            try:
                if any(ch in text for ch in "<>!=~"):
                    SpecifierSet(text)
                else:
                    Version(text)
                return True
            except (InvalidVersion, InvalidSpecifier):
                return False

        return bool(re.match(r"^[A-Za-z0-9_\.\-\+\!\=\>\<\,\~\s]+$", text))

    @staticmethod
    def is_plain_version(version):
        if not version:
            return False

        text = str(version).strip()
        if text.startswith("=="):
            text = text[2:].strip()

        if not text:
            return False
        if "," in text:
            return False
        if any(text.startswith(op) for op in (">", "<", "!", "~", "=")):
            return False

        if _HAS_PACKAGING:
            try:
                Version(text)
                return True
            except InvalidVersion:
                return False

        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_\.\-\+\!]*$", text))

    @staticmethod
    def normalize_exact_version(version):
        if not version:
            return None
        text = str(version).strip()
        if text.startswith("=="):
            text = text[2:].strip()
        if PackageIdentity.is_plain_version(text):
            return text
        return None

    @staticmethod
    def build_requirement_spec(name, version=None):
        canonical = PackageIdentity.canonicalize(name)
        if not version:
            return canonical

        text = str(version).strip()
        if not text:
            return canonical

        if text.startswith((">", "<", "=", "!", "~")):
            return canonical + text

        return canonical + "==" + text


def _strip_inline_comment(line):
    if "#" not in line:
        return line
    return line.split("#", 1)[0]


def _validate_requirements_line(line):
    clean = _strip_inline_comment(line).strip()

    if not clean:
        return None
    if clean.startswith("-"):
        return None
    if any(token in clean for token in ("@", "://", "git+")):
        return None
    if clean.startswith((".", "/", "~")):
        return None

    if _HAS_PACKAGING:
        try:
            req = Requirement(clean)
            if getattr(req, "url", None):
                return None
            if not PackageIdentity.is_valid_name(req.name):
                _warning("Skipping requirement with invalid package name: {!r}".format(req.name))
                return None
            return PackageIdentity.canonicalize(req.name), clean
        except InvalidRequirement:
            _warning("Skipping invalid requirement line: {!r}".format(clean))
            return None

    base_name = re.split(r"[<=>!~\[]", clean)[0].strip()
    if not PackageIdentity.is_valid_name(base_name):
        _warning("Skipping requirement with invalid package name: {!r}".format(base_name))
        return None

    specifier = clean[len(base_name):].strip()
    if specifier.startswith("["):
        close = specifier.find("]")
        if close == -1:
            _warning("Skipping malformed extras requirement: {!r}".format(clean))
            return None
        specifier = specifier[close + 1:].strip()

    if specifier and not PackageIdentity.is_valid_version(specifier):
        _warning("Skipping requirement with invalid specifier: {!r}".format(clean))
        return None

    return PackageIdentity.canonicalize(base_name), clean


# =============================================================================
# Trust gate
# =============================================================================

class TrustGate(object):
    @staticmethod
    def assert_safe_archive(zip_file, target_base_dir):
        target_base = _real_abs(target_base_dir)
        members = zip_file.infolist()
        total_uncompressed = 0

        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("Security Boundary Exceeded: archive has too many entries.")

        for member in members:
            name = member.filename

            if not name or "\x00" in name:
                raise PermissionError("Security Defended: invalid archive filename blocked.")

            # Block absolute paths and drive prefixes.
            if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
                raise PermissionError("Security Defended: absolute archive path blocked: {}".format(name))

            # Block symlinks based on Unix mode bits.
            if ((member.external_attr >> 16) & 0o170000) == 0o120000:
                raise PermissionError("Security Defended: symlink archive entry blocked: {}".format(name))

            target_path = _real_abs(os.path.join(target_base, name))
            if not _is_inside_or_equal(target_path, target_base):
                raise PermissionError("Security Defended: Zip-Slip path blocked: {}".format(name))

            total_uncompressed += member.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_SIZE_BYTES:
                raise ValueError("Security Boundary Exceeded: archive inflation threshold hit.")

            if member.file_size > 10 * 1024:
                ratio = member.file_size / float(max(member.compress_size, 1))
                if ratio > MAX_COMPRESSION_RATIO:
                    raise ValueError(
                        "Security Defended: high compression bomb ratio: {:.1f}x".format(ratio)
                    )

    @staticmethod
    def assert_safe_download_size(data):
        if len(data) > MAX_FILE_SIZE_BYTES:
            raise ValueError("Network Exception: downloaded payload exceeds configured limit.")

    @staticmethod
    def verify_sha256(data, expected_hex):
        if not expected_hex:
            return True

        computed = hashlib.sha256(data).hexdigest()
        if computed.lower() != expected_hex.lower():
            raise ValueError(
                "Integrity Mismatch: blocked corrupted/intercepted payload.\n"
                "Expected: {}\nComputed: {}".format(expected_hex, computed)
            )
        return True


# =============================================================================
# Ledger
# =============================================================================

class ManifestTracker(object):
    def __init__(self, log_path):
        self.log_path = log_path

    def _empty_ledger(self):
        return {"__schema_version__": LEDGER_SCHEMA_VERSION, "packages": {}}

    def _normalize_package_record(self, value):
        if not isinstance(value, dict):
            value = {}

        history = value.get("history", [])
        if not isinstance(history, list):
            history = []

        manifest_files = value.get("manifest_files", [])
        if not isinstance(manifest_files, list):
            manifest_files = []

        manifest_files = sorted(
            set(_normalize_rel_path(p) for p in manifest_files if isinstance(p, str))
        )

        owners = value.get("owners", {})
        if not isinstance(owners, dict):
            owners = {}

        normalized_owners = {}
        for path, owner_list in owners.items():
            if not isinstance(path, str):
                continue
            if not isinstance(owner_list, list):
                owner_list = []
            normalized_owners[_normalize_rel_path(path)] = sorted(
                set(PackageIdentity.canonicalize(o) for o in owner_list if isinstance(o, str))
            )

        return {
            "history": history[-LOG_RETENTION_LIMIT:],
            "manifest_files": manifest_files,
            "owners": normalized_owners,
        }

    def load_ledger(self):
        if not os.path.exists(self.log_path):
            return self._empty_ledger()

        try:
            with open(self.log_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            backup_path = self.log_path + ".corrupt-{}".format(int(time.time()))
            try:
                os.rename(self.log_path, backup_path)
                _warning("Ledger was corrupted and moved to: {}".format(backup_path))
            except Exception:
                _warning("Ledger was corrupted and could not be backed up: {}".format(e))
            return self._empty_ledger()

        if not isinstance(data, dict):
            return self._empty_ledger()

        if "packages" in data and isinstance(data.get("packages"), dict):
            raw_packages = data.get("packages", {})
        else:
            raw_packages = dict((k, v) for k, v in data.items() if not str(k).startswith("__"))

        packages = {}
        for key, value in raw_packages.items():
            packages[PackageIdentity.canonicalize(key)] = self._normalize_package_record(value)

        return {"__schema_version__": LEDGER_SCHEMA_VERSION, "packages": packages}

    def save_ledger(self, ledger):
        if "packages" not in ledger:
            ledger = {"__schema_version__": LEDGER_SCHEMA_VERSION, "packages": ledger}
        _atomic_write_json(self.log_path, ledger)

    def log_transaction(self, package_name, identity_token, source_channel,
                        status="SUCCESS", written_files=None):
        canonical_key = PackageIdentity.canonicalize(package_name)
        ledger = self.load_ledger()
        packages = ledger.setdefault("packages", {})
        record = self._normalize_package_record(packages.get(canonical_key, {}))

        history = record.get("history", [])
        history.append({
            "source": source_channel,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "version_or_id": identity_token,
            "status": status,
        })
        history = history[-LOG_RETENTION_LIMIT:]

        if written_files is None:
            manifest = record.get("manifest_files", [])
        else:
            manifest = sorted(set(
                _normalize_rel_path(p) for p in written_files if isinstance(p, str)
            ))

        owners = record.get("owners", {})

        # Rebuild ownership for this package to avoid stale owner entries after
        # reinstall/upgrade changes the package's manifest file set.
        cleaned_owners = {}
        for path, owner_list in owners.items():
            if not isinstance(owner_list, list):
                owner_list = []
            filtered = [
                PackageIdentity.canonicalize(owner)
                for owner in owner_list
                if isinstance(owner, str) and PackageIdentity.canonicalize(owner) != canonical_key
            ]
            if filtered:
                cleaned_owners[_normalize_rel_path(path)] = sorted(set(filtered))

        owners = cleaned_owners

        for path in manifest:
            owners_for_path = owners.setdefault(path, [])
            if canonical_key not in owners_for_path:
                owners_for_path.append(canonical_key)
            owners[path] = sorted(set(owners_for_path))

        packages[canonical_key] = {
            "history": history,
            "manifest_files": manifest,
            "owners": owners,
        }
        self.save_ledger(ledger)

    def add_history_only(self, package_name, identity_token, source_channel, status):
        self.log_transaction(package_name, identity_token, source_channel, status, written_files=None)

    def remove_package_record(self, canonical_key):
        canonical_key = PackageIdentity.canonicalize(canonical_key)
        ledger = self.load_ledger()
        packages = ledger.setdefault("packages", {})
        if canonical_key in packages:
            del packages[canonical_key]
            self.save_ledger(ledger)
            return True
        return False


# =============================================================================
# Uninstaller
# =============================================================================

class ManifestUninstaller(object):
    def __init__(self, target_base_dir, tracker, gist_folder_dir=None):
        self.target_base_dir = os.path.normpath(_real_abs(target_base_dir))
        self.tracker = tracker
        self.gist_folder_dir = os.path.normpath(_real_abs(gist_folder_dir)) if gist_folder_dir else None

    def _safe_remove(self, full_path, base_dir):
        norm_path = os.path.normpath(_real_abs(full_path))
        norm_base = os.path.normpath(_real_abs(base_dir))

        if not _is_strictly_inside(norm_path, norm_base):
            raise PermissionError("Security Defended: manifest escape blocked: {}".format(full_path))

        if os.path.isfile(norm_path):
            try:
                os.remove(norm_path)
                return True
            except OSError as e:
                _warning("Unable to remove file {} ({})".format(full_path, e))
        return False

    def _prune_empty_dirs_from_manifest(self, manifest_files, base_dir):
        norm_base = os.path.normpath(_real_abs(base_dir))
        dirs_to_check = set()

        for rel_path in manifest_files:
            parent = os.path.dirname(_normalize_rel_path(rel_path))
            while parent and parent != ".":
                dirs_to_check.add(parent)
                parent = os.path.dirname(parent)

        for rel_dir in sorted(dirs_to_check, key=lambda p: p.count("/"), reverse=True):
            full_dir = os.path.normpath(os.path.join(norm_base, rel_dir))
            if not _is_strictly_inside(full_dir, norm_base):
                continue
            if full_dir == norm_base:
                continue
            if self.gist_folder_dir and full_dir == self.gist_folder_dir:
                continue
            try:
                if os.path.isdir(full_dir) and not os.listdir(full_dir):
                    os.rmdir(full_dir)
            except OSError:
                pass

    def _resolve_manifest_target(self, rel_path):
        rel_path = _normalize_rel_path(rel_path)

        site_target = os.path.normpath(os.path.join(self.target_base_dir, rel_path))
        if _is_strictly_inside(site_target, self.target_base_dir) and os.path.exists(site_target):
            return site_target, self.target_base_dir, "site"

        if self.gist_folder_dir:
            gist_folder_name = os.path.basename(self.gist_folder_dir)
            prefix = gist_folder_name + "/"
            if rel_path.startswith(prefix):
                stripped = rel_path[len(prefix):]
                gist_target = os.path.normpath(os.path.join(self.gist_folder_dir, stripped))
                if _is_strictly_inside(gist_target, self.gist_folder_dir):
                    return gist_target, self.gist_folder_dir, "gist"

        return site_target, self.target_base_dir, "missing"

    def purge_package(self, raw_package_name):
        canonical_key = PackageIdentity.canonicalize(raw_package_name)
        ledger = self.tracker.load_ledger()
        packages = ledger.get("packages", {})

        if canonical_key not in packages:
            _warning("No ledger entry found for: {}".format(raw_package_name))
            return False

        record = packages[canonical_key]
        manifest_files = record.get("manifest_files")

        if not manifest_files or not isinstance(manifest_files, list):
            _warning("No manifest records found for: {}".format(raw_package_name))
            return False

        print("🗑️ Purging {} recorded asset(s) for package: {}...".format(
            len(manifest_files), canonical_key
        ))

        site_manifest = []
        gist_manifest = []
        removed_count = 0

        for rel_path in manifest_files:
            target, base, kind = self._resolve_manifest_target(rel_path)

            if kind == "missing":
                _warning("Manifest target not found, skipping: {}".format(rel_path))
                continue

            if self._safe_remove(target, base):
                removed_count += 1
                if kind == "site":
                    site_manifest.append(_normalize_rel_path(rel_path))
                elif kind == "gist":
                    gist_folder_name = os.path.basename(self.gist_folder_dir)
                    stripped = _normalize_rel_path(rel_path)
                    if stripped.startswith(gist_folder_name + "/"):
                        stripped = stripped[len(gist_folder_name) + 1:]
                    gist_manifest.append(stripped)

        if site_manifest:
            self._prune_empty_dirs_from_manifest(site_manifest, self.target_base_dir)
        if gist_manifest and self.gist_folder_dir:
            self._prune_empty_dirs_from_manifest(gist_manifest, self.gist_folder_dir)

        if canonical_key.startswith("gist:") and self.gist_folder_dir:
            gist_id = canonical_key.split(":", 1)[1]
            specific_gist_dir = os.path.join(self.gist_folder_dir, gist_id)
            if os.path.isdir(specific_gist_dir) and not os.listdir(specific_gist_dir):
                try:
                    os.rmdir(specific_gist_dir)
                    print("🧹 Cleaned empty Gist workspace folder: {}".format(gist_id))
                except OSError:
                    pass

        del packages[canonical_key]
        self.tracker.save_ledger(ledger)
        _success("Package {} removed. Files removed: {}".format(canonical_key, removed_count))
        return True


# =============================================================================
# Runtime and network
# =============================================================================

@contextmanager
def _scoped_sys_path(target_path):
    norm_target = os.path.normpath(target_path)
    current = [os.path.normpath(p) for p in sys.path]
    inserted = False

    if norm_target not in current:
        sys.path.insert(0, norm_target)
        inserted = True

    try:
        yield
    finally:
        if inserted:
            try:
                sys.path.remove(norm_target)
            except ValueError:
                pass


def _urlopen_with_retry(request_target, timeout=15, retries=2):
    last_exc = None

    for attempt in range(retries + 1):
        try:
            return urlopen(request_target, timeout=timeout)
        except (HTTPError, URLError, TimeoutError) as e:
            last_exc = e

            if isinstance(e, HTTPError) and e.code not in TRANSIENT_HTTP_CODES:
                break

            if attempt == retries:
                break

            time.sleep(1.5 ** attempt)

    if last_exc:
        raise last_exc

    raise RuntimeError("Unexpected network exhaustion during connection loop.")


def _read_response_safely(response):
    buffer = BytesIO()
    total = 0

    while True:
        chunk = response.read(4096)
        if not chunk:
            break

        total += len(chunk)
        if total > MAX_FILE_SIZE_BYTES:
            raise ValueError("Network Exception: compressed payload limit breached.")

        buffer.write(chunk)

    return buffer.getvalue()


def _decode_utf8(data, context="payload"):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Could not decode {} as UTF-8.".format(context))


class _TeeStream(object):
    """
    Capture pip output while also showing it live.

    Pythonista users need visible output because network installs can otherwise
    look frozen while stdout/stderr are redirected.

    Some pip/progress versions expect stream-like methods such as isatty().
    Returning False prevents progress-bar TTY behavior that breaks in Pythonista.
    """
    def __init__(self, real_stream):
        self.real_stream = real_stream
        self.buffer = StringIO()
        self.encoding = getattr(real_stream, "encoding", "utf-8")
        self.errors = getattr(real_stream, "errors", "replace")

    def write(self, data):
        self.buffer.write(data)
        try:
            self.real_stream.write(data)
        except Exception:
            pass

    def flush(self):
        try:
            self.real_stream.flush()
        except Exception:
            pass

    def isatty(self):
        return False

    def fileno(self):
        if hasattr(self.real_stream, "fileno"):
            return self.real_stream.fileno()
        raise OSError("No file descriptor available")

    def getvalue(self):
        return self.buffer.getvalue()


def _normalize_pip_args_for_pythonista(args):
    """
    Add Pythonista-friendly pip flags.

    pip progress bars are fragile with Pythonista/in-process streams. The
    --progress-bar off option avoids progress wrappers that expect a real TTY.
    """
    args = list(args)

    if args and args[0] == "install" and "--progress-bar" not in args:
        args = ["install", "--progress-bar", "off"] + args[1:]

    return args


def run_pip_command(args):
    """
    Pythonista-compatible in-process pip runner.

    Subprocess is intentionally not used. Output is shown live and also captured
    internally, so long installs do not look frozen.
    """
    global PIP_RUN_COUNT

    sentinel = object()
    saved_argv = list(sys.argv)
    saved_main = sys.modules.get("__main__", sentinel)
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr

    tee_stdout = _TeeStream(saved_stdout)
    tee_stderr = _TeeStream(saved_stderr)
    sys.stdout = tee_stdout
    sys.stderr = tee_stderr

    ok = False
    error_trace = None

    try:
        args = _normalize_pip_args_for_pythonista(args)
        sys.argv = ["pip"] + list(args)
        runpy.run_module("pip", run_name="__main__", alter_sys=True)
        ok = True
    except SystemExit as sys_exit:
        ok = sys_exit.code == 0 or sys_exit.code is None
    except Exception as e:
        ok = False
        error_trace = "❌ Internal pip execution failed: {}\n{}".format(e, traceback.format_exc())
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass

        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
        sys.argv = saved_argv

        if saved_main is sentinel:
            sys.modules.pop("__main__", None)
        else:
            sys.modules["__main__"] = saved_main

        try:
            gc.collect()
            time.sleep(0.05)
        except Exception:
            pass

    PIP_RUN_COUNT += 1

    if PIP_RUN_COUNT in PIP_RUN_WARNING_THRESHOLDS:
        _warning(
            "Several pip operations have run in this Pythonista session ({}). "
            "For best stability, consider using session cleanup or restarting Pythonista soon.".format(
                PIP_RUN_COUNT
            )
        )

    if error_trace:
        print(error_trace)

    return ok


# =============================================================================
# Filesystem scanning
# =============================================================================

def _scan_directory_state(base_dir):
    state = {}
    norm_base = os.path.normpath(_real_abs(base_dir))

    if not os.path.isdir(norm_base):
        return state

    for root, dirs, files in os.walk(norm_base):
        dirs[:] = [d for d in dirs if d not in ("__pycache__",)]

        for file_name in files:
            full_path = os.path.join(root, file_name)
            rel_path = _normalize_rel_path(os.path.relpath(full_path, norm_base))
            try:
                stat = os.stat(full_path)
                state[rel_path] = (stat.st_mtime, stat.st_size)
            except OSError:
                pass

    return state


def _compute_state_delta(initial_state, post_state):
    changed = []
    for rel_path, meta in post_state.items():
        if rel_path not in initial_state or initial_state[rel_path] != meta:
            changed.append(_normalize_rel_path(rel_path))
    return sorted(set(changed))


# =============================================================================
# pip bootstrap
# =============================================================================

def bootstrap_pip(site_packages_dir):
    """
    Install pinned pip from FALLBACK_WHEEL_URL.

    This intentionally does NOT query PyPI for the latest pip version. Pythonista
    compatibility is better with a known older pip, so the fallback wheel is now
    the primary/bootstrap wheel.
    """
    print("❌ pip missing. Installing pinned pip {}...".format(_FALLBACK_WHEEL_VERSION))

    wheel_url = FALLBACK_WHEEL_URL
    target_sha256 = FALLBACK_WHEEL_SHA256

    try:
        with _urlopen_with_retry(wheel_url, timeout=30) as resp:
            wheel_bytes = _read_response_safely(resp)

        TrustGate.assert_safe_download_size(wheel_bytes)
        TrustGate.verify_sha256(wheel_bytes, target_sha256)

        print("🛡️ Cryptographic pinned pip verification complete.")

        with ZipFile(BytesIO(wheel_bytes)) as zip_ref:
            TrustGate.assert_safe_archive(zip_ref, site_packages_dir)
            zip_ref.extractall(site_packages_dir)

        _success(
            "Pinned pip {} installed. Restart Pythonista to clear interpreter state.".format(
                _FALLBACK_WHEEL_VERSION
            )
        )
    except Exception as e:
        raise RuntimeError("Critical execution error during bootstrap phase: {}".format(e))


# =============================================================================
# PyPI install
# =============================================================================

def _fetch_pypi_metadata(canonical_name):
    canonical_name = PackageIdentity.canonicalize(canonical_name)

    if canonical_name in _PYPI_METADATA_CACHE:
        return _PYPI_METADATA_CACHE[canonical_name]

    url = "https://pypi.org/pypi/{}/json".format(canonical_name)
    with _urlopen_with_retry(url, timeout=15) as resp:
        meta_json = json.loads(_decode_utf8(_read_response_safely(resp), "PyPI metadata"))

    _PYPI_METADATA_CACHE[canonical_name] = meta_json
    return meta_json


def _select_release_version_from_metadata(meta_json, version=None):
    """
    Best-effort release selector for compatibility warnings.

    Exact versions are used directly. Range constraints are intentionally not
    fully resolved here; for those, use PyPI's reported latest version.
    """
    if version:
        exact = PackageIdentity.normalize_exact_version(version)
        if exact:
            return exact

    return meta_json.get("info", {}).get("version")


def _classify_pypi_release_files(files):
    has_pure_wheel = False
    has_any_wheel = False
    has_sdist = False
    wheel_names = []
    sdist_names = []

    for asset in files or []:
        filename = asset.get("filename", "")
        packagetype = asset.get("packagetype", "")

        if packagetype == "bdist_wheel" or filename.endswith(".whl"):
            has_any_wheel = True
            wheel_names.append(filename)
            if "none-any.whl" in filename:
                has_pure_wheel = True

        if packagetype == "sdist" or filename.endswith((".tar.gz", ".zip", ".tar.bz2")):
            has_sdist = True
            sdist_names.append(filename)

    return {
        "has_pure_wheel": has_pure_wheel,
        "has_any_wheel": has_any_wheel,
        "has_sdist": has_sdist,
        "wheel_names": wheel_names,
        "sdist_names": sdist_names,
    }


def _warn_pypi_compatibility(pkg_name, version=None, install_deps=True):
    """
    Warn when the selected package release appears source-only or platform-wheel-only.

    This is a best-effort preflight for Pythonista. It does not resolve
    dependencies, but it catches many likely failures before pip starts.
    """
    canonical = PackageIdentity.canonicalize(pkg_name)

    try:
        meta_json = _fetch_pypi_metadata(canonical)
    except Exception as e:
        _warning("Could not check PyPI compatibility for {}: {}".format(canonical, e))
        return True

    release_version = _select_release_version_from_metadata(meta_json, version)
    releases = meta_json.get("releases", {})

    if not release_version or release_version not in releases:
        return True

    classification = _classify_pypi_release_files(releases.get(release_version, []))

    risky = False
    warning_lines = []

    if not classification["has_pure_wheel"]:
        risky = True
        if classification["has_any_wheel"]:
            warning_lines.append(
                "Only platform-specific wheels were found. They may not work on Pythonista/iOS."
            )
        elif classification["has_sdist"]:
            warning_lines.append(
                "No wheel found; pip may try a source build, which usually fails on iOS."
            )
        else:
            warning_lines.append("No usable distribution files were detected for this release.")

    if VERBOSE_PREFLIGHT or risky:
        print("\n🔎 Compatibility preflight for {}=={}:".format(canonical, release_version))
        print("   Pure Python wheel: {}".format("yes" if classification["has_pure_wheel"] else "no"))
        print("   Any wheel: {}".format("yes" if classification["has_any_wheel"] else "no"))
        print("   Source distribution: {}".format("yes" if classification["has_sdist"] else "no"))
        print("   Dependencies: {}".format("auto" if install_deps else "manual / --no-deps"))

    for line in warning_lines:
        _warning(line)

    if install_deps and (VERBOSE_PREFLIGHT or risky):
        _notice(
            "Dependency packages are not fully resolved in this preflight. "
            "A dependency may still be source-only and fail."
        )

    if risky:
        return _prompt_yes_no("Continue anyway?", default_no=True)

    return True


def _fetch_pypi_hashes_for_exact_version(canonical_name, exact_version=None):
    try:
        meta_json = _fetch_pypi_metadata(canonical_name)
        target_version = exact_version or meta_json.get("info", {}).get("version")

        if not target_version:
            return None, None

        releases = meta_json.get("releases", {})
        if target_version not in releases:
            _warning("Version '{}' not found for {}.".format(target_version, canonical_name))
            return None, None

        hashes = []
        for asset in releases[target_version]:
            digest = asset.get("digests", {}).get("sha256")
            if digest:
                hashes.append("sha256:" + digest)

        return target_version, hashes if hashes else None

    except Exception as e:
        _warning("Could not fetch PyPI hashes for {}: {}".format(canonical_name, e))
        return None, None


def _can_hash_pin_top_level(version):
    if not version:
        return True
    return PackageIdentity.is_plain_version(version)


def _replace_target_placeholder(args, site_packages_dir):
    return [site_packages_dir if item == PIP_TARGET_PLACEHOLDER else item for item in args]


def _build_pip_args_for_pypi_package(canonical_name, version=None, allow_hashes=True, install_deps=True):
    if version and not PackageIdentity.is_valid_version(version):
        raise ValueError("Invalid version or specifier syntax.")

    exact_version = PackageIdentity.normalize_exact_version(version) if version else None

    if allow_hashes and not ENABLE_PIP_REQUIRE_HASHES:
        _warning(
            "Strict pip --hash mode is disabled for Pythonista compatibility. "
            "Installing normally instead."
        )
        allow_hashes = False

    if allow_hashes and _can_hash_pin_top_level(version):
        resolved_version, hashes = _fetch_pypi_hashes_for_exact_version(canonical_name, exact_version)

        if hashes and resolved_version:
            print("🛡️ Retrieved {} hash constraint(s) for {}=={}.".format(
                len(hashes), canonical_name, resolved_version
            ))
            _notice("Hash mode uses --no-deps. Install dependencies separately if needed.")

            pkg_spec = "{}=={}".format(canonical_name, resolved_version)
            hash_args = []
            for h in hashes:
                hash_args.extend(["--hash", h])

            args = [
                "install",
                "--upgrade",
                "--target",
                PIP_TARGET_PLACEHOLDER,
                "--no-compile",
                "--no-deps",
                "--require-hashes",
                pkg_spec,
            ] + hash_args

            return args, resolved_version, True

    if version and not PackageIdentity.is_plain_version(version):
        _warning(
            "Version specifier '{}' is a range/constraint and cannot be hash-pinned. "
            "Installing without hash verification.".format(version)
        )

    pkg_spec = PackageIdentity.build_requirement_spec(canonical_name, version)
    args = [
        "install",
        "--upgrade",
        "--target",
        PIP_TARGET_PLACEHOLDER,
        "--no-compile",
    ]

    if not install_deps:
        args.append("--no-deps")

    args.append(pkg_spec)
    return args, version or "latest", False


def _extract_requirement_from_pip_args(args):
    """
    Return the package requirement from a pip install arg list for display.

    This avoids accidentally printing a trailing --hash value.
    """
    skip_next = {
        "--target",
        "--hash",
        "-t",
        "-i",
        "--index-url",
        "--extra-index-url",
    }

    options_without_values = {
        "install",
        "--upgrade",
        "--no-compile",
        "--no-deps",
        "--require-hashes",
    }

    idx = 0
    candidates = []

    while idx < len(args):
        item = args[idx]

        if item in skip_next:
            idx += 2
            continue

        if item in options_without_values:
            idx += 1
            continue

        if item.startswith("-"):
            idx += 1
            continue

        candidates.append(item)
        idx += 1

    for candidate in candidates:
        if candidate != PIP_TARGET_PLACEHOLDER and not candidate.startswith("sha256:"):
            return candidate

    return candidates[-1] if candidates else "(unknown package)"


def _run_pip_install_with_optional_hash_retry(pip_args, hash_mode, site_packages_dir):
    pip_args = _replace_target_placeholder(pip_args, site_packages_dir)
    ok = run_pip_command(pip_args)

    if ok:
        return True, pip_args

    if not hash_mode:
        return False, pip_args

    _warning("Hash-verified install failed. This can happen when dependencies are missing.")
    if not _prompt_yes_no("Retry same package without hash mode and with dependencies allowed?", default_no=True):
        return False, pip_args

    # Rebuild a non-hash command from the package spec. The package spec appears
    # immediately after --require-hashes in the hash command.
    try:
        pkg_spec = pip_args[pip_args.index("--require-hashes") + 1]
    except Exception:
        return False, pip_args

    fallback_args = [
        "install",
        "--upgrade",
        "--target",
        site_packages_dir,
        "--no-compile",
        pkg_spec,
    ]

    return run_pip_command(fallback_args), fallback_args


def install_pypi_package(pkg_name, site_packages_dir, tracker, version=None, allow_hashes=True, install_deps=True, preflight=True):
    if not PackageIdentity.is_valid_name(pkg_name):
        _error("Input validation boundary error: invalid package name.")
        return False

    if version and not PackageIdentity.is_valid_version(version):
        _error("Input validation boundary error: invalid version/specifier.")
        return False

    canonical_name = PackageIdentity.canonicalize(pkg_name)

    if preflight:
        if not _warn_pypi_compatibility(canonical_name, version=version, install_deps=install_deps):
            _warning("Install cancelled by compatibility preflight.")
            return False

    try:
        pip_args, identity_token, hash_mode = _build_pip_args_for_pypi_package(
            canonical_name,
            version=version,
            allow_hashes=allow_hashes,
            install_deps=install_deps,
        )
    except Exception as e:
        _error("Could not prepare pip install command: {}".format(e))
        return False

    initial_state = _scan_directory_state(site_packages_dir)

    preview_args = _replace_target_placeholder(pip_args, site_packages_dir)
    pkg_preview = _extract_requirement_from_pip_args(preview_args)
    print("⬇️ Transmitting installation call for package: {}".format(pkg_preview))

    ok, final_args = _run_pip_install_with_optional_hash_retry(pip_args, hash_mode, site_packages_dir)

    if ok:
        post_state = _scan_directory_state(site_packages_dir)
        written = _compute_state_delta(initial_state, post_state)
        source = "pypi-hash" if hash_mode and "--require-hashes" in final_args else "pypi"
        if "--no-deps" in final_args and source == "pypi":
            source = "pypi-no-deps"
        tracker.log_transaction(canonical_name, identity_token, source, "SUCCESS", written)
        _success("Install recorded in ledger: {}".format(canonical_name))
        return True

    tracker.add_history_only(canonical_name, identity_token, "pypi", "FAILED")
    _error("pip reported failure for: {}".format(canonical_name))
    return False


# =============================================================================
# Gist install
# =============================================================================

def _parse_gist_id(gist_target):
    """
    Accepts:
        - raw 32 hex Gist id
        - https://gist.github.com/user/<32hex>
        - https://gist.github.com/user/<32hex>/...
        - https://gist.github.com/<32hex>
        - gist:<32hex>

    Also keeps compatibility with older numeric-looking ids accepted previously.
    """
    text = gist_target.strip()

    if text.startswith("gist:"):
        text = text.split(":", 1)[1].strip()

    direct = re.match(r"^([a-fA-F0-9]{32}|[0-9]{5,})$", text)
    if direct:
        return direct.group(1)

    patterns = [
        r"gist\.github\.com/[^/\s]+/([a-fA-F0-9]{32}|[0-9]{5,})(?:[/?#]|$)",
        r"gist\.github\.com/([a-fA-F0-9]{32}|[0-9]{5,})(?:[/?#]|$)",
        r"/gists?/([a-fA-F0-9]{32}|[0-9]{5,})(?:[/?#]|$)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)

    return None


def _fetch_gist_payload(gist_id):
    api_req = Request(
        "https://api.github.com/gists/{}".format(gist_id),
        headers={"User-Agent": "Pythonista-Pipper"},
    )
    with _urlopen_with_retry(api_req, timeout=15) as resp:
        return json.loads(_decode_utf8(_read_response_safely(resp), "Gist metadata"))


def _download_gist_file(raw_url):
    if not any(raw_url.startswith(prefix) for prefix in GIST_ALLOWED_RAW_PREFIXES):
        raise PermissionError(
            "Security Defended: Gist raw_url points to unexpected host: {}".format(raw_url)
        )

    with _urlopen_with_retry(
        Request(raw_url, headers={"User-Agent": "Pythonista-Pipper"}),
        timeout=30,
    ) as resp:
        data = _read_response_safely(resp)

    TrustGate.assert_safe_download_size(data)
    return data


def _write_gist_file(install_path, filename, data):
    if not _safe_gist_filename(filename):
        raise PermissionError("Security Defended: unsafe Gist filename blocked: {}".format(filename))

    target = _safe_join(install_path, filename)
    _atomic_write_bytes(target, data)
    return target


def _install_gist_archive(file_data, filename, install_path, site_packages_dir):
    try:
        with ZipFile(BytesIO(file_data)) as arch:
            TrustGate.assert_safe_archive(arch, site_packages_dir)
    except BadZipFile:
        raise ValueError("Gist archive is not a valid zip/wheel: {}".format(filename))

    tmp_arch = _write_gist_file(install_path, filename, file_data)

    try:
        return run_pip_command([
            "install",
            "--upgrade",
            "--target",
            site_packages_dir,
            "--no-compile",
            tmp_arch,
        ])
    finally:
        try:
            os.remove(tmp_arch)
        except OSError:
            pass


def _prompt_gist_requirements_consent(requirements):
    print("\n⚠️ SECURITY DISCLOSURE: This Gist contains requirements.txt dependencies:")
    supported = []

    for line in requirements:
        parsed = _validate_requirements_line(line)
        if parsed is None:
            continue
        _, clean = parsed
        supported.append(clean)
        print("   • {}".format(clean))

    if not supported:
        print("   (No supported requirement lines found.)")
        return False

    return _prompt_yes_no("Proceed with installing these dependencies?", default_no=True)


def install_gist_package(gist_url, site_packages_dir, tracker, gist_folder_dir):
    gist_id = _parse_gist_id(gist_url)
    if not gist_id:
        _error("Malformed Gist locator target identity path string.")
        return False

    install_path = _safe_join(gist_folder_dir, gist_id)
    transaction_status = "SUCCESS"
    site_initial = None
    gist_initial = None

    try:
        payload = _fetch_gist_payload(gist_id)
        files = payload.get("files", {})

        if not files:
            _warning("Gist contained no files.")
            return False

        print("\n⚠️ SECURITY DISCLOSURE: Gist files can contain arbitrary executable code:")
        for fname in sorted(files.keys()):
            print("   • {}".format(fname))

        if not _prompt_yes_no("Proceed with processing remote asset collection?", default_no=True):
            return False

        os.makedirs(install_path, exist_ok=True)

        site_initial = _scan_directory_state(site_packages_dir)
        gist_initial = _scan_directory_state(install_path)

        requirements = None

        with _scoped_sys_path(install_path):
            for filename, meta in sorted(files.items()):
                if not _safe_gist_filename(filename):
                    _warning("Skipping unsafe Gist filename: {}".format(filename))
                    continue

                raw_url = meta.get("raw_url")
                if not raw_url:
                    continue

                file_ext = os.path.splitext(filename)[1].lower()
                if file_ext not in GIST_ALLOWED_EXTENSIONS:
                    _warning("Skipping unsupported Gist file type: {}".format(filename))
                    continue

                file_data = _download_gist_file(raw_url)

                if filename.lower() == "requirements.txt":
                    requirements = _decode_utf8(file_data, "requirements.txt").splitlines()
                    _write_gist_file(install_path, filename, file_data)
                    continue

                if file_ext == ".py":
                    _write_gist_file(install_path, filename, file_data)
                    continue

                if file_ext in (".whl", ".zip"):
                    ok = _install_gist_archive(file_data, filename, install_path, site_packages_dir)
                    if not ok:
                        transaction_status = "PARTIAL"
                    continue

                _write_gist_file(install_path, filename, file_data)

            if requirements:
                # Note: requirements-installed dependency ownership is not tracked separately.
                if _prompt_gist_requirements_consent(requirements):
                    for line in requirements:
                        parsed = _validate_requirements_line(line)
                        if parsed is None:
                            continue
                        _, clean_line = parsed
                        ok = run_pip_command([
                            "install",
                            "--upgrade",
                            "--target",
                            site_packages_dir,
                            "--no-compile",
                            clean_line,
                        ])
                        if not ok:
                            transaction_status = "PARTIAL"
                else:
                    print("⏭️ Skipping requirements.txt installation as requested.")

        site_post = _scan_directory_state(site_packages_dir)
        gist_post = _scan_directory_state(install_path)

        delta_site = _compute_state_delta(site_initial, site_post)
        gist_folder_name = os.path.basename(gist_folder_dir)
        delta_gist = [
            _normalize_rel_path(os.path.join(gist_folder_name, gist_id, p))
            for p in _compute_state_delta(gist_initial, gist_post)
        ]

        tracker.log_transaction(
            "gist:{}".format(gist_id),
            gist_id,
            "gist",
            transaction_status,
            sorted(set(delta_site + delta_gist)),
        )

        if transaction_status == "SUCCESS":
            _success("Gist install completed and recorded.")
        else:
            _warning("Gist install completed partially and was recorded as PARTIAL.")

        return transaction_status == "SUCCESS"

    except Exception as e:
        _error("Error during Gist evaluation cycle: {}".format(e))

        if site_initial is not None:
            try:
                site_post = _scan_directory_state(site_packages_dir)
                gist_post = _scan_directory_state(install_path) if os.path.isdir(install_path) else {}
                gist_folder_name = os.path.basename(gist_folder_dir)

                delta_site = _compute_state_delta(site_initial, site_post)
                delta_gist = [
                    _normalize_rel_path(os.path.join(gist_folder_name, gist_id, p))
                    for p in _compute_state_delta(gist_initial or {}, gist_post)
                ]

                failed_key = "gist:{}".format(gist_id)
                tracker.log_transaction(
                    failed_key,
                    gist_id,
                    "gist",
                    "FAILED",
                    sorted(set(delta_site + delta_gist)),
                )
                _warning("Partial install state recorded.")

                if _prompt_yes_no("Remove partial failed Gist files now?", default_no=False):
                    try:
                        cleanup_uninstaller = ManifestUninstaller(
                            site_packages_dir,
                            tracker,
                            gist_folder_dir=gist_folder_dir,
                        )
                        cleanup_uninstaller.purge_package(failed_key)
                    except Exception as cleanup_err:
                        _warning("Immediate cleanup failed: {}".format(cleanup_err))
                        _warning("You can still use uninstall from the main menu later.")
                else:
                    _warning("Partial files kept. Use uninstall from the main menu to clean up later.")

            except Exception as log_err:
                _warning("Ledger update after failure also failed: {}".format(log_err))

        return False



# =============================================================================
# Existing package discovery / ledger import
# =============================================================================

def _read_metadata_headers(meta_path):
    """
    Read simple RFC822-style metadata headers from METADATA or PKG-INFO.

    Returns a dict with lowercase keys.
    """
    headers = {}

    try:
        try:
            f = open(meta_path, "r", encoding="utf-8", errors="ignore")
        except TypeError:
            f = open(meta_path, "r")

        with f:
            for line in f:
                if not line.strip():
                    break

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key and key not in headers:
                    headers[key] = value

                if "name" in headers and "version" in headers:
                    # Keep reading is unnecessary for discovery.
                    break

    except Exception:
        pass

    return headers


def _safe_record_path_to_relpath(record_entry, dist_info_rel_dir, site_packages_dir):
    """
    Convert a RECORD path entry to a normalized site-packages relative path.

    RECORD paths should be relative to site-packages. For imported packages,
    absolute RECORD entries are rejected entirely because accepting them creates
    ambiguity and can make tests/environment-specific paths look safe.
    """
    if not record_entry:
        return None

    entry = record_entry.strip().replace("\\", "/")

    if not entry or "\x00" in entry:
        return None

    # Reject absolute paths outright. RECORD entries should be relative.
    if os.path.isabs(entry) or re.match(r"^[A-Za-z]:", entry):
        return None

    # Reject traversal before joining.
    norm_entry = os.path.normpath(entry).replace("\\", "/")
    if norm_entry == ".":
        return None
    if norm_entry == ".." or norm_entry.startswith("../"):
        return None
    if "/../" in "/" + norm_entry + "/":
        return None

    site_base = _real_abs(site_packages_dir)
    candidate = _real_abs(os.path.join(site_base, norm_entry))
    if not _is_inside_or_equal(candidate, site_base):
        return None

    rel = _normalize_rel_path(os.path.relpath(candidate, site_base))
    if rel == ".." or rel.startswith("../"):
        return None

    return rel


def _read_dist_info_record(record_path, dist_info_rel_dir, site_packages_dir):
    """
    Read a wheel RECORD file and return existing relative file paths.

    csv is imported here to keep startup imports minimal.
    """
    import csv

    result = []

    try:
        try:
            f = open(record_path, "r", encoding="utf-8", errors="ignore", newline="")
        except TypeError:
            f = open(record_path, "r")

        with f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue

                rel_path = _safe_record_path_to_relpath(row[0], dist_info_rel_dir, site_packages_dir)
                if not rel_path:
                    continue

                full_path = os.path.join(site_packages_dir, rel_path)
                if os.path.exists(full_path):
                    result.append(rel_path)

    except Exception as e:
        _warning("Could not read RECORD {}: {}".format(record_path, e))

    return sorted(set(result))


def _guess_top_level_files_from_metadata(site_packages_dir, metadata_dir, package_name):
    """
    Fallback when RECORD is missing.

    This is intentionally conservative. It uses top_level.txt if available,
    otherwise guesses from the normalized package name.
    """
    result = []
    candidate_names = []

    top_level_path = os.path.join(metadata_dir, "top_level.txt")
    if os.path.exists(top_level_path):
        try:
            try:
                f = open(top_level_path, "r", encoding="utf-8", errors="ignore")
            except TypeError:
                f = open(top_level_path, "r")

            with f:
                for line in f:
                    item = line.strip()
                    if item and PackageIdentity.is_valid_name(item):
                        candidate_names.append(item)
        except Exception:
            pass

    canonical = PackageIdentity.canonicalize(package_name)
    candidate_names.append(canonical.replace("-", "_"))
    candidate_names.append(canonical.replace("-", ""))

    for name in sorted(set(candidate_names)):
        if not name:
            continue

        package_dir = os.path.join(site_packages_dir, name)
        package_file = os.path.join(site_packages_dir, name + ".py")

        if os.path.isdir(package_dir):
            for root, _, files in os.walk(package_dir):
                for filename in files:
                    full = os.path.join(root, filename)
                    result.append(_normalize_rel_path(os.path.relpath(full, site_packages_dir)))

        if os.path.isfile(package_file):
            result.append(_normalize_rel_path(os.path.relpath(package_file, site_packages_dir)))

    # Include metadata directory itself.
    if os.path.isdir(metadata_dir):
        for root, _, files in os.walk(metadata_dir):
            for filename in files:
                full = os.path.join(root, filename)
                result.append(_normalize_rel_path(os.path.relpath(full, site_packages_dir)))

    return sorted(set(result))


def discover_site_packages_distributions(site_packages_dir):
    """
    Discover installed distributions already present in site-packages.

    Returns a list of dicts:
        {
            "name": display name,
            "canonical": canonical name,
            "version": version or unknown,
            "metadata_dir": relative metadata dir,
            "metadata_type": dist-info/egg-info,
            "manifest_files": [...],
            "complete": bool,
            "source": record/fallback
        }
    """
    discovered = []
    seen_metadata_dirs = set()

    if not os.path.isdir(site_packages_dir):
        return discovered

    for entry in sorted(os.listdir(site_packages_dir)):
        full = os.path.join(site_packages_dir, entry)

        if not os.path.isdir(full):
            continue

        lower = entry.lower()
        is_dist_info = lower.endswith(".dist-info")
        is_egg_info = lower.endswith(".egg-info")

        if not is_dist_info and not is_egg_info:
            continue

        if full in seen_metadata_dirs:
            continue
        seen_metadata_dirs.add(full)

        metadata_file = None
        if is_dist_info:
            candidate = os.path.join(full, "METADATA")
            if os.path.exists(candidate):
                metadata_file = candidate
        else:
            candidate = os.path.join(full, "PKG-INFO")
            if os.path.exists(candidate):
                metadata_file = candidate

        headers = _read_metadata_headers(metadata_file) if metadata_file else {}

        name = headers.get("name")
        version = headers.get("version", "unknown")

        if not name:
            # Fallback from directory name: package-version.dist-info
            base = entry.rsplit(".", 1)[0]
            if "-" in base:
                name = base.rsplit("-", 1)[0]
            else:
                name = base

        canonical = PackageIdentity.canonicalize(name)
        metadata_rel = _normalize_rel_path(os.path.relpath(full, site_packages_dir))

        manifest_files = []
        source = "fallback"
        complete = False

        if is_dist_info:
            record_path = os.path.join(full, "RECORD")
            if os.path.exists(record_path):
                manifest_files = _read_dist_info_record(record_path, metadata_rel, site_packages_dir)
                source = "record"
                complete = bool(manifest_files)

        if not manifest_files:
            manifest_files = _guess_top_level_files_from_metadata(site_packages_dir, full, name)
            complete = False

        discovered.append({
            "name": name,
            "canonical": canonical,
            "version": version,
            "metadata_dir": metadata_rel,
            "metadata_type": "dist-info" if is_dist_info else "egg-info",
            "manifest_files": sorted(set(manifest_files)),
            "complete": complete,
            "source": source,
        })

    discovered.sort(key=lambda item: item.get("canonical", ""))
    return discovered


def _ledger_has_package(tracker, canonical_name):
    ledger = tracker.load_ledger()
    packages = ledger.get("packages", {})
    return PackageIdentity.canonicalize(canonical_name) in packages


def show_discovered_site_packages(site_packages_dir, tracker):
    discovered = discover_site_packages_distributions(site_packages_dir)

    print("\n📦 Packages discovered in site-packages:")
    if not discovered:
        print("   (none found)")
        return []

    for idx, item in enumerate(discovered, 1):
        in_ledger = _ledger_has_package(tracker, item["canonical"])
        ledger_text = "ledger=yes" if in_ledger else "ledger=no"
        complete_text = "record=yes" if item["complete"] else "record=no/fallback"
        print(
            "   {}. {} v{} [{} | {} | files={}]".format(
                idx,
                item["name"],
                item["version"],
                ledger_text,
                complete_text,
                len(item["manifest_files"]),
            )
        )

    print("\nTotal discovered: {}".format(len(discovered)))
    return discovered


def import_discovered_package_to_ledger(site_packages_dir, tracker, discovered_item, force_incomplete=False):
    """
    Import an existing distribution into Pipper's ledger so manifest uninstall can work.

    If RECORD is available, import is considered complete.
    If only fallback guessing is available, require force_incomplete=True.
    """
    canonical = discovered_item["canonical"]

    if _ledger_has_package(tracker, canonical):
        _warning("{} is already present in Pipper ledger.".format(canonical))
        return False

    manifest_files = discovered_item.get("manifest_files", [])

    if not manifest_files:
        _warning("{} has no discovered files to import.".format(canonical))
        return False

    if not discovered_item.get("complete") and not force_incomplete:
        _warning(
            "{} has no RECORD file. Fallback guessed {} files. "
            "Import refused unless forced.".format(canonical, len(manifest_files))
        )
        return False

    status = "IMPORTED" if discovered_item.get("complete") else "IMPORTED_INCOMPLETE"

    tracker.log_transaction(
        canonical,
        discovered_item.get("version", "unknown"),
        "site-scan",
        status=status,
        written_files=manifest_files,
    )

    _success(
        "Imported {} v{} into ledger with {} file(s). Status: {}".format(
            discovered_item.get("name"),
            discovered_item.get("version", "unknown"),
            len(manifest_files),
            status,
        )
    )
    return True


def import_all_discovered_record_packages(site_packages_dir, tracker):
    discovered = discover_site_packages_distributions(site_packages_dir)
    imported = 0
    skipped = 0

    for item in discovered:
        if _ledger_has_package(tracker, item["canonical"]):
            skipped += 1
            continue

        if not item.get("complete"):
            skipped += 1
            continue

        if import_discovered_package_to_ledger(site_packages_dir, tracker, item, force_incomplete=False):
            imported += 1
        else:
            skipped += 1

    print("\nImport complete. Imported: {} | Skipped: {}".format(imported, skipped))
    return imported


def prompt_import_discovered_package(site_packages_dir, tracker):
    discovered = show_discovered_site_packages(site_packages_dir, tracker)

    if not discovered:
        return False

    print(
        "\nImport options:\n"
        "   number  import one package\n"
        "   a       import all packages with RECORD files\n"
        "   q       cancel\n"
    )

    choice = input("Import selection: ").strip().lower()

    if choice in ("", "q"):
        return False

    if choice == "a":
        return import_all_discovered_record_packages(site_packages_dir, tracker) > 0

    try:
        idx = int(choice)
    except Exception:
        _error("Selection must be a number, a, or q.")
        return False

    if idx < 1 or idx > len(discovered):
        _error("Selection out of range.")
        return False

    item = discovered[idx - 1]

    if _ledger_has_package(tracker, item["canonical"]):
        _warning("Package is already in Pipper ledger.")
        return False

    print("\nSelected: {} v{}".format(item["name"], item["version"]))
    print("Metadata: {}".format(item["metadata_dir"]))
    print("Discovered files: {}".format(len(item["manifest_files"])))
    print("Record quality: {}".format("complete RECORD" if item["complete"] else "fallback guess only"))

    if not item["complete"]:
        _warning(
            "This package has no RECORD file. Pipper only guessed files from top_level.txt/name. "
            "Uninstall may be incomplete or unsafe."
        )
        if not _prompt_yes_no("Force import incomplete manifest?", default_no=True):
            return False
        return import_discovered_package_to_ledger(site_packages_dir, tracker, item, force_incomplete=True)

    if not _prompt_yes_no("Import this package into Pipper ledger for uninstall support?", default_no=True):
        return False

    return import_discovered_package_to_ledger(site_packages_dir, tracker, item, force_incomplete=False)



# =============================================================================
# Runtime diagnostics
# =============================================================================

def _try_get_installed_version(name):
    if importlib_metadata is None:
        return None

    candidates = [
        name,
        PackageIdentity.canonicalize(name),
        name.replace("-", "_"),
        name.replace("_", "-"),
    ]

    for candidate in candidates:
        try:
            return importlib_metadata.version(candidate)
        except Exception:
            pass

    return None


def _find_site_packages_dir():
    preferred = []
    fallback = []

    for path in sys.path:
        if not os.path.isdir(path):
            continue
        if "site-packages-3" in path:
            preferred.append(path)
        elif "site-packages" in path:
            fallback.append(path)

    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]

    # Extra fallback for non-standard embedded builds.
    try:
        if hasattr(site, "getsitepackages"):
            for candidate in site.getsitepackages():
                if candidate and os.path.isdir(candidate) and "site-packages" in candidate:
                    return candidate
    except Exception:
        pass

    return None


def _runtime_report(site_packages_dir, gist_folder_dir):
    _section("Runtime Report")
    print("Python version: {}".format(sys.version.split()[0]))
    print("Executable: {}".format(sys.executable))
    print("Site packages: {}".format(site_packages_dir))
    print("Gist folder: {}".format(gist_folder_dir))
    print("Export folder: {}".format(os.path.join(_find_user_documents_dir(site_packages_dir), "pipper_exports")))
    print("Packaging available: {}".format("yes" if _HAS_PACKAGING else "no"))
    print("importlib.metadata available: {}".format("yes" if importlib_metadata is not None else "no"))
    print("pip --hash mode enabled: {}".format("yes" if ENABLE_PIP_REQUIRE_HASHES else "no"))
    print("pip progress bar: off")
    print("verbose preflight: {}".format("yes" if VERBOSE_PREFLIGHT else "no"))
    print("pip operations this session: {}".format(PIP_RUN_COUNT))
    print("PyPI metadata cache entries: {}".format(len(_PYPI_METADATA_CACHE)))

    try:
        import pip
        pip_version = getattr(pip, "__version__", "unknown")
    except Exception:
        pip_version = "not importable"

    print("pip: {}".format(pip_version))



# =============================================================================
# Ledger uninstall browser helpers
# =============================================================================

def _get_package_last_history(metadata):
    history = metadata.get("history", [])
    if history and isinstance(history, list):
        last = history[-1]
        if isinstance(last, dict):
            return last
    return {}


def _format_uninstall_row(idx, pkg, metadata):
    last = _get_package_last_history(metadata)
    status = last.get("status", "UNKNOWN")
    source = last.get("source", "unknown")
    token = last.get("version_or_id", "unknown")
    file_count = len(metadata.get("manifest_files", []) or [])

    return "   {}. {} [{} | {} | {} | files={}]".format(
        idx,
        pkg,
        status,
        source,
        token,
        file_count,
    )


def _print_uninstall_details(pkg, metadata):
    last = _get_package_last_history(metadata)
    manifest_files = metadata.get("manifest_files", []) or []

    print("\nSelected package:")
    print("   Name: {}".format(pkg))
    print("   Status: {}".format(last.get("status", "UNKNOWN")))
    print("   Source: {}".format(last.get("source", "unknown")))
    print("   Version/token: {}".format(last.get("version_or_id", "unknown")))
    print("   Timestamp: {}".format(last.get("timestamp", "unknown")))
    print("   Manifest files: {}".format(len(manifest_files)))

    if manifest_files:
        print("\nFirst manifest entries:")
        for rel_path in manifest_files[:8]:
            print("   - {}".format(rel_path))
        if len(manifest_files) > 8:
            print("   ... {} more".format(len(manifest_files) - 8))


def _select_package_from_ledger_for_uninstall(tracker):
    ledger = tracker.load_ledger()
    packages = ledger.get("packages", {})

    if not packages:
        print("No packages recorded in ledger.")
        return None

    package_names = sorted(packages.keys())

    print("\n🗑️ Packages available for uninstall:\n")
    for idx, pkg in enumerate(package_names, 1):
        print(_format_uninstall_row(idx, pkg, packages[pkg]))

    print(
        "\nSelection options:\n"
        "   number   uninstall that package\n"
        "   name     uninstall by package name\n"
        "   d<number> show package details, e.g. d3\n"
        "   q        cancel\n"
    )

    while True:
        choice = input("Select package to uninstall: ").strip()

        if not choice:
            continue

        lowered = choice.lower()

        if lowered == "q":
            return None

        if lowered.startswith("d") and lowered[1:].isdigit():
            idx = int(lowered[1:])
            if idx < 1 or idx > len(package_names):
                print("Invalid detail selection.")
                continue
            pkg = package_names[idx - 1]
            _print_uninstall_details(pkg, packages[pkg])
            continue

        if choice.isdigit():
            idx = int(choice)
            if idx < 1 or idx > len(package_names):
                print("Invalid selection.")
                continue
            return package_names[idx - 1]

        canonical = PackageIdentity.canonicalize(choice)
        if canonical in packages:
            return canonical

        print("Package not found in ledger. Try number, exact name, d<number>, or q.")




# =============================================================================
# Export helpers
# =============================================================================

def _find_user_documents_dir(site_packages_dir):
    """
    Best-effort Pythonista-friendly export location.

    This is intentionally a Pythonista-targeted heuristic, not a general virtual
    environment locator. Pythonista usually places site-packages under a
    Documents tree, so walking upward gives a user-visible export folder.
    """
    current = _real_abs(site_packages_dir)

    while current and current != os.path.dirname(current):
        if os.path.basename(current) == "Documents":
            return current
        current = os.path.dirname(current)

    try:
        home = os.path.expanduser("~")
        if home and os.path.isdir(home):
            docs = os.path.join(home, "Documents")
            if os.path.isdir(docs):
                return docs
            return home
    except Exception:
        pass

    return site_packages_dir


def _resolve_export_dir(site_packages_dir):
    export_base = _find_user_documents_dir(site_packages_dir)
    export_dir = os.path.join(export_base, "pipper_exports")

    try:
        os.makedirs(export_dir, exist_ok=True)
    except OSError:
        export_dir = os.path.join(site_packages_dir, "pipper_exports")
        os.makedirs(export_dir, exist_ok=True)
        _warning("Could not write to Documents; exporting inside site-packages instead.")

    return export_dir


def export_ledger_and_requirements(site_packages_dir, tracker):
    """
    Export Pipper's ledger and a best-effort requirements.txt from ledger history.

    The requirements export includes packages with plain-looking versions/tokens.
    Gist entries and unknown/latest tokens are commented out.
    """
    ledger = tracker.load_ledger()
    packages = ledger.get("packages", {})

    if not packages:
        print("No ledger entries to export.")
        return False

    export_dir = _resolve_export_dir(site_packages_dir)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    human_stamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    ledger_path = os.path.join(export_dir, "installed-{}.json".format(stamp))
    requirements_path = os.path.join(export_dir, "requirements-{}.txt".format(stamp))
    summary_path = os.path.join(export_dir, "summary-{}.txt".format(stamp))

    _atomic_write_json(ledger_path, ledger)

    requirement_lines = [
        "# Generated by Pipper on {}".format(human_stamp),
        "# Best-effort export from Pipper ledger history.",
        "",
    ]

    summary_lines = []
    summary_lines.append("Pipper export created: {}".format(human_stamp))
    summary_lines.append("Packages: {}".format(len(packages)))
    summary_lines.append("")

    for pkg in sorted(packages.keys()):
        metadata = packages[pkg]
        history = metadata.get("history", [])
        last = history[-1] if history else {}
        source = last.get("source", "unknown")
        status = last.get("status", "UNKNOWN")
        token = last.get("version_or_id", "unknown")
        file_count = len(metadata.get("manifest_files", []) or [])

        summary_lines.append("{} | token={} | source={} | status={} | files={}".format(
            pkg, token, source, status, file_count
        ))

        if pkg.startswith("gist:"):
            requirement_lines.append("# {}  # Gist entry, not a PyPI requirement".format(pkg))
            continue

        if token in ("unknown", "latest", None):
            requirement_lines.append("# {}  # version unknown/latest from ledger".format(pkg))
            continue

        token_text = str(token).strip()

        if PackageIdentity.is_plain_version(token_text):
            exact = PackageIdentity.normalize_exact_version(token_text) or token_text
            requirement_lines.append("{}=={}".format(pkg, exact))
        else:
            requirement_lines.append("# {}  # non-plain token: {}".format(pkg, token_text))

    _atomic_write_text(requirements_path, "\n".join(requirement_lines) + "\n")
    _atomic_write_text(summary_path, "\n".join(summary_lines) + "\n")

    _success("Export complete:")
    print("   Folder: {}".format(export_dir))
    print("   Ledger: {}".format(ledger_path))
    print("   Requirements: {}".format(requirements_path))
    print("   Summary: {}".format(summary_path))
    return True



# =============================================================================
# Requirements import / freeze helpers
# =============================================================================

def _prompt_local_file_path(prompt_text):
    path = input(prompt_text).strip()
    if not path:
        return None

    expanded = os.path.expanduser(path)
    if os.path.isfile(expanded):
        return expanded

    # Try relative to current working directory.
    rel = os.path.abspath(path)
    if os.path.isfile(rel):
        return rel

    _warning("File not found: {}".format(path))
    return None



def _split_requirement_for_install(full_spec, fallback_name):
    """
    Convert a validated requirement line into (package_name, version_spec).

    Extras are currently ignored for pipper's package-name path, because custom
    extras can expand dependency graphs unpredictably on Pythonista.
    """
    clean = full_spec.strip()

    if _HAS_PACKAGING:
        try:
            req = Requirement(clean)
            name = PackageIdentity.canonicalize(req.name)
            spec = str(req.specifier) if req.specifier else None
            return name, spec
        except Exception:
            pass

    base = re.split(r"[<=>!~\[]", clean)[0].strip()
    if not base:
        base = fallback_name

    spec = clean[len(base):].strip()
    if spec.startswith("["):
        close = spec.find("]")
        if close != -1:
            spec = spec[close + 1:].strip()

    return PackageIdentity.canonicalize(base), spec or None


def install_requirements_file(site_packages_dir, tracker):
    """
    Batch install a local requirements.txt-style file.

    Only the restricted safe subset supported by _validate_requirements_line is
    accepted. Direct URLs, recursive -r, editables, and custom indexes are skipped.
    """
    req_path = _prompt_local_file_path("Local requirements.txt path: ")
    if not req_path:
        return False

    try:
        try:
            f = open(req_path, "r", encoding="utf-8", errors="ignore")
        except TypeError:
            f = open(req_path, "r")

        with f:
            lines = f.read().splitlines()
    except Exception as e:
        _error("Could not read requirements file: {}".format(e))
        return False

    parsed = []
    skipped = 0

    for line in lines:
        item = _validate_requirements_line(line)
        if item is None:
            clean = _strip_inline_comment(line).strip()
            if clean:
                skipped += 1
            continue
        parsed.append(item)

    if not parsed:
        _warning("No supported requirement lines found.")
        if skipped:
            _warning("Skipped unsupported/non-PyPI lines: {}".format(skipped))
        return False

    print("\n📄 Supported requirements discovered:")
    for idx, (_, spec) in enumerate(parsed, 1):
        print("   {}. {}".format(idx, spec))

    if skipped:
        _warning("Skipped unsupported/non-PyPI lines: {}".format(skipped))

    install_deps = _prompt_yes_no(
        "Install dependencies automatically for these requirements?",
        default_no=False,
    )

    _notice(
        "Batch mode skips per-package compatibility preflight to avoid repeated prompts. "
        "If a package fails, retry it with custom install for detailed preflight."
    )

    if not _prompt_yes_no("Proceed with batch install?", default_no=True):
        return False

    success = 0
    failed = 0

    for base_name, full_spec in parsed:
        print("\nBatch item: {}".format(full_spec))

        pkg_name, version_part = _split_requirement_for_install(full_spec, base_name)

        ok = install_pypi_package(
            pkg_name,
            site_packages_dir,
            tracker,
            version=version_part,
            allow_hashes=False,
            install_deps=install_deps,
            preflight=False,
        )

        if ok:
            success += 1
        else:
            failed += 1

    print("\nBatch install complete. Success: {} | Failed: {}".format(success, failed))
    return failed == 0


def freeze_site_packages(site_packages_dir):
    """
    Best-effort freeze by scanning .dist-info/.egg-info metadata.

    Unlike ledger export, this includes packages even if Pipper did not install
    or import them into the ledger.
    """
    discovered = discover_site_packages_distributions(site_packages_dir)

    if not discovered:
        _warning("No distributions discovered to freeze.")
        return False

    export_dir = _resolve_export_dir(site_packages_dir)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    human_stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    freeze_path = os.path.join(export_dir, "freeze-{}.txt".format(stamp))
    summary_path = os.path.join(export_dir, "freeze-summary-{}.txt".format(stamp))

    lines = [
        "# Generated by Pipper freeze on {}".format(human_stamp),
        "# Best-effort scan of site-packages metadata.",
        "",
    ]

    summary = [
        "Pipper freeze created: {}".format(human_stamp),
        "Distributions: {}".format(len(discovered)),
        "",
    ]

    for item in discovered:
        name = item.get("canonical") or PackageIdentity.canonicalize(item.get("name", ""))
        version = item.get("version", "unknown")
        complete = item.get("complete")
        source = item.get("source", "unknown")
        files = len(item.get("manifest_files", []) or [])

        if version and version != "unknown":
            lines.append("{}=={}".format(name, version))
        else:
            lines.append("# {}  # version unknown".format(name))

        summary.append("{} | version={} | source={} | record={} | files={}".format(
            name,
            version,
            source,
            "yes" if complete else "no/fallback",
            files,
        ))

    _atomic_write_text(freeze_path, "\n".join(lines) + "\n")
    _atomic_write_text(summary_path, "\n".join(summary) + "\n")

    _success("Freeze export complete:")
    print("   Folder: {}".format(export_dir))
    print("   Freeze: {}".format(freeze_path))
    print("   Summary: {}".format(summary_path))
    return True




# =============================================================================
# Session / memory helpers
# =============================================================================

def session_status_report():
    print("\n🧠 Session Status")
    print("   Pip operations this session: {}".format(PIP_RUN_COUNT))
    print("   Loaded modules: {}".format(len(sys.modules)))
    print("   PyPI metadata cache entries: {}".format(len(_PYPI_METADATA_CACHE)))
    print("   Verbose preflight: {}".format("ON" if VERBOSE_PREFLIGHT else "OFF"))

    if PIP_RUN_COUNT >= 10:
        _warning("High pip operation count. Restarting Pythonista is recommended after package work.")
    elif PIP_RUN_COUNT >= 5:
        _warning("Moderate pip operation count. Session cleanup may help.")
    else:
        _notice("Session looks light.")


def session_cleanup():
    """
    Safe cleanup only.

    We intentionally do not unload pip from sys.modules. That is fragile and can
    break the current Pythonista session. Full reset still requires restarting
    Pythonista.
    """
    before_cache = len(_PYPI_METADATA_CACHE)
    _PYPI_METADATA_CACHE.clear()

    try:
        collected = gc.collect()
    except Exception:
        collected = "unknown"

    print("\n🧹 Session cleanup complete.")
    print("   Garbage objects collected: {}".format(collected))
    print("   PyPI metadata cache entries cleared: {}".format(before_cache))
    print("   Loaded modules still present: {}".format(len(sys.modules)))
    _notice("For a full interpreter memory reset, restart Pythonista.")


def prompt_session_tools():
    while True:
        session_status_report()
        print(
            "\nSession options:\n"
            "   c  run safe cleanup\n"
            "   q  return to main menu\n"
        )

        choice = input("Selection: ").strip().lower()

        if choice in ("", "q"):
            return

        if choice == "c":
            session_cleanup()
            continue

        print("Unknown selection.")



# =============================================================================
# CLI
# =============================================================================

class CLI(object):
    def __init__(self, site_packages_dir, gist_folder_dir, tracker, uninstaller):
        self.site_packages_dir = site_packages_dir
        self.gist_folder_dir = gist_folder_dir
        self.tracker = tracker
        self.uninstaller = uninstaller

    def show_ledger_summary(self):
        ledger = self.tracker.load_ledger()
        packages = ledger.get("packages", {})

        if not packages:
            print("No ledger entries recorded yet.")
            return

        def _last_timestamp_for_summary(item):
            metadata = item[1]
            history = metadata.get("history", [])
            if history and isinstance(history, list):
                last = history[-1]
                if isinstance(last, dict):
                    return last.get("timestamp", "")
            return ""

        recent = sorted(packages.items(), key=_last_timestamp_for_summary)[-3:]

        print("Recent Installation Ledger Logs (latest timestamps):")
        for pkg, metadata in recent:
            history = metadata.get("history", [])
            if history:
                last = history[-1]
                last_status = last.get("status", "UNKNOWN")
                token = last.get("version_or_id", "unknown")
            else:
                last_status = "UNKNOWN"
                token = "unknown"
            print("   ✓ {} v{} [Status: {}]".format(pkg, token, last_status))

    def show_preset_catalog(self):
        print("\n📦 Preset Catalog Selections:")

        for idx, (name, meta) in enumerate(PRESET_PACKAGES.items(), 1):
            current_ver = _try_get_installed_version(name)
            configured_ver = meta.get("version")
            status = "[v{}]".format(current_ver) if current_ver else "[not active]"
            pin = "pinned {}".format(configured_ver) if configured_ver else "latest"

            print("   {}. {} {} - {} ({})".format(
                idx,
                name,
                status,
                meta.get("desc", ""),
                pin,
            ))

    def show_full_ledger(self):
        print("\n📋 Detailed Unified System Ledger:")
        ledger = self.tracker.load_ledger()
        packages = ledger.get("packages", {})

        if not packages:
            print("   (empty)")
            return

        for pkg, metadata in packages.items():
            print("   • Package identity: {}".format(pkg))

            for entry in metadata.get("history", []):
                print(
                    "     - Channel: {} | Token: {} | Status: {} | {}".format(
                        entry.get("source"),
                        entry.get("version_or_id"),
                        entry.get("status"),
                        entry.get("timestamp"),
                    )
                )

            print("     Manifest files: {}".format(len(metadata.get("manifest_files", []))))

    def handle_preset_install(self, selection=None):
        items = list(PRESET_PACKAGES.items())

        if selection is None:
            selection = input("Preset number to install: ").strip()

        try:
            idx = int(selection)
        except Exception:
            _error("Preset selection must be a number.")
            return

        if idx < 1 or idx > len(items):
            _error("Preset selection out of range.")
            return

        name, meta = items[idx - 1]
        version = meta.get("version")

        print("Selected preset: {}".format(name))
        print("Configured version: {}".format(version or "latest"))
        _notice("Preset installs use normal dependency mode for better Pythonista usability.")

        install_pypi_package(
            name,
            self.site_packages_dir,
            self.tracker,
            version=version,
            allow_hashes=False,
            install_deps=True,
            preflight=False,
        )

    def handle_custom_install(self):
        name = input("Target package library title: ").strip()
        if not name:
            _warning("No package name entered.")
            return

        version = input("Version restrictions (blank for latest): ").strip()

        if version and not PackageIdentity.is_valid_version(version):
            _error("Invalid version or specifier syntax.")
            return

        install_deps = _prompt_yes_no(
            "Install dependencies automatically?",
            default_no=False,
        )

        use_hashes = False
        if ENABLE_PIP_REQUIRE_HASHES and (not version or PackageIdentity.is_plain_version(version)):
            use_hashes = _prompt_yes_no(
                "Use strict hash mode? This installs the top-level package only (--no-deps)",
                default_no=True,
            )
            if use_hashes:
                install_deps = False

        install_pypi_package(
            name,
            self.site_packages_dir,
            self.tracker,
            version=version if version else None,
            allow_hashes=use_hashes,
            install_deps=install_deps,
            preflight=True,
        )

    def handle_gist_install(self):
        target = input("GitHub target gist link/id: ").strip()
        if not target:
            _warning("No Gist target entered.")
            return

        install_gist_package(target, self.site_packages_dir, self.tracker, self.gist_folder_dir)

    def handle_uninstall(self):
        target = _select_package_from_ledger_for_uninstall(self.tracker)

        if not target:
            return

        ledger = self.tracker.load_ledger()
        metadata = ledger.get("packages", {}).get(target, {})
        _print_uninstall_details(target, metadata)

        if not _prompt_yes_no("Proceed with uninstall of {}?".format(target), default_no=True):
            print("Uninstall cancelled.")
            return

        self.uninstaller.purge_package(target)

    def handle_runtime_report(self):
        _runtime_report(self.site_packages_dir, self.gist_folder_dir)

    def handle_repair_ledger(self):
        if os.path.exists(self.tracker.log_path):
            backup_path = self.tracker.log_path + ".bak-{}".format(time.strftime("%Y%m%d-%H%M%S"))
            try:
                shutil.copy2(self.tracker.log_path, backup_path)
                _success("Ledger backup created: {}".format(backup_path))
            except Exception as e:
                _warning("Could not create ledger backup: {}".format(e))
                if not _prompt_yes_no("Continue repair without backup?", default_no=True):
                    return

        ledger = self.tracker.load_ledger()
        self.tracker.save_ledger(ledger)
        _success("Ledger loaded, normalized, and saved.")

    def handle_export_ledger(self):
        export_ledger_and_requirements(self.site_packages_dir, self.tracker)

    def handle_requirements_install(self):
        install_requirements_file(self.site_packages_dir, self.tracker)

    def handle_freeze_export(self):
        freeze_site_packages(self.site_packages_dir)

    def handle_toggle_verbose_preflight(self):
        global VERBOSE_PREFLIGHT
        VERBOSE_PREFLIGHT = not VERBOSE_PREFLIGHT
        print("Verbose preflight is now {} (resets on restart).".format("ON" if VERBOSE_PREFLIGHT else "OFF"))

    def handle_session_tools(self):
        prompt_session_tools()

    def handle_scan_installed(self):
        show_discovered_site_packages(self.site_packages_dir, self.tracker)

    def handle_import_installed(self):
        prompt_import_discovered_package(self.site_packages_dir, self.tracker)

    def run_once(self):
        self.show_ledger_summary()
        self.show_preset_catalog()

        print(
            "\nOptions:\n"
            "   1-{} (install preset)\n"
            "   c (custom pypi)\n"
            "   g (github gist url/id)\n"
            "   u (uninstall package from ledger list)\n"
            "   l (history list)\n"
            "   s (scan existing site-packages)\n"
            "   i (import existing package for uninstall)\n"
            "   r (runtime report)\n"
            "   x (repair/normalize ledger)\n"
            "   e (export ledger / requirements)\n"
            "   b (batch install requirements.txt)\n"
            "   f (freeze scan export)\n"
            "   v (toggle verbose preflight)\n"
            "   m (memory/session status)\n"
            "   q (quit)\n".format(len(PRESET_PACKAGES))
        )

        action = input("Selection input path: ").strip().lower()

        if action in ("", "q"):
            return False

        if action.isdigit():
            self.handle_preset_install(action)
            return True

        dispatch = {
            "c": self.handle_custom_install,
            "g": self.handle_gist_install,
            "u": self.handle_uninstall,
            "l": self.show_full_ledger,
            "s": self.handle_scan_installed,
            "i": self.handle_import_installed,
            "r": self.handle_runtime_report,
            "x": self.handle_repair_ledger,
            "e": self.handle_export_ledger,
            "b": self.handle_requirements_install,
            "f": self.handle_freeze_export,
            "v": self.handle_toggle_verbose_preflight,
            "m": self.handle_session_tools,
        }

        handler = dispatch.get(action)

        if handler:
            handler()
        else:
            print("Unknown selection.")

        return True

    def run(self):
        while True:
            if not self.run_once():
                break


# =============================================================================
# Self-tests
# =============================================================================

def _self_test_identity():
    assert PackageIdentity.canonicalize("Beautiful_Soup4") == "beautiful-soup4"
    assert PackageIdentity.is_valid_name("requests")
    assert not PackageIdentity.is_valid_name("../requests")
    assert PackageIdentity.is_plain_version("1.2.3")
    assert PackageIdentity.is_plain_version("==1.2.3")
    assert not PackageIdentity.is_plain_version(">=1.2")
    assert PackageIdentity.build_requirement_spec("requests", "2.31.0") == "requests==2.31.0"
    assert PackageIdentity.build_requirement_spec("requests", ">=2,<3") == "requests>=2,<3"


def _self_test_paths():
    base = _real_abs(os.getcwd())
    good = _safe_join(base, "abc")
    assert _is_inside_or_equal(good, base)

    try:
        _safe_join(base, "..", "evil")
        raise AssertionError("Expected path breakout to fail")
    except PermissionError:
        pass


def _self_test_requirements():
    assert _validate_requirements_line("requests==2.31.0") is not None
    assert _validate_requirements_line("requests>=2,<3") is not None
    assert _validate_requirements_line("-r other.txt") is None
    assert _validate_requirements_line("git+https://example.com/x") is None
    assert _validate_requirements_line("pkg @ https://example.com/pkg.whl") is None


def _self_test_gist_parser():
    gid = "0123456789abcdef0123456789abcdef"
    assert _parse_gist_id(gid) == gid
    assert _parse_gist_id("gist:" + gid) == gid
    assert _parse_gist_id("https://gist.github.com/user/" + gid) == gid
    assert _parse_gist_id("https://gist.github.com/user/" + gid + "#file-x") == gid
    assert _parse_gist_id("https://gist.github.com/" + gid) == gid
    assert _parse_gist_id("https://api.github.com/gists/" + gid) == gid
    assert _parse_gist_id("not a gist") is None


def _self_test_gist_filenames():
    assert _safe_gist_filename("main.py")
    assert _safe_gist_filename("README.md")
    assert not _safe_gist_filename("../evil.py")
    assert not _safe_gist_filename("/evil.py")
    assert not _safe_gist_filename(".pth")
    assert not _safe_gist_filename("folder/file.py")


def _self_test_record_path_safety():
    base = _real_abs(os.getcwd())
    assert _safe_record_path_to_relpath("pkg/__init__.py", "pkg-1.dist-info", base) == "pkg/__init__.py"
    assert _safe_record_path_to_relpath("../evil.py", "pkg-1.dist-info", base) is None
    assert _safe_record_path_to_relpath("pkg/../../evil.py", "pkg-1.dist-info", base) is None
    assert _safe_record_path_to_relpath("/tmp/evil.py", "pkg-1.dist-info", base) is None


def run_self_tests():
    _section("Running self tests")
    _self_test_identity()
    _self_test_paths()
    _self_test_requirements()
    _self_test_gist_parser()
    _self_test_gist_filenames()
    _self_test_record_path_safety()
    _success("Self tests passed.")



# =============================================================================
# Optional compatibility dependency helper
# =============================================================================

def ensure_packaging_available(site_packages_dir):
    """
    Ask before installing 'packaging'.

    Pipper can run without packaging, but validation is better with it. This is
    optional because startup should not unexpectedly modify the environment.
    """
    global _HAS_PACKAGING, Version, InvalidVersion, SpecifierSet, InvalidSpecifier, Requirement, InvalidRequirement

    if _HAS_PACKAGING:
        return True

    print("\n📦 Optional dependency missing: packaging")
    print("   Pipper will still work, but version/specifier validation is less strict.")

    if not _prompt_yes_no("Install 'packaging' now for better validation?", default_no=True):
        return False

    ok = run_pip_command([
        "install",
        "--upgrade",
        "--target",
        site_packages_dir,
        "--no-compile",
        "packaging",
    ])

    if not ok:
        _warning("Could not install packaging. Continuing in degraded validation mode.")
        return False

    try:
        from packaging.version import Version as _Version, InvalidVersion as _InvalidVersion
        from packaging.specifiers import SpecifierSet as _SpecifierSet, InvalidSpecifier as _InvalidSpecifier
        from packaging.requirements import Requirement as _Requirement, InvalidRequirement as _InvalidRequirement

        Version = _Version
        InvalidVersion = _InvalidVersion
        SpecifierSet = _SpecifierSet
        InvalidSpecifier = _InvalidSpecifier
        Requirement = _Requirement
        InvalidRequirement = _InvalidRequirement
        _HAS_PACKAGING = True

        _success("'packaging' installed and activated for this session.")
        return True
    except Exception:
        _warning("'packaging' installed, but Pythonista may need a restart before it imports.")
        return False



# =============================================================================
# Main
# =============================================================================

def main():
    _banner("🎉 Hardened Pythonista Package Architecture (Pipper)")

    if not _HAS_PACKAGING:
        _warn_degraded_validation()

    site_packages_dir = _find_site_packages_dir()

    if not site_packages_dir:
        sys.exit("❌ Architecture Error: Cannot isolate root runtime directory.")

    if not _HAS_PACKAGING:
        ensure_packaging_available(site_packages_dir)

    gist_folder_dir = os.path.join(site_packages_dir, "gist_installs")
    os.makedirs(gist_folder_dir, exist_ok=True)

    tracker = ManifestTracker(os.path.join(site_packages_dir, "installed.json"))
    uninstaller = ManifestUninstaller(
        site_packages_dir,
        tracker,
        gist_folder_dir=gist_folder_dir,
    )

    if "--self-test" in sys.argv:
        run_self_tests()
        return

    try:
        import pip  # noqa: F401
    except ImportError:
        try:
            bootstrap_pip(site_packages_dir)
            print("\nℹ️  Pipper is now exiting.")
            print("   Please restart Pythonista and run Pipper again.")
        except RuntimeError as err:
            sys.exit("❌ Initialization Fault: {}".format(err))
        return

    cli = CLI(site_packages_dir, gist_folder_dir, tracker, uninstaller)
    cli.run()


if __name__ == "__main__":
    main()
