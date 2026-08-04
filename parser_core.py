"""
parser_core.py
--------------
Pure-logic core for AlertForge: JSON log parsing / field extraction and the
sqlite data layer. Kept separate from app.py (the Tkinter UI) so it has
zero GUI dependencies and can be unit-tested headlessly and reused if the
UI is ever swapped out.
"""

import base64
import binascii
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import unquote_plus as _url_unquote

try:
    from spellchecker import SpellChecker
except ImportError:
    SpellChecker = None


# --------------------------------------------------------------------------
# Transform functions referenced from field_mappings.json via "path::name"
# --------------------------------------------------------------------------

def _domain_from_email(value):
    if not value or "@" not in str(value):
        return ""
    return str(value).split("@", 1)[1]


def _azure_result(value):
    if value in (None, ""):
        return ""
    try:
        code = int(value)
    except (ValueError, TypeError):
        return str(value)
    return "Success" if code == 0 else f"Failure (errorCode {code})"


_WIN_AUTH_EVENT_LABELS = {
    "4624": "4624 - Successful Logon",
    "4625": "4625 - Failed Logon",
    "4634": "4634 - Logoff",
    "4648": "4648 - Explicit Credential Logon",
    "4672": "4672 - Special Privileges Assigned",
}


def _windows_auth_event_label(value):
    if value in (None, ""):
        return ""
    key = str(value).strip()
    return _WIN_AUTH_EVENT_LABELS.get(key, f"Event {key}")


def _windows_auth_result(value):
    if value in (None, ""):
        return ""
    key = str(value).strip()
    if key == "4624":
        return "Success"
    if key == "4625":
        return "Failure"
    return "Unknown"


def _dict_get_ci(d, key):
    """Case-insensitive dict key lookup."""
    if not isinstance(d, dict):
        return None
    match = next((k for k in d.keys() if k.lower() == str(key).lower()), None)
    return d[match] if match is not None else None


def _flatten_name_value_pairs(value):
    """Turn a list of {"Name": ..., "Value": ...} dicts (the pattern O365 /
    Rapid7 audit logs use for ExtendedProperties, Parameters, DeviceProperties,
    etc.) into a single readable 'Name=Value; Name2=Value2' string."""
    if not isinstance(value, list):
        return ""
    parts = []
    for item in value:
        if isinstance(item, dict):
            name = _dict_get_ci(item, "Name") or _dict_get_ci(item, "var")
            val = _dict_get_ci(item, "Value")
            if val is None:
                val = _dict_get_ci(item, "val")
            if name is not None:
                parts.append(f"{name}={val}")
    return "; ".join(parts)


def _flatten_name_value_json_string(value):
    """Same as flatten_name_value_pairs, but for logs where the Name/Value
    parameter array arrives as a JSON-encoded STRING rather than a real
    nested array - e.g. Sentinel's OfficeActivity table stores its
    "Parameters" field as '[{"Name":"X","Value":"Y"}, ...]' text instead
    of an actual JSON array, since the underlying Office 365 Management
    Activity API double-serializes it. Parses the string first, then
    flattens it the same way; falls back gracefully (empty string) if the
    value isn't valid JSON or isn't a string to begin with."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return ""
    return _flatten_name_value_pairs(value)


def _join_list(value):
    """Join a list value into one readable 'a; b; c' string - e.g. a
    Sentinel watchlist alert that carries Computer / IpAddressList as
    arrays because the aggregate alert spans more than one host or source
    IP. Non-list values pass through as a plain string unchanged, so this
    is safe to use even on a field that's sometimes a list and sometimes
    a single scalar depending on the alert."""
    if isinstance(value, list):
        return "; ".join(str(v) for v in value if v not in (None, ""))
    return "" if value in (None, "") else str(value)


TRANSFORMS = {
    "domain_from_email": _domain_from_email,
    "azure_result": _azure_result,
    "windows_auth_event_label": _windows_auth_event_label,
    "windows_auth_result": _windows_auth_result,
    "flatten_name_value_pairs": _flatten_name_value_pairs,
    "flatten_name_value_json_string": _flatten_name_value_json_string,
    "join_list": _join_list,
}

CANONICAL_FIELDS = [
    "user", "domain", "host", "src_ip", "dst_ip",
    "process", "cmdline", "parent_process", "parent_cmdline",
    "timestamp", "event_id", "event_type", "result",
    "location", "device_os",
]

# Status values an analyst can set on a saved incident, for quick triage
# tracking in the Incidents tab (filterable there). New incidents default
# to "Open".
INCIDENT_STATUSES = ["Open", "Escalated", "Closed", "False Positive"]


# --------------------------------------------------------------------------
# Generic JSON helpers
# --------------------------------------------------------------------------

def flatten(obj, prefix=""):
    """Flatten nested dict/list JSON into {dot.path: scalar_value}."""
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            newkey = f"{prefix}.{k}" if prefix else str(k)
            items.update(flatten(v, newkey))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            newkey = f"{prefix}[{i}]"
            items.update(flatten(v, newkey))
    else:
        items[prefix] = obj
    return items


def _leaf_name(dot_path):
    return re.split(r"[.\[]", dot_path)[-1].rstrip("]").lower()


_BRACKET_INDEX_RE = re.compile(r"^([^\[]+)\[(\d+)\]$")
_BRACKET_NAMED_RE = re.compile(r"^([^\[]+)\[([^=\]]+)=([^\]]+)\]$")


def get_path(data, path):
    """Case-insensitive dot-path lookup into nested dict/list JSON.

    Supports two bracket forms for list access, in addition to plain
    ``a.b.c`` dict traversal:
      - ``field[0]``            -> numeric index into a list
      - ``field[Name=Value]``   -> find the first dict in a list where
                                    dict['Name'] == 'Value' (case-insensitive
                                    key AND value match); used for the
                                    common {"Name": ..., "Value": ...} pair
                                    pattern seen in O365 / Rapid7 audit logs
                                    (ExtendedProperties, Parameters, etc.)
    """
    if not path:
        return None
    cur = data
    for part in path.split("."):
        named = _BRACKET_NAMED_RE.match(part)
        indexed = _BRACKET_INDEX_RE.match(part)
        if named:
            field, matchkey, matchval = named.groups()
            container = _dict_get_ci(cur, field) if isinstance(cur, dict) else None
            if not isinstance(container, list):
                return None
            found = None
            for item in container:
                if isinstance(item, dict):
                    v = _dict_get_ci(item, matchkey)
                    if v is not None and str(v).lower() == matchval.lower():
                        found = item
                        break
            cur = found
        elif indexed:
            field, idx = indexed.groups()
            container = _dict_get_ci(cur, field) if isinstance(cur, dict) else None
            if not isinstance(container, list):
                return None
            i = int(idx)
            cur = container[i] if 0 <= i < len(container) else None
        else:
            if isinstance(cur, list):
                cur = cur[0] if cur else None
            if isinstance(cur, dict):
                cur = _dict_get_ci(cur, part)
            else:
                return None
    return cur


def get_field_value(data, spec):
    """Resolve one 'fields' entry from a profile: '', 'literal:x', 'a.b',
    or 'a.b::transform'.

    Supports '||'-separated fallback candidates (e.g.
    'pathA::transformA||pathB::transformB') so one canonical field can be
    shared by two log shapes detected under the same profile - each
    candidate is tried in order and the first one that resolves to a
    non-empty value wins. This is how the merged O365/Azure AD sign-in
    profile fills fields like host/device_os from either the O365
    DeviceProperties Name/Value list or the Azure deviceDetail object,
    whichever the current log actually has."""
    if not spec:
        return None
    for candidate in spec.split("||"):
        candidate = candidate.strip()
        if not candidate:
            continue
        if candidate.startswith("literal:"):
            return candidate[len("literal:"):]
        if "::" in candidate:
            path, transform_name = candidate.split("::", 1)
        else:
            path, transform_name = candidate, None
        val = get_path(data, path)
        if transform_name and transform_name in TRANSFORMS:
            val = TRANSFORMS[transform_name](val)
        if val not in (None, ""):
            return val
    return None


def detect_profile(data, profiles):
    """Returns (profile_or_None, match_type) where match_type is 'exact'
    (every detect_key found) or 'partial' (a majority found - handles
    analysts pasting just the top portion of a log, which commonly leaves
    out one or two of a profile's identifying fields)."""
    flat = flatten(data)
    leaf_names = {_leaf_name(k) for k in flat.keys()}

    # Pass 1: exact match - every detect_key present. First configured
    # profile wins ties, same priority order as before.
    for profile in profiles:
        required = [dk.lower() for dk in profile.get("detect_keys", [])]
        if required and all(r in leaf_names for r in required):
            return profile, "exact"

    # Pass 2: partial match fallback, only used when nothing matched
    # exactly. Requires a majority of a profile's detect_keys to be
    # present so unrelated logs that merely share one common field name
    # don't get misdetected.
    best_profile = None
    best_matched = 0
    for profile in profiles:
        required = [dk.lower() for dk in profile.get("detect_keys", [])]
        if not required:
            continue
        matched = sum(1 for r in required if r in leaf_names)
        threshold = max(1, (len(required) + 1) // 2)  # ceil(n/2)
        if matched >= threshold and matched > best_matched:
            best_profile = profile
            best_matched = matched
    if best_profile is not None:
        return best_profile, "partial"
    return None, None


def extract_generic(data, fallback_map):
    flat = flatten(data)
    leaf_to_value = {}
    for k, v in flat.items():
        leaf = _leaf_name(k)
        if leaf not in leaf_to_value:
            leaf_to_value[leaf] = v
    result = {}
    for canon, candidates in fallback_map.items():
        if canon.startswith("_"):
            continue
        val = None
        for c in candidates:
            if c.lower() in leaf_to_value:
                val = leaf_to_value[c.lower()]
                break
        result[canon] = val
    return result


def _try_wrap_as_object(text):
    """Repair a pasted JSON *fragment* that's missing its enclosing braces
    - the common pattern when an analyst selects and copies just the
    'juicy' top fields out of the middle of a larger JSON log, e.g.:

        "timestamp": "...",
        "user": "...",
        "source_ip": "...",

    with no surrounding { } and often a trailing comma. Tries a few
    reasonable repairs and returns the first one that parses as a dict,
    or None if nothing works."""
    t = text.strip()
    if not t:
        return None
    t_nocomma = t[:-1].rstrip() if t.endswith(",") else t
    candidates = []
    if not (t.startswith("{") and t.endswith("}")):
        candidates.append("{" + t_nocomma + "}")
    if t.startswith("{") and not t.endswith("}"):
        candidates.append(t_nocomma + "}")
    if t.endswith("}") and not t.startswith("{"):
        candidates.append("{" + t_nocomma)
    for cand in candidates:
        try:
            parsed = json.loads(cand)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


_KV_SCRAPE_RE = re.compile(
    r'"([^"\\]+)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
)


def _scrape_flat_pairs(text):
    """Last-resort fallback: scan the whole pasted blob for any
    "key": value pairs (string/number/bool/null values only - nested
    objects/arrays are skipped since they can't be reliably reconstructed
    from a partial/malformed paste). Used when the text isn't valid JSON
    even after brace-repair, e.g. a messier or more deeply-truncated
    paste. First occurrence of a key wins, since analysts tend to paste
    the most relevant fields first."""
    result = {}
    for key, raw_val in _KV_SCRAPE_RE.findall(text):
        if key in result:
            continue
        try:
            result[key] = json.loads(raw_val)
        except json.JSONDecodeError:
            result[key] = raw_val.strip('"')
    return result or None


_BAD_JSON_ESCAPE_RE = re.compile(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})')


def _fix_unescaped_backslashes(text):
    r"""Repair the single most common way a SIEM export breaks otherwise
    well-formed JSON: a raw Windows file path or command line (e.g.
    "C:\Windows\System32\svchost.exe -k Something") pasted straight
    into a JSON string value with its backslashes never escaped. A bare
    backslash is only legal in JSON right before one of \" \\ \/ \b \f
    \n \r \t or a \uXXXX unicode escape - anything else (a Windows path
    separator, most commonly) makes the whole document fail to parse
    even though it visually looks complete (matched braces, etc.).

    Doubles up every backslash that ISN'T already part of one of those
    valid escapes, leaving genuinely valid JSON completely untouched -
    so this is safe to run unconditionally as a repair attempt without
    risking corrupting text that was already fine."""
    return _BAD_JSON_ESCAPE_RE.sub(r"\\\\", text)


def parse_json_blobs_verbose(raw_text):
    """Accepts a single JSON object, a JSON array of objects,
    newline-delimited JSON, or a partial/malformed fragment (missing
    braces, truncated, etc.). Returns (list_of_dicts, repair_method) where
    repair_method is None (clean JSON), 'unescaped_backslashes' (a raw
    Windows path/command line's backslashes were escaped before
    parsing), 'wrapped' (braces were added back on), or 'scraped'
    (last-resort flat key:value scan)."""
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return [], None

    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            objs = [p for p in parsed if isinstance(p, dict)]
            if objs:
                return objs, None
        elif isinstance(parsed, dict):
            return [parsed], None
    except json.JSONDecodeError:
        pass

    # Retry once with unescaped-backslash repair before falling through
    # to the lossier strategies below - this is what keeps a log's full
    # nested structure intact (so profile field mapping still works
    # normally) instead of degrading straight to a flat best-effort
    # scrape just because one Windows path in the middle of the log
    # wasn't escaped.
    repaired_text = _fix_unescaped_backslashes(raw_text)
    repair_used = repaired_text != raw_text
    if repair_used:
        try:
            parsed = json.loads(repaired_text)
            if isinstance(parsed, list):
                objs = [p for p in parsed if isinstance(p, dict)]
                if objs:
                    return objs, "unescaped_backslashes"
            elif isinstance(parsed, dict):
                return [parsed], "unescaped_backslashes"
        except json.JSONDecodeError:
            pass

    work_text = repaired_text if repair_used else raw_text

    objs = []
    for line in work_text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objs.append(obj)
        except json.JSONDecodeError:
            continue
    if objs:
        return objs, ("unescaped_backslashes" if repair_used else None)

    wrapped = _try_wrap_as_object(work_text)
    if wrapped is not None:
        return [wrapped], "wrapped"

    scraped = _scrape_flat_pairs(work_text)
    if scraped:
        return [scraped], "scraped"

    return [], None


def parse_json_blobs(raw_text):
    """Back-compat wrapper: same as parse_json_blobs_verbose but drops the
    repair-method flag."""
    objs, _ = parse_json_blobs_verbose(raw_text)
    return objs


class FieldMapper:
    """Loads field_mappings.json and extracts canonical SOC fields from
    pasted JSON log text."""

    def __init__(self, config_path):
        self.config_path = config_path
        self.config = {"profiles": [], "generic_fallback": {}}
        self.load()

    def load(self):
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

    def save_raw(self, raw_json_text):
        """Validate then persist raw JSON text as the new config."""
        parsed = json.loads(raw_json_text)  # raises if invalid
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2)
        self.config = parsed

    def save_config(self, config_dict):
        """Persist a config dict (already the live self.config, or a
        modified copy) directly to disk without a JSON text round-trip.
        Used by the friendly Field Mappings UI (add field / new profile /
        delete) so it never has to build raw JSON text by hand."""
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2)
        self.config = config_dict

    def raw_text(self):
        with open(self.config_path, "r", encoding="utf-8") as f:
            return f.read()

    def export_profiles(self, profile_ids=None):
        """Return a deep-copied list of profile dicts, for sharing between
        analysts as a small standalone JSON file. If profile_ids is given,
        only profiles whose 'id' is in that collection are returned;
        otherwise every profile is returned."""
        profiles = self.config.get("profiles", [])
        if profile_ids:
            profiles = [p for p in profiles if p["id"] in profile_ids]
        return json.loads(json.dumps(profiles))

    def import_profiles(self, profiles, overwrite=False):
        """Import a list of profile dicts (as produced by export_profiles)
        into the live config, keyed by 'id'. A profile whose id already
        exists is left alone and reported as skipped unless
        overwrite=True, in which case it replaces the existing one in
        place (so its position/order is preserved). New profiles are
        appended. Persists to disk via save_config. Returns
        (imported_count, skipped_ids)."""
        self.config.setdefault("profiles", [])
        existing_index = {p["id"]: i for i, p in enumerate(self.config["profiles"]) if "id" in p}
        imported = 0
        skipped = []
        for prof in profiles:
            pid = prof.get("id") if isinstance(prof, dict) else None
            if not pid:
                continue
            normalized = {
                "id": pid,
                "label": prof.get("label", pid),
                "detect_keys": prof.get("detect_keys", []),
                "fields": prof.get("fields", {}),
            }
            if pid in existing_index:
                if overwrite:
                    self.config["profiles"][existing_index[pid]] = normalized
                    imported += 1
                    continue
                skipped.append(pid)
                continue
            self.config["profiles"].append(normalized)
            existing_index[pid] = len(self.config["profiles"]) - 1
            imported += 1
        self.save_config(self.config)
        return imported, skipped

    def parse(self, raw_text, forced_profile_id=None):
        """Returns dict: {label, canonical, field_order, warnings,
        record_count, matched}.

        'canonical' holds whatever fields the matched profile defines (a
        mix of the common cross-source fields like user/host/process and
        source-specific extras like geoip_city or process_sha256).
        'field_order' preserves the profile's field ordering for display.

        Handles analysts pasting only part of a log (a very common
        workflow - the "juicy" fields tend to be near the top of an
        auth/process log) two ways: it tries to repair JSON fragments
        that are missing their enclosing braces, and it detects a log
        profile off a majority of its identifying fields rather than
        requiring every single one to be present.

        If forced_profile_id is given, automatic detection is skipped
        entirely and that profile's field mapping is used no matter what
        detect_keys would otherwise say - this is the escape hatch for an
        analyst who knows better than the auto-detector (two profiles
        with overlapping generic field names, a log a profile hasn't been
        tuned for yet, etc.). If the id doesn't match any current profile
        (e.g. it was renamed/deleted since being selected), this silently
        falls back to auto-detection with a warning explaining why.
        """
        objs, repair_method = parse_json_blobs_verbose(raw_text)
        if not objs:
            return {
                "label": None,
                "canonical": {k: "" for k in CANONICAL_FIELDS},
                "field_order": list(CANONICAL_FIELDS),
                "warnings": [
                    "Could not parse input as JSON, even after trying to "
                    "repair a partial paste. Paste a JSON object (or "
                    "fragment of one), a JSON array, or newline-delimited "
                    "JSON."
                ],
                "record_count": 0,
                "matched": False,
            }

        data = objs[0]
        warnings = []

        forced_profile = None
        if forced_profile_id:
            forced_profile = next(
                (p for p in self.config.get("profiles", []) if p.get("id") == forced_profile_id),
                None,
            )
            if forced_profile is None:
                warnings.append(
                    "The manually selected profile could not be found (it "
                    "may have been renamed or deleted since you picked it) "
                    "- auto-detect was used instead."
                )

        if forced_profile is not None:
            profile, match_type = forced_profile, "forced"
        else:
            profile, match_type = detect_profile(data, self.config.get("profiles", []))

        if repair_method == "unescaped_backslashes":
            warnings.append(
                "Pasted text had one or more literal backslashes (commonly "
                "a Windows file path or command line, e.g. "
                "C:\\Windows\\System32\\svchost.exe) that weren't escaped, "
                "which is invalid JSON on its own - fixed automatically "
                "before parsing. Double check any path/command-line "
                "fields below."
            )
        elif repair_method == "wrapped":
            warnings.append(
                "Pasted text was missing its outer { } braces (looks like "
                "a partial copy/paste of a larger log) - repaired "
                "automatically. Fields you didn't paste will show blank."
            )
        elif repair_method == "scraped":
            warnings.append(
                "Pasted text wasn't valid JSON, so fields were pulled with "
                "a best-effort scan for \"key\": value pairs. Nested "
                "list/object fields (like Name/Value parameter arrays) "
                "won't be available this way - paste more of the log if "
                "you need those. Double check the results."
            )

        if profile:
            canonical = {}
            agg_fields = []
            for field, spec in profile["fields"].items():
                if isinstance(spec, str) and spec.startswith("all:"):
                    # 'all:path' aggregates a value across EVERY pasted
                    # JSON record instead of just the first - used for
                    # fields like a USB-copy alert's file names, where an
                    # analyst commonly pastes one JSON object per file
                    # copied rather than a single record.
                    agg_fields.append(field)
                    path = spec[len("all:"):]
                    seen = []
                    for obj in objs:
                        v = get_path(obj, path)
                        if v not in (None, "") and str(v) not in seen:
                            seen.append(str(v))
                    canonical[field] = "; ".join(seen)
                else:
                    canonical[field] = get_field_value(data, spec)
            field_order = list(profile["fields"].keys())
            label = profile["label"]
            matched = True
            if match_type == "partial":
                required = profile.get("detect_keys", [])
                flat_leaf_names = {_leaf_name(k) for k in flatten(data).keys()}
                found = sum(1 for r in required if r.lower() in flat_leaf_names)
                warnings.append(
                    f"Only {found}/{len(required)} of the fields normally "
                    f"used to identify '{label}' were found, so this looks "
                    f"like a partial paste of that log type. Extracted "
                    f"fields not included in your paste will show blank."
                )
            elif match_type == "forced":
                warnings.append(
                    f"Profile manually set to '{label}' - auto-detect was "
                    f"bypassed. Extracted fields not present in this log "
                    f"will show blank."
                )
        else:
            canonical = extract_generic(data, self.config.get("generic_fallback", {}))
            field_order = list(CANONICAL_FIELDS)
            label = "Unrecognized format - generic field matching used"
            warnings.append(
                "No known log profile matched this log. Generic key "
                "matching was used and results may be incomplete. "
                "Consider adding a profile in the Field Mappings tab."
            )
            matched = False
            agg_fields = []

        for k in list(canonical.keys()):
            v = canonical[k]
            canonical[k] = "" if v is None else str(v)

        if len(objs) > 1:
            if agg_fields:
                warnings.append(
                    f"Input contained {len(objs)} JSON records. Most fields "
                    f"were extracted from the first record only, but "
                    f"{', '.join(agg_fields)} were aggregated across all "
                    f"{len(objs)} records."
                )
            else:
                warnings.append(
                    f"Input contained {len(objs)} JSON records; fields were "
                    f"extracted from the first record only."
                )

        return {
            "label": label,
            "canonical": canonical,
            "field_order": field_order,
            "warnings": warnings,
            "record_count": len(objs),
            "matched": matched,
        }


_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}|#(\w+)")


def fill_template(text, data):
    """Replace placeholders in template/note text with values from data.

    Two syntaxes are supported:
      - {field}  - explicit placeholder. If the field is missing/blank it
                   is replaced with a visible '[field]' marker so the
                   analyst notices and fills it in by hand.
      - #field   - inline tag, e.g. "seen from #source_ip". Only replaced
                   if 'field' is a known key in data; otherwise left
                   untouched so incidental '#' text (ticket numbers,
                   hashtags, etc.) is never corrupted.

    'data' is a flat dict of canonical/extra field name -> string value
    (whatever the parser extracted for the current log).
    """

    def _sub(m):
        brace_key, tag_key = m.group(1), m.group(2)
        if brace_key is not None:
            if brace_key in data and str(data[brace_key]).strip() != "":
                return str(data[brace_key])
            return f"[{brace_key}]"
        if tag_key is not None:
            if tag_key in data and str(data[tag_key]).strip() != "":
                return str(data[tag_key])
            return m.group(0)
        return m.group(0)

    return _PLACEHOLDER_RE.sub(_sub, text or "")


_UNRESOLVED_TAG_RE = re.compile(r"\{(\w+)\}|#(\w+)|\[(\w+)\]")


def find_unresolved_tag_spans(text, known_fields):
    """Scan text for #tag / {field} / [field] placeholders that haven't
    been resolved into real values yet - used by the UI to highlight
    them (e.g. bold+yellow in the ticket output box) so it's obvious at
    a glance what still needs attention before a write-up goes out.
    Returns a list of (start, end) character offsets into `text`.

    - '{field}' is always considered unresolved, regardless of whether
      'field' is a recognized name - fill_template() replaces every
      '{...}' it finds (with the real value, or a '[field]' marker if
      blank), so any '{...}' still present in the raw text simply hasn't
      been run through that yet.
    - '#field' and '[field]' are only flagged when 'field' (case
      insensitive) is one of known_fields - matching fill_template()'s
      own behavior of leaving unrecognized #hashtags and bracketed text
      alone, so ticket numbers, '#1234', '[redacted]', etc. are never
      mistaken for a broken placeholder.
    """
    known = {k.lower() for k in known_fields}
    spans = []
    for m in _UNRESOLVED_TAG_RE.finditer(text or ""):
        brace_word, hash_word, bracket_word = m.group(1), m.group(2), m.group(3)
        if brace_word is not None:
            hit = True
        elif hash_word is not None:
            hit = hash_word.lower() in known
        else:
            hit = bracket_word.lower() in known
        if hit:
            spans.append((m.start(), m.end()))
    return spans


def remove_unresolved_tags(text, known_fields):
    """Delete every unresolved #tag/{field}/[field] placeholder found by
    find_unresolved_tag_spans (e.g. a leftover '#analysis' the analyst
    typed but never ended up using) straight out of text, for when the
    fix is "this placeholder just isn't needed" rather than "go find a
    value for it." Eats one adjacent space on either side of a removed
    tag (preferring the left) so deleting a mid-sentence tag doesn't
    leave a double space behind - deliberately leaves newlines alone, so
    a tag sitting alone on its own line just becomes a blank line rather
    than silently collapsing surrounding paragraph structure. Returns
    the text unchanged if nothing was unresolved."""
    spans = find_unresolved_tag_spans(text, known_fields)
    if not spans:
        return text
    result = text
    for start, end in reversed(spans):
        left, right = start, end
        if left > 0 and result[left - 1] == " ":
            left -= 1
        elif right < len(result) and result[right] == " ":
            right += 1
        result = result[:left] + result[right:]
    return result


# --------------------------------------------------------------------------
# Log sanitization (Sanitize Logs tab)
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

_SID_RE = re.compile(r"\bS-1-(?:\d+-){1,14}\d+\b")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"
)

# Permissive candidate pattern - real filtering happens in _looks_like_ipv6
# below, since hex-only groups separated by colons would otherwise also
# match plain HH:MM:SS timestamps.
_IPV6_CANDIDATE_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{0,4}\b"
    r"|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b"
)

# Common Windows/Linux computer-name conventions (WORKSTATION-07,
# DESKTOP-ABC123, srv-dc01, SQL-01, ...) - deliberately scoped to a fixed
# list of recognized prefixes rather than "any hyphenated alphanumeric
# token", since the latter would also catch ticket/incident references
# like INC-1234 that must never be redacted. "WIN" and "PC" were
# deliberately left off this list - they collide constantly with benign
# Windows/PC terminology that has nothing to do with an actual hostname
# ("Windows", "WindowsPowerShell", "Win32", "PC" as in "personal
# computer"), which is far more common in pasted logs than a real
# WIN-prefixed or PC-prefixed machine name.
#
# The prefix alone is never enough to redact - a bare "Host" (as in the
# PowerShell cmdlet Write-Host) or "Server" used as an ordinary word must
# NOT be treated as a hostname, so a suffix is REQUIRED: either a hyphen
# followed by more alphanumerics (WORKSTATION-07, srv-dc01) or a digit
# immediately after the prefix (HOST01, DC01). Real machine names almost
# always carry a numeric/hyphenated suffix for uniqueness, so this cuts
# out the common-English-word false positives without giving up realistic
# naming conventions.
#
# The trailing negative lookahead skips a match that's immediately
# followed by (an optional quote then) a colon - i.e. it's acting as a
# label/JSON key ("HostName": ..., "Host: ...") rather than an actual
# value, since a raw pasted JSON log's KEYS can otherwise collide with
# these same prefixes (HostName, ClientIP, etc.) and corrupt the log
# structure if redacted.
_HOSTNAME_RE = re.compile(
    r'\b(?:WORKSTATION|DESKTOP|LAPTOP|SERVER|SRV|HOST|NODE|CLIENT|'
    r'MAIL|EXCH|SQL|WEB|APP|DB|DC|VM)'
    r'(?:-[A-Za-z0-9][A-Za-z0-9-]*|[0-9][A-Za-z0-9-]*)\b(?!"?\s*:)',
    re.IGNORECASE,
)

# Registrable domain names / FQDNs (contoso.com, srv-dc01.contoso.com,
# sub.example.co.uk, ...). The candidate pattern requires the final label
# to be alphabetic so dotted-decimal IPs and version strings
# (10.0.22631, 537.36) never match on their own, but that alone isn't a
# strong enough signal in log/code-heavy text - dotted identifier chains
# like "rc.Cells.Item" or a file name like "powershell.exe" also fit that
# shape. _looks_like_domain (below) narrows candidates down to ones whose
# final label is a recognized TLD, the same two-step "permissive regex +
# validating heuristic" pattern _looks_like_ipv6 uses. Same trailing-
# colon/JSON-key guard as hostnames.
_DOMAIN_CANDIDATE_RE = re.compile(
    r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b(?!"?\s*:)'
)

# Not exhaustive, but covers the TLDs that actually show up in SOC
# logs/tickets: generic, common country codes, and a few internal/
# infrastructure pseudo-TLDs (local, corp, lan, internal) - deliberately
# excludes things like "exe", "dll", "item", "value" etc. that are common
# final "labels" in code/file-path text but are not TLDs.
_COMMON_TLDS = {
    "com", "net", "org", "gov", "edu", "mil", "io", "co", "biz", "info",
    "name", "local", "corp", "internal", "lan", "int", "arpa", "dev",
    "app", "cloud", "eu", "asia", "tv", "me", "xyz", "onmicrosoft",
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "ru", "br", "in",
    "nl", "se", "no", "dk", "fi", "es", "it", "pl", "ch", "at", "be",
    "ie", "nz", "sg", "hk", "kr", "mx", "za",
}


def _looks_like_domain(candidate):
    """Validates a _DOMAIN_CANDIDATE_RE match by checking its final label
    against _COMMON_TLDS - see the comment above _DOMAIN_CANDIDATE_RE for
    why the regex shape alone (dotted labels ending in letters) isn't a
    reliable enough signal on its own."""
    last_label = candidate.rsplit(".", 1)[-1].lower()
    return last_label in _COMMON_TLDS


def _looks_like_ipv6(candidate):
    """A cheap-but-effective filter to keep the permissive IPv6 candidate
    regex from mistaking a plain HH:MM:SS timestamp for an address: real
    IPv6 text almost always has a '::' compression, a hex letter (a-f),
    or more colons than a timestamp ever has (timestamps top out at 2)."""
    if "::" in candidate:
        return True
    if re.search(r"[A-Fa-f]", candidate):
        return True
    return candidate.count(":") >= 4


# --------------------------------------------------------------------------
# VirusTotal quick-lookup links (Incident Workspace's Extracted Fields table)
# --------------------------------------------------------------------------

# A file hash is unambiguous by length alone: 32 hex chars is MD5, 40 is
# SHA1, 64 is SHA256 - nothing else in a SOC log's extracted fields is
# ever a bare hex string of exactly one of those three lengths.
_HASH_RE = re.compile(r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})")

# Unlike the hash/IP checks above (which require the WHOLE field value to
# be that exact thing), a URL is looked for WITHIN the value, since a
# field holding a URL commonly has it embedded in a bit of surrounding
# text (a full request line, a "message" field, etc.) rather than as a
# clean standalone value. ';' is excluded from the URL body so a
# join_list-aggregated multi-value field ("http://a.com; http://b.com")
# is correctly seen as two separate matches rather than one URL that
# swallows the delimiter - which, same as the hash/IP checks, means it
# gets no link at all (see _extract_single_url below).
_URL_RE = re.compile(r"https?://[^\s;\"'<>]+", re.IGNORECASE)

# Trailing punctuation that's almost always sentence/log punctuation
# rather than part of the URL itself (a period ending a sentence, a
# closing paren/bracket wrapping the URL, a trailing comma, etc.).
_URL_TRAILING_PUNCT = ".,;:!?)]}'\""


def _extract_single_url(value):
    """Returns the one URL found in `value`, or None if there isn't
    exactly one (zero, or more than one - see _URL_RE's docstring for why
    more than one means "no link" rather than "link the first one")."""
    matches = _URL_RE.findall(value)
    if len(matches) != 1:
        return None
    url = matches[0].rstrip(_URL_TRAILING_PUNCT)
    return url or None


def _vt_url_id(url):
    """VirusTotal's URL identifier: the URL, base64 (URL-safe) encoded
    with the '=' padding stripped - this is the same identifier scheme
    VirusTotal's own API/GUI uses, computed entirely locally (no lookup,
    no network call - just building the link, exactly like the hash/IP
    links above)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def virustotal_url(value):
    """Returns a VirusTotal GUI lookup URL for `value`, or None. Handles
    three cases: `value` is - in its entirety - a single IPv4/IPv6
    address or an MD5/SHA1/SHA256 hash (fullmatch), or `value` contains
    exactly one http(s) URL somewhere in it (see _extract_single_url).
    Used to decide whether an extracted field's value gets a clickable
    "VT" lookup link.

    The hash/IP checks deliberately require the WHOLE value to be one of
    these (fullmatch, not "contains one somewhere in a longer string") so
    a multi-value field produced by the join_list transform (e.g. a
    Sentinel alert's aggregated "10.1.2.3; 10.1.2.4") never produces a
    link that silently points at only the first of several values - only
    a clean single-value field gets a lookup link. The URL check applies
    the same "exactly one, or no link" rule, just via "contains" instead
    of "is", since URL-bearing fields are more often embedded in a bit of
    surrounding text."""
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if _HASH_RE.fullmatch(v):
        return f"https://www.virustotal.com/gui/file/{v.lower()}"
    if _IPV4_RE.fullmatch(v):
        return f"https://www.virustotal.com/gui/ip-address/{v}"
    if _IPV6_CANDIDATE_RE.fullmatch(v) and _looks_like_ipv6(v):
        return f"https://www.virustotal.com/gui/ip-address/{v}"
    url = _extract_single_url(v)
    if url:
        return f"https://www.virustotal.com/gui/url/{_vt_url_id(url)}"
    return None


# Order matters here: keyword replacements run first (most certain,
# analyst-specified), then the JSON-key-based detection below
# (structurally certain - the log itself labeled the field), then
# narrower/more-specific regex patterns before broader ones, so e.g. a
# hostname is redacted as HOST_n before whatever is left of its parent
# domain gets swept into DOMAIN_n.
SANITIZE_CATEGORIES = ["json_fields", "email", "mac", "sid", "ipv6", "ipv4", "hostname", "domain"]

SANITIZE_CATEGORY_LABELS = {
    "json_fields": "Account/Host/Domain via JSON fields",
    "email": "Email address",
    "mac": "MAC address",
    "sid": "Windows SID",
    "ipv6": "IPv6 address",
    "ipv4": "IPv4 address",
    "hostname": "Hostname",
    "domain": "Domain name",
}

# --------------------------------------------------------------------------
# JSON-key-based detection: a bare username ("jdoe") or an unconventional
# hostname ("SFO-FIN-01") has no reliable generic regex shape - the only
# way to know it's sensitive is that the log itself labels the field. The
# Sanitize Logs tab's input is very often JSON (or JSON-ish), so these
# specific dotted field names are pulled out structurally instead of
# guessed at, using the same tolerant JSON parsing and case-insensitive
# dot-path lookup (parse_json_blobs_verbose / get_path) the field-mapping
# parser uses elsewhere in this file.
#
# These fields aren't all the same KIND of thing - some are usernames,
# some are device/asset names, some are Windows domain names - so rather
# than force them into separate "account" vs "hostname" categories (which
# gets confusing/wrong for a field like process.account_domain, which is
# a domain, not a username or a host), they're all treated as one
# "json_fields" category and redacted with a plain "REDACTED" literal
# instead of a numbered placeholder. This trades away the "same value
# gets the same number everywhere" bookkeeping for these specific fields
# in exchange for not mischaracterizing what kind of value each one is.
_JSON_SENSITIVE_KEYS = [
    "source_user", "destination_user", "source_account", "destination_account",
    "account", "user",
    "process.username", "parent_process.username",
    "destination_asset", "source_asset", "hostname",
    "process.account_domain", "parent_process.account_domain",
    "process.exe_file.owner", "parent_process.exe_file.owner",
]


def _extract_json_field_values(raw_text, key_paths):
    """Parse `raw_text` as JSON (single object, array, or newline-
    delimited - reusing parse_json_blobs_verbose, the same tolerant
    parser the log-parsing side of this app uses) and pull out every
    distinct, non-trivial string value found at any of `key_paths`
    (dotted, case-insensitive, resolved via get_path) across every
    record. Values are deduplicated case-insensitively, keeping the
    first casing seen, so "jdoe" and "JDoe" showing up in two different
    fields don't get treated as two different accounts downstream.
    Returns [] if the text isn't parseable as JSON at all (or has no
    matching fields) - the JSON-key stage is simply a no-op for freeform
    text that has no structure to read fields from."""
    objs, _ = parse_json_blobs_verbose(raw_text)
    if not objs:
        return []
    seen_lower = set()
    values = []
    for obj in objs:
        for path in key_paths:
            val = get_path(obj, path)
            if val in (None, ""):
                continue
            val = str(val).strip()
            if len(val) < 2:
                continue
            key = val.lower()
            if key in seen_lower:
                continue
            seen_lower.add(key)
            values.append(val)
    return values


def _boundary_pattern(value):
    """Compile a case-insensitive regex matching `value` literally
    wherever it appears in text - used to sweep the ENTIRE pasted log for
    other mentions of a value pulled out of one specific JSON field, not
    just the field itself, so e.g. a username named in a "user" field
    also gets redacted anywhere it's mentioned again in a free-text log
    line elsewhere in the same paste.

    Anchored with a \\b word boundary on whichever end(s) actually border
    a word character - e.g. "CONTOSO\\jdoe" or "S-1-5-18" get boundaries
    on both ends since both their first and last characters are word
    characters, while a value that starts or ends with punctuation just
    isn't anchored on that side. This keeps a short value like "jdoe"
    from matching inside a longer word ("jdoexyz") while still working
    for values containing internal punctuation a plain \\b...\\b wrap
    would otherwise choke on."""
    left = r"\b" if (value[0].isalnum() or value[0] == "_") else ""
    right = r"\b" if (value[-1].isalnum() or value[-1] == "_") else ""
    return re.compile(left + re.escape(value) + right, re.IGNORECASE)


def _apply_stage(text, pattern, make_replacement, spans):
    """Run one substitution stage of the sanitize pipeline: replace every
    `pattern` match in `text` using `make_replacement(match) -> str`,
    while also carrying forward `spans` - a list of (start, end)
    highlight spans left over from EARLIER stages, in `text`'s
    coordinates - remapped to their new positions in the resulting
    string. A new span is added for each of THIS stage's own actual
    replacements (skipped when make_replacement returns the exact same
    text as the match, e.g. an IPv6 candidate that turned out to be a
    plain timestamp and was left alone).

    This exists because sanitize_text() runs several regex substitutions
    back to back, each seeing the PREVIOUS stage's output - so any
    (start, end) offsets computed by an earlier stage would otherwise be
    silently invalidated the moment a later stage inserts or removes any
    text before them. Threading spans through _apply_stage like this is
    what lets sanitize_text() hand the UI an exact set of "what changed"
    highlight spans covering the whole pipeline, not just the last
    stage."""
    matches = list(pattern.finditer(text))
    if not matches:
        return text, list(spans)

    old_spans_sorted = sorted(spans)
    span_idx = 0
    parts = []
    new_spans = []
    old_pos = 0
    new_pos = 0

    def flush_verbatim(old_end):
        nonlocal old_pos, new_pos, span_idx
        chunk = text[old_pos:old_end]
        parts.append(chunk)
        delta = new_pos - old_pos
        while (
            span_idx < len(old_spans_sorted)
            and old_spans_sorted[span_idx][0] >= old_pos
            and old_spans_sorted[span_idx][1] <= old_end
        ):
            s, e = old_spans_sorted[span_idx]
            new_spans.append((s + delta, e + delta))
            span_idx += 1
        new_pos += len(chunk)
        old_pos = old_end

    for m in matches:
        flush_verbatim(m.start())
        # Any not-yet-consumed old span that starts inside this match
        # overlaps content that's about to be replaced - drop it. This
        # is rare in practice, since the categories below deliberately
        # run narrow-to-broad specifically to avoid one stage's
        # placeholder text getting caught by a later stage's pattern.
        while span_idx < len(old_spans_sorted) and old_spans_sorted[span_idx][0] < m.end():
            span_idx += 1
        original = m.group(0)
        repl = make_replacement(m)
        parts.append(repl)
        if repl != original:
            new_spans.append((new_pos, new_pos + len(repl)))
        new_pos += len(repl)
        old_pos = m.end()

    flush_verbatim(len(text))
    new_text = "".join(parts)
    new_spans.sort()
    return new_text, new_spans


def sanitize_text(text, categories=None, keyword_pairs=None):
    """Redact sensitive values from pasted log text before sharing it
    outside the team (a vendor, a public ticket, a write-up). Every
    value any category detects is replaced with the exact same plain
    "REDACTED" literal - not a numbered placeholder (no EMAIL_1, IP_2,
    HOST_1, etc.) - so nothing about the real value (or even which
    category caught it) can be reconstructed from the output text
    itself. This deliberately gives up the earlier design's "same value
    gets the same number everywhere" bookkeeping (which let a reader
    tell whether two redacted IPs were the same IP or different ones) in
    exchange for a simpler, more conservative guarantee: sanitized
    output never contains anything BUT the literal word REDACTED where a
    match was found. `counts` (see below) still separately reports how
    many DISTINCT values each category caught, for the on-screen summary
    - that bookkeeping happens internally and is never reflected in the
    output text.

    categories: dict of {category_name: bool} controlling which built-in
    detectors run (see SANITIZE_CATEGORIES for the valid names); a
    category missing from the dict is treated as enabled. Pass {} or
    None to run every category.

    keyword_pairs: list of (keyword, replacement) pairs applied FIRST,
    before any automatic detection - a literal, case-insensitive
    substring replace for organization-specific terms (a company name,
    an internal project codename) that no generic pattern could know
    about. Every occurrence of a given keyword becomes the exact
    replacement text supplied (an analyst-chosen string, not
    necessarily "REDACTED").

    Before the regex categories below run, this also tries to parse
    `text` as JSON and pull out well-known fields (_JSON_SENSITIVE_KEYS,
    the "json_fields" category) - see the comment above that list for why
    a bare username or an unconventionally-named host needs to be found
    this way rather than by regex. Every value found this way is swept
    across the WHOLE text (case-insensitively), not just replaced at its
    own JSON field, so the same value mentioned again later in a
    free-text log line - or in a different pasted record - is redacted
    too. Values are processed longest-first so a compound value that
    happens to contain a shorter one (e.g. a device name like
    "jdoe-laptop" that embeds the username "jdoe") is redacted as a
    single clean whole rather than leaving a partial fragment like
    "REDACTED-laptop" behind.

    Because every category renders identically, a value redacted by one
    category (e.g. a hostname immediately followed by its parent domain,
    "srv-dc01.contoso.com") can end up fully absorbed into a single
    "REDACTED" by a LATER stage's pattern - e.g. the domain stage seeing
    "REDACTED.contoso.com" and matching the whole thing as one
    dotted-label candidate, since the literal word "REDACTED" is itself
    a syntactically valid domain label. This is harmless from a data-
    safety standpoint (nothing real leaks either way) but means `counts`
    can occasionally attribute a merged match to whichever category's
    stage runs last over it, rather than splitting credit between both.

    Returns (sanitized_text, counts, spans):
      - counts maps each category name to the number of DISTINCT values
        that were replaced in that category (0 if the category was
        disabled or nothing matched), even though every one of them
        renders as the same "REDACTED" text in the output.
      - spans is a list of (start, end) character offsets into
        sanitized_text marking every place the text actually changed -
        a "REDACTED" literal or a custom keyword replacement - so the UI
        can highlight exactly what was redacted, the same way
        find_unresolved_tag_spans powers the unresolved-tag highlight in
        the ticket output box.

    Detection is heuristic/best-effort, the same spirit as the rest of
    this app's field-mapping fallbacks - review sanitized output before
    sharing it, don't assume it's perfect. In particular the REGEX-based
    hostname detection is deliberately scoped to recognized computer-name
    conventions (WORKSTATION-07, srv-dc01, ...) rather than "any
    hyphenated word", specifically so it doesn't also swallow ticket/
    incident references like INC-1234 - the JSON-key-based detection
    above doesn't have that limitation, since a "hostname"/
    "destination_asset"/"source_asset" field is redacted regardless of
    whether its value happens to look like a recognized naming
    convention.
    """
    if categories is None:
        categories = {}
    keyword_pairs = keyword_pairs or []

    def enabled(cat):
        return categories.get(cat, True)

    counts = {cat: 0 for cat in SANITIZE_CATEGORIES}
    value_maps = {cat: {} for cat in SANITIZE_CATEGORIES}

    def make_redactor(cat):
        """Every match in `cat` becomes the same plain "REDACTED"
        literal, for every category - not a numbered placeholder. Still
        keys the seen-values map case-insensitively (so "jdoe" and
        "JDoe", or two mentions of the same IP, count as one distinct
        value for the summary count) and still records each newly-seen
        value so `counts` reports how many distinct values were caught,
        even though the replacement text itself never varies."""
        vmap = value_maps[cat]

        def _sub(m):
            raw = m.group(0)
            key = raw.lower()
            if key not in vmap:
                vmap[key] = "REDACTED"
                counts[cat] += 1
            return "REDACTED"
        return _sub

    spans = []

    for keyword, replacement in keyword_pairs:
        keyword = (keyword or "").strip()
        if not keyword:
            continue
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        text, spans = _apply_stage(text, pattern, lambda m, r=(replacement or ""): r, spans)

    # JSON-key-based detection - runs before the generic regex categories
    # below so a value found this way (and every other mention of it
    # anywhere in the text) is already redacted before a looser pattern
    # gets a chance to see it. Extracted values are swept longest-first
    # so a compound value that happens to CONTAIN a shorter one (e.g. a
    # device name like "jdoe-laptop" that embeds the username "jdoe")
    # gets redacted as one clean whole before the shorter value's own
    # stage would otherwise leave a partial "REDACTED-laptop" fragment
    # behind.
    if enabled("json_fields"):
        json_sub = make_redactor("json_fields")
        json_values = sorted(
            _extract_json_field_values(text, _JSON_SENSITIVE_KEYS), key=len, reverse=True
        )
        for val in json_values:
            text, spans = _apply_stage(text, _boundary_pattern(val), json_sub, spans)

    if enabled("email"):
        text, spans = _apply_stage(text, _EMAIL_RE, make_redactor("email"), spans)

    if enabled("mac"):
        text, spans = _apply_stage(text, _MAC_RE, make_redactor("mac"), spans)

    if enabled("sid"):
        text, spans = _apply_stage(text, _SID_RE, make_redactor("sid"), spans)

    if enabled("ipv6"):
        ipv6_sub = make_redactor("ipv6")
        text, spans = _apply_stage(
            text, _IPV6_CANDIDATE_RE,
            lambda m: ipv6_sub(m) if _looks_like_ipv6(m.group(0)) else m.group(0),
            spans,
        )

    if enabled("ipv4"):
        text, spans = _apply_stage(text, _IPV4_RE, make_redactor("ipv4"), spans)

    if enabled("hostname"):
        text, spans = _apply_stage(text, _HOSTNAME_RE, make_redactor("hostname"), spans)

    if enabled("domain"):
        domain_sub = make_redactor("domain")
        text, spans = _apply_stage(
            text, _DOMAIN_CANDIDATE_RE,
            lambda m: domain_sub(m) if _looks_like_domain(m.group(0)) else m.group(0),
            spans,
        )

    return text, counts, spans


# --------------------------------------------------------------------------
# Text Tools tab - general-purpose text munging, independent of the
# structured log parsing/sanitizing above. Each function takes a string
# and returns a string; apply_text_tools() chains whichever ones the UI
# checkboxes select, always in the fixed order defined by
# TEXT_TOOL_OPERATIONS below, regardless of the order they were checked
# in, so the same set of selections always produces the same result.
# --------------------------------------------------------------------------


def text_tool_base64_decode(text):
    """Base64-decode `text`, tolerating stray non-alphabet junk in/around
    the encoded data: anything that isn't part of the base64 alphabet
    (A-Z a-z 0-9 + / =) - line breaks, surrounding quotes, colons,
    spaces, etc. - is stripped first, then the cleaned string is padded
    out to a multiple of 4 characters if needed and decoded. Note this
    can only strip PUNCTUATION/whitespace junk, not an alphanumeric
    label glued directly onto the payload (e.g. "b64=AbC...") - a label
    made of letters/digits is indistinguishable from real base64 data by
    a charset filter alone, so it is decoded as-is (and will corrupt the
    result) rather than silently guessed at. Any NUL bytes in the
    decoded result are dropped (a common artifact of decoding a UTF-16
    blob as if it were UTF-8/Latin-1), and the remaining bytes are
    decoded as UTF-8 with unrepresentable bytes replaced rather than
    raising, so a partially-binary blob still produces a readable result
    instead of an error. Returns a bracketed error message (not a raised
    exception) if nothing usable survives the cleanup or the cleaned
    text isn't valid base64, so a bad selection doesn't crash the tab."""
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", text)
    if not cleaned:
        return "[base64 decode error: no base64 data found in input]"
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError) as e:
        return f"[base64 decode error: {e}]"
    raw = raw.replace(b"\x00", b"")
    return raw.decode("utf-8", errors="replace")


def text_tool_hex_decode(text):
    """Decode a hex-encoded blob, tolerating separators/junk (spaces,
    '0x' prefixes, colons, newlines) by stripping anything that isn't a
    hex digit before decoding. '0x'/'0X' prefixes are stripped as a unit
    first - the leading '0' in "0x48" is itself a valid hex digit, so
    stripping only the 'x' would leave a stray '0' behind and shift
    every following byte pairing by one nibble. An odd trailing nibble
    (left over after stripping) is dropped rather than erroring. NUL
    bytes are removed from the decoded result for the same reason as
    base64 decode above, and the remaining bytes are decoded as UTF-8
    with replacement."""
    cleaned = re.sub(r"0[xX]", "", text)
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", cleaned)
    if not cleaned:
        return "[hex decode error: no hex data found in input]"
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"[hex decode error: {e}]"
    raw = raw.replace(b"\x00", b"")
    return raw.decode("utf-8", errors="replace")


def text_tool_url_decode(text):
    """Percent-decode URL-encoded text (%20, %2F, etc.) and also decode
    '+' as a space (the application/x-www-form-urlencoded convention used
    in URL query strings), via the standard library's unquote_plus - no
    special-casing needed since it already leaves ordinary text
    untouched."""
    return _url_unquote(text)


def text_tool_extract_emails(text):
    """Every email address found in `text` (reusing the same pattern
    sanitize_text uses to detect them), one per line, in the order they
    appear - not deduplicated, since Remove Duplicates is its own
    separate, explicit operation an analyst can additionally check."""
    return "\n".join(_EMAIL_RE.findall(text))


def text_tool_extract_ips(text):
    """Every IPv4 and IPv6 address found in `text` (reusing the same
    patterns sanitize_text uses), one per line, IPv4 matches first then
    IPv6, in the order each group appears - not deduplicated, for the
    same reason as text_tool_extract_emails above."""
    ipv4_matches = _IPV4_RE.findall(text)
    ipv6_matches = [m for m in _IPV6_CANDIDATE_RE.findall(text) if _looks_like_ipv6(m)]
    return "\n".join(ipv4_matches + ipv6_matches)


_FILE_PATH_EXTENSIONS = (
    "pdf", "txt", "csv", "tsv", "xlsx", "xls", "doc", "docx", "ppt", "pptx",
    "exe", "dll", "msi", "bat", "cmd", "ps1", "sh", "py", "js", "json",
    "xml", "log", "ini", "cfg", "conf", "config", "yaml", "yml",
    "zip", "rar", "7z", "tar", "gz",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico",
    "mp3", "mp4", "avi", "mov", "wav",
    "html", "htm", "css", "sql", "db", "bak", "tmp", "dat", "md", "rtf",
    "eml", "msg",
)

# A file name/path candidate: an optional Windows drive letter (C:\),
# UNC prefix (\\server\), or relative-path prefix (.\ or ..\), followed
# by zero or more directory segments, then a final "name.ext" where ext
# is one of the common extensions above (see _FILE_PATH_EXTENSIONS - not
# exhaustive, but covers the everyday document/executable/archive/
# script/media/log types a SOC analyst runs into). Directory segments
# may contain spaces (real Windows paths often do - "Program Files", "My
# Documents") since they're always terminated by a \ or /, but the final
# filename itself may not, so the match can't run on past the end of a
# sentence ("...attached the report.pdf to the ticket" only matches
# "report.pdf", not the whole sentence). Also matches a bare filename
# with no path in front of it at all.
_FILE_PATH_RE = re.compile(
    r'(?<!\w)(?:[A-Za-z]:\\|\\\\|\.{1,2}[\\/])?'
    r'(?:[\w.\- ]+[\\/])*'
    r'[\w.\-]+\.(?:' + "|".join(_FILE_PATH_EXTENSIONS) + r')\b',
    re.IGNORECASE,
)


def text_tool_extract_paths(text):
    """Every file name/path found in `text` whose extension is one of
    _FILE_PATH_EXTENSIONS above, one per line, in the order they appear -
    not deduplicated, for the same reason as text_tool_extract_emails/
    text_tool_extract_ips above. Matches a bare filename on its own
    ("report.pdf") as well as a full Windows path (drive letter or UNC
    share) or relative/Unix-style path in front of it. Heuristic/best-
    effort like the rest of this app's extraction tools - review the
    result, especially for filenames that legitimately contain spaces."""
    return "\n".join(_FILE_PATH_RE.findall(text))


def text_tool_remove_whitespace(text):
    """Collapse whitespace down to the minimum needed to keep the text
    readable one-entry-per-line: within each line, every run of
    horizontal whitespace (spaces/tabs) becomes a single space and
    leading/trailing horizontal whitespace is trimmed; blank or
    whitespace-only lines are dropped entirely, which is what collapses
    multiple consecutive line breaks down to a single line break between
    the remaining lines."""
    lines = text.splitlines()
    cleaned = [re.sub(r"[^\S\n]+", " ", line).strip() for line in lines]
    return "\n".join(line for line in cleaned if line)


def text_tool_sort_alphabetically(text):
    """Sort non-blank lines alphabetically (case-insensitively, so
    "Zebra" and "apple" sort by letter rather than by ASCII case),
    preserving each line's original text/case in the output."""
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(sorted(lines, key=str.lower))


def text_tool_remove_duplicates(text):
    """Drop repeat lines, matching case-insensitively (so "jdoe" and
    "JDoe" count as the same line) while keeping the first occurrence's
    original text/case and original order - not sorted, so this can be
    used on its own to de-duplicate a list without disturbing its order."""
    seen = set()
    out = []
    for line in text.splitlines():
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return "\n".join(out)


def text_tool_defang(text):
    """Defang URLs/IPs so they're not clickable/"live" when pasted into
    a ticket, chat, or email: http/https -> hxxp/hxxps (case-preserving
    on the first letter so "Http" -> "Hxxp"), '://' -> '[://]', and every
    literal '.' -> '[.]'. This is a blunt, whole-text replacement (not
    URL-aware extraction first) matching how analysts conventionally
    defang IOCs by hand."""
    def _hxxp(m):
        word = m.group(0)
        prefix = word[:4]
        rest = word[4:]
        if prefix[0].isupper():
            hxxp = "Hxxp" if prefix[1:].islower() else "HXXP"
        else:
            hxxp = "hxxp"
        return hxxp + rest

    text = re.sub(r"https?", _hxxp, text, flags=re.IGNORECASE)
    text = text.replace("://", "[://]")
    text = text.replace(".", "[.]")
    return text


TEXT_TOOL_OPERATIONS = [
    ("base64_decode", "Base64 Decode (strip junk, drop NUL bytes)", text_tool_base64_decode),
    ("hex_decode", "From Hex Code", text_tool_hex_decode),
    ("url_decode", "URL Decode", text_tool_url_decode),
    ("extract_emails", "Extract Email Addresses", text_tool_extract_emails),
    ("extract_ips", "Extract IP Addresses", text_tool_extract_ips),
    ("extract_paths", "Extract File Names/Paths", text_tool_extract_paths),
    ("remove_whitespace", "Remove Extra Whitespace", text_tool_remove_whitespace),
    ("sort", "Sort Alphabetically", text_tool_sort_alphabetically),
    ("dedupe", "Remove Duplicates (not case-sensitive)", text_tool_remove_duplicates),
    ("defang", "Defang URLs/IPs", text_tool_defang),
]
_TEXT_TOOL_FUNCS = {key: func for key, _label, func in TEXT_TOOL_OPERATIONS}


def apply_text_tools(text, operations):
    """Run the selected text-tool operations over `text`, always in the
    fixed pipeline order given by TEXT_TOOL_OPERATIONS above - decode
    (Base64/Hex/URL), then extract (Email/IP), then clean up (whitespace/
    sort/dedupe), then Defang last - regardless of what order
    `operations` lists them in, so a given set of checked boxes always
    produces the same result. Defang runs last on purpose: if it ran
    before extraction, the '[.]'/'[://]' it inserts would break the
    email/IP regexes used by the extract operations.

    `extract_emails`, `extract_ips`, and `extract_paths` are handled
    together, once, the first time any of them is reached in the fixed
    order: all three run against the same input text (rather than one's
    output feeding the next, which would find nothing) and their results
    are combined, emails first, then IPs, then file names/paths.
    `operations` is any iterable of the operation keys from
    TEXT_TOOL_OPERATIONS; unknown keys are ignored."""
    wanted = set(operations)
    extraction_done = False
    extraction_keys = ("extract_emails", "extract_ips", "extract_paths")
    for key, _label, func in TEXT_TOOL_OPERATIONS:
        if key not in wanted:
            continue
        if key in extraction_keys:
            if extraction_done:
                continue
            parts = [_TEXT_TOOL_FUNCS[k](text) for k in extraction_keys if k in wanted]
            text = "\n".join(p for p in parts if p)
            extraction_done = True
            continue
        text = func(text)
    return text


# --------------------------------------------------------------------------
# Spell-check (Analysis / Notes / Ticket Output / Template editor boxes
# ONLY - deliberately never run against raw log/JSON/path text, where
# nearly every token would trip a general-English dictionary)
# --------------------------------------------------------------------------

_SPELLCHECKER = None
_SPELLCHECKER_LOAD_FAILED = False


def _get_spellchecker():
    """Lazily constructs the shared SpellChecker instance on first use
    (loading its dictionary has a small startup cost, not worth paying
    before the window even appears) and reuses it after that. Returns
    None - permanently, without retrying - if the pyspellchecker package
    isn't installed or fails to load its dictionary for any reason, so
    every function in this section degrades to "no spelling issues
    found" instead of crashing the app over an optional feature."""
    global _SPELLCHECKER, _SPELLCHECKER_LOAD_FAILED
    if _SPELLCHECKER is not None or _SPELLCHECKER_LOAD_FAILED:
        return _SPELLCHECKER
    if SpellChecker is None:
        _SPELLCHECKER_LOAD_FAILED = True
        return None
    try:
        _SPELLCHECKER = SpellChecker()
    except Exception:
        _SPELLCHECKER_LOAD_FAILED = True
        return None
    return _SPELLCHECKER


_SPELLCHECK_WORD_RE = re.compile(r"[A-Za-z']+")

# Extremely common SOC/IT/cybersecurity vocabulary that a general-purpose
# English dictionary doesn't recognize (verified against pyspellchecker's
# bundled corpus - things like "malware", "hostname", and "timestamp"
# would otherwise be flagged as misspelled on nearly every write-up,
# which would make the feature actively annoying rather than helpful).
# This is a supplement to, not a replacement for, the analyst's own
# per-install custom dictionary (Add to Dictionary in the right-click
# menu) - it covers the vocabulary almost every analyst uses, not
# vendor/product-specific names, which are what the custom dictionary is
# for.
_KNOWN_TECH_TERMS = {
    "adware", "allowlist", "anti-virus", "apt", "backend", "blueteam",
    "botnet", "brute-force", "bruteforce", "checksum", "clickjacking",
    "credentialed", "cyberattack", "cybercrime", "cyberespionage",
    "cybersecurity", "cyberthreat", "datacenter", "deauthenticate",
    "deauthenticated", "defang", "defanged", "denylist", "deprovision",
    "deprovisioned", "dlp", "edr", "exfil", "exfiltration", "failover",
    "fileless", "filename", "frontend", "geoip", "geolocation",
    "hashcode", "hostname", "iam", "infosec", "ioa", "ioc", "iocs",
    "keylogger", "logoff", "logon", "lookup", "loopback", "malspam",
    "malware", "metadata", "mfa", "middleware", "misconfiguration",
    "misconfigured", "multifactor", "offboarding", "onboarding", "pcap",
    "pentest", "pentesting", "purpleteam", "ransomware", "redteam",
    "reimage", "reimaged", "rootkit", "runbook", "sandboxing",
    "sanitization", "shellcode", "siem", "signon", "smishing", "soar",
    "spearphishing", "spyware", "sso", "subnet", "timestamp",
    "typosquatting", "uncredentialed", "unpatched", "uptime",
    "useragent", "vishing", "vpn", "webshell", "whitelist", "xdr",
    "zero-day", "zeroday",
}


def find_misspelled_word_spans(text, known_words=None):
    """Returns [(start_offset, end_offset, word), ...] for every word in
    `text` that isn't recognized - used to underline likely misspellings
    in the Analysis/Notes/Ticket Output/Template editor boxes only.
    Deliberately conservative to keep false positives low: skips
    anything under 3 letters (initials, units), ALL-CAPS tokens
    (acronyms and product names like SOC, VT, RAPID7 are routine in this
    app's text and are not misspellings), anything in the bundled
    _KNOWN_TECH_TERMS list, and anything in `known_words` (the analyst's
    own custom dictionary, case-insensitive). Returns [] with no error if
    pyspellchecker isn't installed."""
    checker = _get_spellchecker()
    if checker is None or not text:
        return []
    known = _KNOWN_TECH_TERMS | {w.lower() for w in (known_words or ())}
    spans = []
    for m in _SPELLCHECK_WORD_RE.finditer(text):
        word = m.group(0)
        if len(word) < 3 or word.isupper() or word.lower() in known:
            continue
        if checker.unknown([word]):
            spans.append((m.start(), m.end(), word))
    return spans


def spelling_suggestions(word, limit=5):
    """Up to `limit` candidate corrections for `word`, pyspellchecker's
    own best guess first (if it has one), for the right-click context
    menu's suggestion list. Returns [] if pyspellchecker isn't
    installed."""
    checker = _get_spellchecker()
    if checker is None or not word:
        return []
    candidates = checker.candidates(word) or set()
    lowered = word.lower()
    candidates.discard(lowered)
    best = checker.correction(word)
    ordered = []
    if best and best != lowered:
        ordered.append(best)
    for c in sorted(candidates):
        if c not in ordered:
            ordered.append(c)
    return ordered[:limit]


# --------------------------------------------------------------------------
# SQLite data layer
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,      -- 'escalation' or 'false_positive'
    name TEXT NOT NULL,
    alert_type TEXT,
    body TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    raw_logs TEXT,
    analysis TEXT,
    output TEXT,
    extracted_json TEXT,
    status TEXT DEFAULT 'Open',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS sanitize_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL,
    replacement TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS custom_dictionary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS query_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    syntax TEXT NOT NULL,        -- 'leql' or 'kql'
    profile_id TEXT NOT NULL DEFAULT '',  -- '' means generic/any profile
    label TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
);
"""

SEED_TEMPLATES = [
    (
        "escalation",
        "Suspicious O365 Authentication",
        "Authentication",
        "ESCALATION - Suspicious O365 Authentication\n"
        "Detected: {timestamp}\n\n"
        "Summary:\n"
        "User #user authenticated to O365 (#event_id) with result #result from "
        "source IP #src_ip (#geoip_city, #geoip_region, #geoip_country - "
        "#geoip_org, connection type #geoip_connection_type).\n"
        "Device: #device_display_name (OS: #device_os, Browser: #device_browser) "
        "- Compliant: #device_compliant, Managed: #device_managed, Trust Type: "
        "#device_trust_type. Sign-in request type: #request_type.\n\n"
        "Analysis:\n"
        "<analyst to summarize why this is suspicious - impossible travel, "
        "unfamiliar geo, non-compliant/unmanaged device, off-hours access, MFA "
        "bypass indicators, etc.>\n\n"
        "Recommended Action:\n"
        "- Confirm activity with account owner\n"
        "- Consider forcing password reset / revoking sessions if unconfirmed\n"
        "- Review sign-in history for #user over the last 7 days\n",
    ),
    (
        "false_positive",
        "O365 Authentication (Known Travel/Device)",
        "Authentication",
        "This alert was reviewed and determined to be a FALSE POSITIVE.\n\n"
        "User #user signed in to O365 from #geoip_city, #geoip_region, "
        "#geoip_country (source IP #src_ip) on a compliant/managed device "
        "(#device_display_name). This is consistent with known travel / an "
        "approved device for this user.\n\n"
        "No further action required. Closing as benign - confirmed authorized "
        "sign-in.\n",
    ),
    (
        "escalation",
        "Suspicious O365 Inbox Rule",
        "Inbox Rule",
        "ESCALATION - Suspicious O365 Inbox Rule Change\n"
        "Detected: {timestamp}\n\n"
        "Summary:\n"
        "User #user (#action) from client IP #client_ip. Rule name: #rule_name.\n"
        "Forward to: #forward_to | Redirect to: #redirect_to | Delete message: "
        "#delete_message | Move to folder: #move_to_folder | Stop processing "
        "rules: #stop_processing_rules\n"
        "All rule parameters: #all_parameters\n\n"
        "Analysis:\n"
        "<analyst to summarize why this is suspicious - external "
        "forwarding/redirect, rule deleting or hiding messages, unfamiliar "
        "client IP, account compromise indicators, etc.>\n\n"
        "Recommended Action:\n"
        "- Confirm rule creation with the account owner\n"
        "- If unconfirmed, disable/remove the rule and reset credentials\n"
        "- Review mailbox audit log for #user for other suspicious activity\n",
    ),
    (
        "false_positive",
        "O365 Inbox Rule (User-Created, Benign)",
        "Inbox Rule",
        "This alert was reviewed and determined to be a FALSE POSITIVE.\n\n"
        "Inbox rule \"#rule_name\" was created by #user from a known client IP "
        "(#client_ip) and is consistent with expected mailbox organization "
        "behavior (no external forwarding/redirect detected).\n\n"
        "No further action required. Closing as benign - confirmed "
        "user-created rule.\n",
    ),
    (
        "escalation",
        "Malicious Process Execution",
        "Process",
        "ESCALATION - Suspicious Process Execution\n"
        "Detected: {timestamp}\n\n"
        "Summary:\n"
        "Host #host (user: #user) executed #process (PID #process_pid) from "
        "#process_exe_path, working directory #working_dir.\n"
        "Command line: #cmdline\n"
        "Parent process: #parent_process (#parent_cmdline)\n"
        "SHA256: #process_sha256 | Signing status: #process_signing_status | "
        "Reputation: #process_reputation (threat level: #process_threat_level)\n\n"
        "Analysis:\n"
        "<analyst to summarize IOC matches, LOLBin usage, unsigned/unknown "
        "binary, unusual parent/child relationship, etc.>\n\n"
        "Recommended Action:\n"
        "- Isolate host #host pending investigation\n"
        "- Submit SHA256 #process_sha256 to threat intel / sandbox\n"
        "- Collect full process tree and any dropped files\n",
    ),
    (
        "false_positive",
        "Process Execution (Signed/Known Software)",
        "Process",
        "This alert was reviewed and determined to be a FALSE POSITIVE.\n\n"
        "Process #process (#cmdline) launched by #parent_process on host "
        "#host is signed (#process_signing_status) and has a known-good "
        "reputation (#process_reputation). This is consistent with "
        "legitimate software activity.\n\n"
        "No further action required. Closing as benign - verified legitimate "
        "process.\n",
    ),
]

# Starter query templates for the Query Builder tab. profile_id "" means
# generic - shown regardless of which profile was detected/selected, in
# addition to whatever's specific to that profile. Bodies use the same
# {field}/#field placeholder syntax as SEED_TEMPLATES (resolved against
# the parsed log's canonical field dict via fill_template), mixed with
# literal query syntax that stays as-is.
#
# KQL bodies use real Log Analytics table/column names (SigninLogs,
# DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents, OfficeActivity,
# and their real columns) - these are verified against actual Sentinel/
# Defender schemas, not guesses. LEQL is far more log-set-dependent, so
# only a couple of starter queries are seeded (in the style the analyst
# themselves confirmed, e.g. `where(account=... AND result=...)` for
# Ingress Authentication) - every query here, in both syntaxes, is meant
# as an editable starting point via "Manage Query Templates" below, not a
# guaranteed-correct final query - always review before running it.
SEED_QUERY_TEMPLATES = [
    (
        "leql", "rapid7_o365_signin", "Pivot by Account (Ingress Authentication)",
        "where(account=#account AND result=#result)",
    ),
    (
        "leql", "rapid7_o365_signin", "Pivot by Source IP (Ingress Authentication)",
        "where(source_ip=#src_ip)",
    ),
    (
        "leql", "rapid7_endpoint_process", "Pivot by Host (Endpoint Activity)",
        "where(hostname=#host)",
    ),
    (
        "leql", "rapid7_endpoint_process", "Pivot by Process Hash (Endpoint Activity)",
        "where(process.exe_file.hashes.sha256=#process_sha256)",
    ),
    (
        "leql", "Active Directory", "Pivot by User (Entra)",
        "where(source_user=#user)",
    ),
    (
        "leql", "", "Generic Full-Text Search",
        '"#user"',
    ),
    (
        "kql", "sentinel_signin", "Pivot by User (SigninLogs)",
        'SigninLogs\n| where UserPrincipalName == "#user"\n| order by TimeGenerated desc',
    ),
    (
        "kql", "sentinel_signin", "Pivot by Source IP (SigninLogs)",
        'SigninLogs\n| where IPAddress == "#src_ip"\n| order by TimeGenerated desc',
    ),
    (
        "kql", "sentinel_device_process", "Pivot by Host (Device Process Events)",
        'DeviceProcessEvents\n| where DeviceName == "#host"\n| order by ProcessCreationTime desc',
    ),
    (
        "kql", "sentinel_device_process", "Pivot by Hash (Device Process Events)",
        'DeviceProcessEvents\n| where SHA256 == "#process_sha256" or InitiatingProcessSHA256 == "#process_sha256"\n'
        '| order by ProcessCreationTime desc',
    ),
    (
        "kql", "sentinel_device_network", "Pivot by IP (Device Network Events)",
        'DeviceNetworkEvents\n| where RemoteIP == "#dst_ip" or LocalIP == "#src_ip"\n| order by TimeGenerated desc',
    ),
    (
        "kql", "files_copied_to_usb", "Pivot by Host (Files Copied to USB)",
        'DeviceEvents\n| where DeviceName == "#host"\n| order by TimeGenerated desc',
    ),
    (
        "kql", "sentinel_office_activity", "Pivot by User (OfficeActivity)",
        'OfficeActivity\n| where UserId == "#user"\n| order by TimeGenerated desc',
    ),
    (
        "kql", "", "Generic Full-Text Search",
        'search "#user"',
    ),
]


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DB:
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        cur = self.conn.execute("SELECT COUNT(*) AS c FROM templates")
        if cur.fetchone()["c"] == 0:
            self._seed_templates()
        cur = self.conn.execute("SELECT COUNT(*) AS c FROM query_templates")
        if cur.fetchone()["c"] == 0:
            self._seed_query_templates()
        self._migrate_legacy_cases_table()
        self._migrate_template_category_and_names()
        self._migrate_add_incident_status()

    def _migrate_add_incident_status(self):
        """One-time migration: older versions of this app created the
        'incidents' table without a 'status' column. Add it (defaulting
        existing rows to 'Open') so upgrading never loses data or crashes
        on the new status filter/UI."""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(incidents)")}
        if "status" not in cols:
            self.conn.execute("ALTER TABLE incidents ADD COLUMN status TEXT DEFAULT 'Open'")
            self.conn.execute("UPDATE incidents SET status='Open' WHERE status IS NULL")
            self.conn.commit()

    def _migrate_template_category_and_names(self):
        """One-time migration: earlier versions used 'canned' as the
        template category (now 'false_positive'), and baked
        '- Escalation' / '- False Positive' suffixes into the seed
        template names, which reads redundantly now that the category is
        also shown as a '[Escalation]' / '[False Positive]' prefix
        wherever templates are listed. Renames are exact-match only, so a
        template you've already renamed yourself is left alone."""
        self.conn.execute("UPDATE templates SET category='false_positive' WHERE category='canned'")
        rename_map = {
            "Suspicious O365 Authentication - Escalation": "Suspicious O365 Authentication",
            "O365 Authentication - False Positive (Known Travel/Device)": "O365 Authentication (Known Travel/Device)",
            "Suspicious O365 Inbox Rule - Escalation": "Suspicious O365 Inbox Rule",
            "O365 Inbox Rule - False Positive (User-Created, Benign)": "O365 Inbox Rule (User-Created, Benign)",
            "Malicious Process Execution - Escalation": "Malicious Process Execution",
            "Process Execution - False Positive (Signed/Known Software)": "Process Execution (Signed/Known Software)",
        }
        for old_name, new_name in rename_map.items():
            self.conn.execute("UPDATE templates SET name=? WHERE name=?", (new_name, old_name))
        self.conn.commit()

    def _migrate_legacy_cases_table(self):
        """One-time migration: if an older version of this app created a
        'cases' table (with ticket_id/title/analyst columns) and the new
        'incidents' table is still empty, copy the old rows over so no
        data gets silently lost across the rename."""
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cases'"
        )
        if not cur.fetchone():
            return
        cur = self.conn.execute("SELECT COUNT(*) AS c FROM incidents")
        if cur.fetchone()["c"] > 0:
            return
        try:
            rows = self.conn.execute(
                "SELECT title, raw_logs, analysis, output, extracted_json, "
                "created_at, updated_at FROM cases"
            ).fetchall()
        except sqlite3.OperationalError:
            return
        for r in rows:
            self.conn.execute(
                "INSERT INTO incidents (title, raw_logs, analysis, output, "
                "extracted_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    r["title"] or "Migrated Incident",
                    r["raw_logs"],
                    r["analysis"],
                    r["output"],
                    r["extracted_json"],
                    r["created_at"],
                    r["updated_at"],
                ),
            )
        self.conn.commit()

    def _seed_templates(self):
        now = _now()
        for category, name, alert_type, body in SEED_TEMPLATES:
            self.conn.execute(
                "INSERT INTO templates (category, name, alert_type, body, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (category, name, alert_type, body, now, now),
            )
        self.conn.commit()

    # ---- templates ----

    def list_templates(self, category=None):
        if category and category != "all":
            cur = self.conn.execute(
                "SELECT * FROM templates WHERE category = ? ORDER BY name",
                (category,),
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM templates ORDER BY category, name"
            )
        return [dict(r) for r in cur.fetchall()]

    def get_template(self, tid):
        cur = self.conn.execute("SELECT * FROM templates WHERE id = ?", (tid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def add_template(self, category, name, alert_type, body):
        now = _now()
        cur = self.conn.execute(
            "INSERT INTO templates (category, name, alert_type, body, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (category, name, alert_type, body, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_template(self, tid, category, name, alert_type, body):
        self.conn.execute(
            "UPDATE templates SET category=?, name=?, alert_type=?, body=?, "
            "updated_at=? WHERE id=?",
            (category, name, alert_type, body, _now(), tid),
        )
        self.conn.commit()

    def delete_template(self, tid):
        self.conn.execute("DELETE FROM templates WHERE id=?", (tid,))
        self.conn.commit()

    def export_templates(self, ids=None):
        """Return a list of plain dicts (category/name/alert_type/body) for
        the given template ids, or every template if ids is None. Omits
        id/timestamps on purpose so importing into another analyst's DB
        never collides with their own numbering - templates are matched
        by name on import instead."""
        if ids:
            rows = [self.get_template(i) for i in ids]
            rows = [r for r in rows if r]
        else:
            rows = self.list_templates()
        return [
            {"category": r["category"], "name": r["name"], "alert_type": r["alert_type"], "body": r["body"]}
            for r in rows
        ]

    def import_templates(self, templates, overwrite=False):
        """Import a list of template dicts (as produced by
        export_templates) from another analyst. Templates are matched by
        name: a name that already exists is left alone and reported as
        skipped unless overwrite=True, in which case the existing
        template's body/category/alert_type are replaced in place. New
        names are inserted as new templates. Returns (imported_count,
        skipped_names)."""
        existing = {t["name"]: t["id"] for t in self.list_templates()}
        imported = 0
        skipped = []
        for t in templates:
            if not isinstance(t, dict):
                continue
            name = (t.get("name") or "").strip()
            if not name:
                continue
            category = t.get("category") or "escalation"
            alert_type = t.get("alert_type") or ""
            body = t.get("body") or ""
            if name in existing:
                if overwrite:
                    self.update_template(existing[name], category, name, alert_type, body)
                    imported += 1
                    continue
                skipped.append(name)
                continue
            new_id = self.add_template(category, name, alert_type, body)
            existing[name] = new_id
            imported += 1
        return imported, skipped

    def _seed_query_templates(self):
        now = _now()
        for syntax, profile_id, label, body in SEED_QUERY_TEMPLATES:
            self.conn.execute(
                "INSERT INTO query_templates (syntax, profile_id, label, body, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (syntax, profile_id, label, body, now, now),
            )
        self.conn.commit()

    # ---- query templates (Query Builder tab: LEQL/KQL) ----

    def list_query_templates(self, syntax=None, profile_id=None):
        """Every query template, optionally filtered to one syntax
        ('leql'/'kql') and/or scoped to one profile. When profile_id is
        given, generic templates (profile_id == '') are always included
        alongside that profile's own - a profile_id of None (the
        default) means "don't filter by profile at all", used by the
        Manage Query Templates list which browses everything."""
        query = "SELECT * FROM query_templates"
        clauses = []
        params = []
        if syntax:
            clauses.append("syntax = ?")
            params.append(syntax)
        if profile_id is not None:
            clauses.append("(profile_id = ? OR profile_id = '')")
            params.append(profile_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY syntax, profile_id, label"
        cur = self.conn.execute(query, params)
        return [dict(r) for r in cur.fetchall()]

    def get_query_template(self, qid):
        cur = self.conn.execute("SELECT * FROM query_templates WHERE id = ?", (qid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def add_query_template(self, syntax, profile_id, label, body):
        now = _now()
        cur = self.conn.execute(
            "INSERT INTO query_templates (syntax, profile_id, label, body, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (syntax, profile_id, label, body, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_query_template(self, qid, syntax, profile_id, label, body):
        self.conn.execute(
            "UPDATE query_templates SET syntax=?, profile_id=?, label=?, body=?, "
            "updated_at=? WHERE id=?",
            (syntax, profile_id, label, body, _now(), qid),
        )
        self.conn.commit()

    def delete_query_template(self, qid):
        self.conn.execute("DELETE FROM query_templates WHERE id=?", (qid,))
        self.conn.commit()

    def export_query_templates(self, ids=None):
        """Return a list of plain dicts (syntax/profile_id/label/body) for
        the given query template ids, or every one if ids is None. Omits
        id/timestamps for the same reason export_templates does - so
        importing into another analyst's DB never collides on numbering;
        matched by (syntax, label) on import instead."""
        if ids:
            rows = [self.get_query_template(i) for i in ids]
            rows = [r for r in rows if r]
        else:
            rows = self.list_query_templates()
        return [
            {"syntax": r["syntax"], "profile_id": r["profile_id"], "label": r["label"], "body": r["body"]}
            for r in rows
        ]

    def import_query_templates(self, query_templates, overwrite=False):
        """Import a list of query template dicts (as produced by
        export_query_templates). Matched by (syntax, label) - the same
        label can validly exist once per syntax (e.g. a "Pivot by Host"
        query in both LEQL and KQL), so syntax is part of the match key.
        Returns (imported_count, skipped_labels)."""
        existing = {(t["syntax"], t["label"]): t["id"] for t in self.list_query_templates()}
        imported = 0
        skipped = []
        for t in query_templates:
            if not isinstance(t, dict):
                continue
            label = (t.get("label") or "").strip()
            if not label:
                continue
            syntax = t.get("syntax") or "kql"
            profile_id = t.get("profile_id") or ""
            body = t.get("body") or ""
            key = (syntax, label)
            if key in existing:
                if overwrite:
                    self.update_query_template(existing[key], syntax, profile_id, label, body)
                    imported += 1
                    continue
                skipped.append(label)
                continue
            new_id = self.add_query_template(syntax, profile_id, label, body)
            existing[key] = new_id
            imported += 1
        return imported, skipped

    # ---- incidents ----

    def list_incidents(self, search=None, status=None):
        """List incidents, optionally filtered by a search term (matched
        against title/raw_logs/analysis/output) and/or an exact status
        value (one of INCIDENT_STATUSES). status=None or "all" means no
        status filtering."""
        clauses = []
        params = []
        if search:
            like = f"%{search}%"
            clauses.append("(title LIKE ? OR raw_logs LIKE ? OR analysis LIKE ? OR output LIKE ?)")
            params.extend([like, like, like, like])
        if status and status != "all":
            clauses.append("status = ?")
            params.append(status)
        sql = "SELECT * FROM incidents"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC"
        cur = self.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def get_incident(self, iid):
        cur = self.conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def add_incident(self, title, raw_logs, analysis, output, extracted_json, status="Open"):
        now = _now()
        cur = self.conn.execute(
            "INSERT INTO incidents (title, raw_logs, analysis, output, "
            "extracted_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (title, raw_logs, analysis, output, extracted_json, status, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_incident(self, iid, title, raw_logs, analysis, output, extracted_json):
        self.conn.execute(
            "UPDATE incidents SET title=?, raw_logs=?, analysis=?, output=?, "
            "extracted_json=?, updated_at=? WHERE id=?",
            (title, raw_logs, analysis, output, extracted_json, _now(), iid),
        )
        self.conn.commit()

    def delete_incident(self, iid):
        self.conn.execute("DELETE FROM incidents WHERE id=?", (iid,))
        self.conn.commit()

    def rename_incident(self, iid, title):
        """Update just an incident's title (and updated_at), leaving its
        logs/analysis/output/extracted fields untouched. Used by the
        Incidents tab's Rename action so an analyst can give a saved
        incident a memorable name (ticket number, short description,
        etc.) without re-saving the whole workspace."""
        self.conn.execute(
            "UPDATE incidents SET title=?, updated_at=? WHERE id=?",
            (title, _now(), iid),
        )
        self.conn.commit()

    def update_incident_status(self, iid, status):
        """Update just an incident's status (and updated_at) for quick
        triage tracking (Open/Escalated/Closed/False Positive) without
        touching anything else about the saved incident."""
        self.conn.execute(
            "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
            (status, _now(), iid),
        )
        self.conn.commit()

    # ---- notes ----
    # Quick-reference notes (KB articles, saved queries, anything an
    # analyst wants handy) - deliberately separate from incidents, which
    # track actual case work (logs/analysis/output tied to one alert).

    def list_notes(self, search=None):
        if search:
            like = f"%{search}%"
            cur = self.conn.execute(
                "SELECT * FROM notes WHERE title LIKE ? OR body LIKE ? "
                "ORDER BY updated_at DESC",
                (like, like),
            )
        else:
            cur = self.conn.execute("SELECT * FROM notes ORDER BY updated_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_note(self, nid):
        cur = self.conn.execute("SELECT * FROM notes WHERE id = ?", (nid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def add_note(self, title, body):
        now = _now()
        cur = self.conn.execute(
            "INSERT INTO notes (title, body, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (title, body, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_note(self, nid, title, body):
        self.conn.execute(
            "UPDATE notes SET title=?, body=?, updated_at=? WHERE id=?",
            (title, body, _now(), nid),
        )
        self.conn.commit()

    def delete_note(self, nid):
        self.conn.execute("DELETE FROM notes WHERE id=?", (nid,))
        self.conn.commit()

    def export_notes(self, ids=None):
        """Return a list of plain dicts (title/body) for the given note
        ids, or every note if ids is None. Omits id/timestamps on purpose
        so importing into another analyst's DB never collides with their
        own numbering - notes are matched by title on import instead."""
        if ids:
            rows = [self.get_note(i) for i in ids]
            rows = [r for r in rows if r]
        else:
            rows = self.list_notes()
        return [{"title": r["title"], "body": r["body"]} for r in rows]

    def import_notes(self, notes, overwrite=False):
        """Import a list of note dicts (as produced by export_notes) from
        another analyst. Notes are matched by title: a title that already
        exists is left alone and reported as skipped unless
        overwrite=True, in which case the existing note's body is
        replaced in place. New titles are inserted as new notes. Returns
        (imported_count, skipped_titles)."""
        existing = {n["title"]: n["id"] for n in self.list_notes()}
        imported = 0
        skipped = []
        for n in notes:
            if not isinstance(n, dict):
                continue
            title = (n.get("title") or "").strip()
            if not title:
                continue
            body = n.get("body") or ""
            if title in existing:
                if overwrite:
                    self.update_note(existing[title], title, body)
                    imported += 1
                    continue
                skipped.append(title)
                continue
            new_id = self.add_note(title, body)
            existing[title] = new_id
            imported += 1
        return imported, skipped

    # ---- sanitize keywords (Sanitize Logs tab custom find/replace list) ----

    def list_sanitize_keywords(self):
        cur = self.conn.execute(
            "SELECT * FROM sanitize_keywords ORDER BY keyword COLLATE NOCASE"
        )
        return [dict(r) for r in cur.fetchall()]

    def get_sanitize_keyword(self, kid):
        cur = self.conn.execute("SELECT * FROM sanitize_keywords WHERE id = ?", (kid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def add_sanitize_keyword(self, keyword, replacement):
        now = _now()
        cur = self.conn.execute(
            "INSERT INTO sanitize_keywords (keyword, replacement, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (keyword, replacement, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_sanitize_keyword(self, kid, keyword, replacement):
        self.conn.execute(
            "UPDATE sanitize_keywords SET keyword=?, replacement=?, updated_at=? WHERE id=?",
            (keyword, replacement, _now(), kid),
        )
        self.conn.commit()

    def delete_sanitize_keyword(self, kid):
        self.conn.execute("DELETE FROM sanitize_keywords WHERE id=?", (kid,))
        self.conn.commit()

    # ---- custom dictionary (spell-check "Add to Dictionary") ----

    def list_custom_dictionary_words(self):
        cur = self.conn.execute(
            "SELECT * FROM custom_dictionary ORDER BY word COLLATE NOCASE"
        )
        return [dict(r) for r in cur.fetchall()]

    def add_custom_dictionary_word(self, word):
        """Adds `word` to the analyst's persistent spell-check dictionary
        (case-insensitive; adding a word that's already there, in any
        case, is a harmless no-op rather than an error)."""
        word = (word or "").strip()
        if not word:
            return
        self.conn.execute(
            "INSERT OR IGNORE INTO custom_dictionary (word, created_at) VALUES (?, ?)",
            (word, _now()),
        )
        self.conn.commit()

    def delete_custom_dictionary_word(self, wid):
        self.conn.execute("DELETE FROM custom_dictionary WHERE id=?", (wid,))
        self.conn.commit()

    # ---- lifecycle ----

    def close(self):
        """Close the underlying sqlite connection. Used before replacing
        the database file on disk (Restore Database) so the file isn't
        held open during the copy."""
        self.conn.close()
