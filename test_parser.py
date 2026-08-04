import base64
import json
import os
import re
import sqlite3
import tempfile

from parser_core import (
    DB, FieldMapper, fill_template, get_field_value, CANONICAL_FIELDS, INCIDENT_STATUSES, TRANSFORMS,
    find_unresolved_tag_spans, remove_unresolved_tags, sanitize_text, SANITIZE_CATEGORIES, SANITIZE_CATEGORY_LABELS,
    TEXT_TOOL_OPERATIONS, apply_text_tools,
    text_tool_base64_decode, text_tool_hex_decode, text_tool_url_decode,
    text_tool_extract_emails, text_tool_extract_ips, text_tool_extract_paths, text_tool_remove_whitespace,
    text_tool_sort_alphabetically, text_tool_remove_duplicates, text_tool_defang,
    parse_json_blobs_verbose, virustotal_url,
    find_misspelled_word_spans, spelling_suggestions,
    SEED_QUERY_TEMPLATES,
)

HERE = os.path.dirname(os.path.abspath(__file__))
mapper = FieldMapper(os.path.join(HERE, "field_mappings.json"))


def check(name, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}")
    if not cond:
        raise SystemExit(1)


# ---------------------------------------------------------------------
# Real Rapid7 InsightIDR sample logs (sanitized values as provided)
# ---------------------------------------------------------------------

O365_AUTH_LOG = {
    "timestamp": "2026-07-02T17:43:45.000Z",
    "user": "jdoe@contoso.com",
    "geoip_city": "San Diego",
    "geoip_country_code": "US",
    "geoip_country_name": "United States",
    "geoip_organization": "Cox Business",
    "geoip_region": "CA",
    "geoip_connection_type": "Corporate",
    "account": "jdoe@contoso.com",
    "result": "SUCCESS",
    "source_ip": "203.0.113.10",
    "service": "o365",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0 OS/10.0.22631",
    "source_json": {
        "CreationTime": "2026-07-02T17:43:45",
        "Id": "c3e812c5-9e00-4a9c-b7be-33c38e221200",
        "Operation": "UserLoggedIn",
        "OrganizationId": "667f07f9-f14f-49bf-aac8-fde5b741da25",
        "RecordType": 15,
        "ResultStatus": "Success",
        "UserKey": "f4a85e3a-9601-4f82-ad18-e8aaf53be0e3",
        "UserType": 0,
        "Version": 1,
        "Workload": "AzureActiveDirectory",
        "ClientIP": "203.0.113.10",
        "ObjectId": "00000003-0000-0ff1-ce00-000000000000",
        "UserId": "jdoe@contoso.com",
        "AzureActiveDirectoryEventType": 1,
        "ExtendedProperties": [
            {"Name": "ResultStatusDetail", "Value": "Success"},
            {"Name": "UserAgent", "Value": "Mozilla/5.0 ..."},
            {"Name": "RequestType", "Value": "Login:reprocess"}
        ],
        "ModifiedProperties": [],
        "Actor": [
            {"ID": "f4a85e3a-9601-4f82-ad18-e8aaf53be0e3", "Type": 0},
            {"ID": "jdoe@contoso.com", "Type": 5}
        ],
        "ActorContextId": "667f07f9-f14f-49bf-aac8-fde5b741da25",
        "ActorIpAddress": "203.0.113.10",
        "Target": [{"ID": "00000003-0000-0ff1-ce00-000000000000", "Type": 0}],
        "TargetContextId": "667f07f9-f14f-49bf-aac8-fde5b741da25",
        "ApplicationId": "00000003-0000-0ff1-ce00-000000000000",
        "DeviceProperties": [
            {"Name": "Id", "Value": "f0f9321a-b098-47a3-a13b-6e611948593a"},
            {"Name": "DisplayName", "Value": "JDOE-LAPTOP"},
            {"Name": "OS", "Value": "Windows10"},
            {"Name": "BrowserType", "Value": "Edge"},
            {"Name": "IsCompliant", "Value": "True"},
            {"Name": "IsCompliantAndManaged", "Value": "True"},
            {"Name": "TrustType", "Value": "1"},
            {"Name": "SessionId", "Value": "005ddf5a-77e4-dbcc-3997-6486c81a4b58"}
        ],
        "ErrorNumber": "0"
    },
    "entry_id": "2b398183-c055-44ce-bf05-2f6a28f9b7dd"
}

O365_INBOX_RULE_LOG = {
    "timestamp": "2026-06-26T20:43:43.000Z",
    "source_user": "jdoe@contoso.com",
    "service": "o365",
    "action": "New-InboxRule",
    "source_account": "",
    "source_json": {
        "CreationTime": "2026-06-26T20:43:43",
        "Id": "e0688ed9-724b-4b8e-dd36-08ded3c39d0f",
        "Operation": "New-InboxRule",
        "OrganizationId": "667f07f9-f14f-49bf-aac8-fde5b741da25",
        "RecordType": 1,
        "ResultStatus": "True",
        "UserKey": "jdoe@contoso.com",
        "UserType": 2,
        "Version": 1,
        "Workload": "Exchange",
        "ClientIP": "203.0.113.20",
        "ObjectId": "NAMPR01A011.PROD.OUTLOOK.COM/.../survey",
        "UserId": "jdoe@contoso.com",
        "Parameters": [
            {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
            {"Name": "Force", "Value": "False"},
            {"Name": "MoveToFolder", "Value": "survey"},
            {"Name": "Name", "Value": "survey"},
            {"Name": "SubjectContainsWords", "Value": "completed survey"},
            {"Name": "StopProcessingRules", "Value": "True"}
        ],
        "RequestId": "aea3a148-1503-2321-9023-4f8dd8769af8"
    },
    "entry_id": "176f3ebe-7b61-4444-b013-6da6901e8ac0"
}

PROCESS_LOG = {
    "hostname": "WORKSTATION-07",
    "dns_domain": "contoso.com",
    "os_type": "WINDOWS",
    "r7_hostid": "88e6ace6eda45ef9ea7407d08d0bb7a2",
    "process": {
        "start_time": "2026-07-02T17:53:16.233Z",
        "name": "svchost.exe",
        "pid": 18020,
        "exe_path": "C:\\Windows\\System32\\svchost.exe",
        "working_dir": "C:\\WINDOWS\\system32\\",
        "cmd_line": "C:\\WINDOWS\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts",
        "username": "NT AUTHORITY\\LOCAL SERVICE",
        "session": 0,
        "exe_file": {
            "owner": "NT SERVICE\\TrustedInstaller",
            "hashes": {
                "md5": "8ec922c7a58a8701ab481b7be9644536",
                "sha256": "949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b",
                "sha1": "3f64c98f22da277a07cab248c44c56eedb796a81"
            },
            "signing_status": "SIGNED_VALID",
            "signing_chain": [
                {"subject": "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Publisher"}
            ]
        },
        "hash_reputation": {"reputation": "Known", "threat_level": "None"}
    },
    "parent_process": {
        "start_time": "2026-04-06T08:25:13.666Z",
        "name": "services.exe",
        "pid": 1056,
        "exe_path": "C:\\Windows\\System32\\services.exe",
        "username": "NT AUTHORITY\\SYSTEM",
        "exe_file": {
            "hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        }
    },
    "endpoint_id": "88e6ace6eda45ef9ea7407d08d0bb7a2",
    "endpoint_vendor": "Rapid7",
    "entry_id": "7deeb088-ea70-40ca-884f-1f80bf658a6a"
}

# --- O365 authentication (Rapid7 InsightIDR) ---
r = mapper.parse(json.dumps(O365_AUTH_LOG))
check("rapid7 o365 signin detect", r["label"] == "Ingress Authentication")
check("rapid7 o365 signin user", r["canonical"]["user"] == "jdoe@contoso.com")
check("rapid7 o365 signin domain (via transform)", r["canonical"]["domain"] == "contoso.com")
check("rapid7 o365 signin host (Name=Value lookup)", r["canonical"]["host"] == "JDOE-LAPTOP")
check("rapid7 o365 signin src_ip", r["canonical"]["src_ip"] == "203.0.113.10")
check("rapid7 o365 signin geoip_city", r["canonical"]["geoip_city"] == "San Diego")
check("rapid7 o365 signin geoip_org", r["canonical"]["geoip_org"] == "Cox Business")
check("rapid7 o365 signin request_type (nested Name=Value)", r["canonical"]["request_type"] == "Login:reprocess")
check("rapid7 o365 signin device_compliant", r["canonical"]["device_compliant"] == "True")
check("rapid7 o365 signin device_trust_type", r["canonical"]["device_trust_type"] == "1")
check("rapid7 o365 signin event_id", r["canonical"]["event_id"] == "UserLoggedIn")
check("rapid7 o365 signin field_order includes geoip_city", "geoip_city" in r["field_order"])

# --- Azure AD / Entra ID sign-in log. This SIEM wraps Azure AD/Entra ID
# sign-in events in the same outer envelope as O365 auth logs (top-level
# geoip_*/user/result/etc., with the raw provider payload nested under
# source_json), just with a different internal source_json shape
# (source_json.properties.* instead of O365's DeviceProperties/Operation).
# From a SOC perspective these are processed identically, so this SIEM's
# Azure sign-ins are detected and parsed by the SAME rapid7_o365_signin
# profile rather than a separate one - real sanitized sample provided by
# the analyst. ---
AZURE_SIGNIN_LOG = {
    "timestamp": "2026-06-03T17:50:55.308Z",
    "user": "sanitized",
    "geoip_city": "Corona",
    "geoip_country_code": "US",
    "geoip_country_name": "United States",
    "geoip_organization": "Spectrum",
    "geoip_region": "CA",
    "geoip_connection_type": "Cable/DSL",
    "account": "sanitized",
    "result": "SUCCESS",
    "source_ip": "sanitized",
    "service": "AZURE_AD",
    # Real Rapid7-normalized Azure AD sign-in logs share the same outer
    # envelope as the O365 shape (see RAPID7_O365_LOG above), including
    # this top-level user_agent - without it here, this fixture doesn't
    # exact-match rapid7_o365_signin's detect_keys and instead collides
    # with sentinel_signin's (UserPrincipalName/AppDisplayName/IPAddress
    # all happen to appear, case-insensitively, nested under
    # source_json.properties below).
    "user_agent": "Windows-AzureAD-Authentication-Provider/1.0",
    "source_json": {
        "time": "2026-06-03T17:50:55.3087318Z",
        "resourceId": "sanitized",
        "operationName": "Sign-in activity",
        "operationVersion": "1.0",
        "category": "SignInLogs",
        "tenantId": "3d3386ec-2870-4a78-bf65-d559043687be",
        "resultType": "0",
        "resultSignature": "SUCCESS",
        "durationMs": 0,
        "callerIpAddress": "104.34.51.215",
        "correlationId": "5c72f175-3538-4c85-9246-e1867f8b4e9a",
        "identity": "sanitized",
        "level": "4",
        "location": "US",
        "properties": {
            "id": "e5ae3062-f883-485c-9372-f9e129b83900",
            "createdDateTime": "2026-06-03T16:11:03.3214919+00:00",
            "userDisplayName": "sanitized",
            "userPrincipalName": "sanitized",
            "userId": "f29291cf-a4d7-4288-a03b-71757a2387b1",
            "appId": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "appDisplayName": "Windows Sign In",
            "ipAddress": "sanitized",
            "status": {
                "errorCode": 0,
                "additionalDetails": "MFA requirement satisfied by claim in the token"
            },
            "clientAppUsed": "Mobile Apps and Desktop clients",
            "userAgent": "Windows-AzureAD-Authentication-Provider/1.0",
            "deviceDetail": {
                "deviceId": "5c3fd774-6591-4087-8850-77295f71c007",
                "displayName": "sanitized-device",
                "operatingSystem": "Windows",
                "browser": "",
                "isCompliant": True,
                "isManaged": True,
                "trustType": "Azure AD joined"
            },
            "location": {
                "city": "Corona",
                "state": "California",
                "countryOrRegion": "US"
            },
            "authenticationDetails": [
                {
                    "authenticationStepDateTime": "2026-06-03T16:11:03.3214919+00:00",
                    "authenticationMethod": "Password",
                    "authenticationMethodDetail": "Password Hash Sync",
                    "succeeded": True,
                    "authenticationStepResultDetail": "Correct password",
                    "authenticationStepRequirement": "",
                    "StatusSequence": 0,
                    "RequestSequence": 1
                }
            ],
            "authenticationRequirement": "singleFactorAuthentication",
            "isInteractive": True,
            "userType": "Member"
        }
    },
    "r7_context": {
        "user": {"type": "user", "rrn": "rrn:uba:us:64dc7573-cd75-4051-9989-b71346ca5500:user:3S0CS8370NY1", "name": "sanitized"},
        "account": {"type": "account", "rrn": "rrn:uba:us:64dc7573-cd75-4051-9989-b71346ca5500:account:ERVA2PJ2AWBJ", "name": "sanitized@example.com"}
    },
    "entry_id": "ca67b00b-66f3-450d-b45e-1a074c3b1f85"
}

ra = mapper.parse(json.dumps(AZURE_SIGNIN_LOG))
check("azure ad signin detected by merged o365 profile", ra["label"] == "Ingress Authentication")
check("azure ad signin matched exactly", ra["matched"] is True)
check("azure ad signin user", ra["canonical"]["user"] == "sanitized")
check("azure ad signin domain blank (no @ in sanitized user)", ra["canonical"]["domain"] == "")
check("azure ad signin src_ip", ra["canonical"]["src_ip"] == "sanitized")
check("azure ad signin result", ra["canonical"]["result"] == "SUCCESS")
check("azure ad signin geoip_city", ra["canonical"]["geoip_city"] == "Corona")
check("azure ad signin geoip_org", ra["canonical"]["geoip_org"] == "Spectrum")
check("azure ad signin service", ra["canonical"]["service"] == "AZURE_AD")
check("azure ad signin event_id falls back to operationName", ra["canonical"]["event_id"] == "Sign-in activity")
check("azure ad signin host falls back to deviceDetail.displayName", ra["canonical"]["host"] == "sanitized-device")
check("azure ad signin device_os falls back to deviceDetail.operatingSystem", ra["canonical"]["device_os"] == "Windows")
check("azure ad signin device_compliant falls back to deviceDetail.isCompliant", ra["canonical"]["device_compliant"] == "True")
check("azure ad signin device_managed falls back to deviceDetail.isManaged", ra["canonical"]["device_managed"] == "True")
check("azure ad signin device_trust_type falls back to deviceDetail.trustType", ra["canonical"]["device_trust_type"] == "Azure AD joined")
check("azure ad signin device_browser blank (empty string in source)", ra["canonical"]["device_browser"] == "")
check("azure ad signin azure_app_display_name", ra["canonical"]["azure_app_display_name"] == "Windows Sign In")
check("azure ad signin azure_user_agent", ra["canonical"]["azure_user_agent"] == "Windows-AzureAD-Authentication-Provider/1.0")
check("azure ad signin azure_device_id", ra["canonical"]["azure_device_id"] == "5c3fd774-6591-4087-8850-77295f71c007")
check("azure ad signin azure_auth_method", ra["canonical"]["azure_auth_method"] == "Password")
check("azure ad signin azure_auth_step_result_detail", ra["canonical"]["azure_auth_step_result_detail"] == "Correct password")
check("azure ad signin azure_auth_requirement", ra["canonical"]["azure_auth_requirement"] == "singleFactorAuthentication")

check("azure_ad_signin standalone profile has been removed", not any(p["id"] == "azure_ad_signin" for p in mapper.config["profiles"]))

# --- get_field_value: '||' fallback candidate support, in isolation from
# any profile (this is what lets one canonical field be shared correctly
# between the O365 and Azure AD shapes under the merged profile above) ---
check(
    "get_field_value fallback picks the first candidate that resolves",
    get_field_value({"a": {"b": "first"}, "c": {"d": "second"}}, "a.b||c.d") == "first",
)
check(
    "get_field_value fallback falls through to the second candidate when the first is missing",
    get_field_value({"c": {"d": "second"}}, "a.b||c.d") == "second",
)
check(
    "get_field_value fallback returns None when no candidate resolves",
    get_field_value({}, "a.b||c.d") is None,
)
check(
    "get_field_value fallback applies a transform on whichever candidate wins",
    get_field_value({"c": "second@example.com"}, "a.b::domain_from_email||c::domain_from_email") == "example.com",
)

# --- Partial paste: analyst pastes only the top fields of an O365 auth
# log, missing the outer { } braces AND missing one of rapid7_o365_signin's
# 3 current detect_keys (user_agent, geoip_connection_type, user) -
# geoip_connection_type isn't in this fragment, leaving 2 of 3 present,
# right at the majority/partial-match threshold. Should still repair +
# detect. ---
PARTIAL_O365_AUTH_PASTE = (
    '  "timestamp" : "2026-06-30T12:34:57.000Z",\n'
    '  "user" : "sanitized",\n'
    '  "geoip_country_code" : "US",\n'
    '  "geoip_country_name" : "United States",\n'
    '  "geoip_organization" : "HostPapa",\n'
    '  "account" : "sanitized",\n'
    '  "result" : "SUCCESS",\n'
    '  "source_ip" : "sanitized",\n'
    '  "service" : "o365",\n'
    '  "user_agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",\n'
)
rp = mapper.parse(PARTIAL_O365_AUTH_PASTE)
check("partial paste still detects the right profile", rp["label"] == "Ingress Authentication")
check("partial paste still matched", rp["matched"] is True)
check("partial paste extracts user", rp["canonical"]["user"] == "sanitized")
check("partial paste extracts result", rp["canonical"]["result"] == "SUCCESS")
check("partial paste extracts geoip_org", rp["canonical"]["geoip_org"] == "HostPapa")
check("partial paste leaves un-pasted field blank, not an error", rp["canonical"]["host"] == "")
check("partial paste warns about brace repair", any("braces" in w for w in rp["warnings"]))
check("partial paste warns about partial detection", any("partial paste of that log type" in w for w in rp["warnings"]))

# A single stray '#' or unrelated fragment shouldn't falsely match any
# real profile via the partial-match fallback.
junk = '"foo": "bar", "note": "not a real log"'
rj = mapper.parse(junk)
check("unrelated fragment does not falsely match a real profile", rj["matched"] is False)

# --- Unescaped-backslash repair: a raw Windows file path/command line
# (e.g. from a Windows Security event pulled into a SIEM export) pasted
# with its backslashes never escaped is invalid JSON on its own, even
# though it looks complete (matched braces). This is a very common,
# real-world paste an analyst hits - the fix should recover the FULL
# nested structure (not just a flat best-effort scrape). ---
WINDOWS_PATH_LOG_RAW = (
    '{\n'
    '  "timestamp": "2026-07-08T13:34:45.443Z",\n'
    '  "service_name": "BcastDVRUserService_1e3c14",\n'
    '  "service_cmdline": "C:\\WINDOWS\\system32\\svchost.exe -k BcastDVRUserService",\n'
    '  "r7_hostid": "51be7a40890bd518cb194b7bc4d181bc",\n'
    '  "source_json": {\n'
    '    "eventCode": 4697,\n'
    '    "isDomainController": false,\n'
    '    "eventData": {\n'
    '      "ServiceFileName": "C:\\WINDOWS\\system32\\svchost.exe -k BcastDVRUserService",\n'
    '      "ClientProcessId": "2676"\n'
    '    }\n'
    '  },\n'
    '  "entry_id": "10581e13-f5dc-4bd0-90e2-f263544b981b"\n'
    '}\n'
)
try:
    json.loads(WINDOWS_PATH_LOG_RAW)
    _windows_path_log_is_invalid_on_its_own = False
except json.JSONDecodeError:
    _windows_path_log_is_invalid_on_its_own = True
check(
    "sanity: unescaped Windows path really is invalid JSON on its own",
    _windows_path_log_is_invalid_on_its_own,
)
wp_objs, wp_method = parse_json_blobs_verbose(WINDOWS_PATH_LOG_RAW)
check("unescaped-backslash repair returns exactly one object", len(wp_objs) == 1)
check("unescaped-backslash repair reports the right repair_method", wp_method == "unescaped_backslashes")
check(
    "unescaped-backslash repair preserves the literal path text",
    wp_objs[0]["service_cmdline"] == r"C:\WINDOWS\system32\svchost.exe -k BcastDVRUserService",
)
check(
    "unescaped-backslash repair preserves NESTED structure (not a flat scrape)",
    wp_objs[0]["source_json"]["eventData"]["ServiceFileName"]
    == r"C:\WINDOWS\system32\svchost.exe -k BcastDVRUserService",
)
check("unescaped-backslash repair leaves a real int untouched", wp_objs[0]["source_json"]["eventCode"] == 4697)
check("unescaped-backslash repair leaves a real bool untouched", wp_objs[0]["source_json"]["isDomainController"] is False)

wp_result = mapper.parse(WINDOWS_PATH_LOG_RAW)
check(
    "unescaped-backslash repair warns the analyst to double check path fields",
    any("backslash" in w.lower() for w in wp_result["warnings"]),
)

# Text that's ALREADY valid JSON (including real escape sequences) must
# come back byte-for-byte identical from the repair function - it should
# only ever touch a backslash that isn't already a legal JSON escape.
ALREADY_VALID_WITH_ESCAPES = (
    '{"a": "line1\\nline2", "b": "tab\\there", "c": "quote\\"x\\"", "u": "caf\\u00e9"}'
)
av_objs, av_method = parse_json_blobs_verbose(ALREADY_VALID_WITH_ESCAPES)
check("valid JSON with real escapes is not touched by the repair path", av_method is None)
check("valid JSON with real escapes still parses its \\n correctly", av_objs[0]["a"] == "line1\nline2")
check("valid JSON with real escapes still parses its \\u unicode correctly", av_objs[0]["u"] == "café")

# --- O365 inbox rule (Rapid7 InsightIDR) - this used to be its own
# standalone profile but has since been merged into "Active Directory /
# Cloud Activity" (both log shapes share the same generic Rapid7-
# normalized field names and kept colliding as two separate profiles).
# O365_INBOX_RULE_LOG only has 3 of that merged profile's 6 detect_keys
# (action, source_user, source_account - it has no source_asset/
# destination_asset/destination_account, which are AD-only), so this is
# a partial/majority match rather than exact - still correctly wins over
# every other profile since nothing else scores higher on this log. ---
r2 = mapper.parse(json.dumps(O365_INBOX_RULE_LOG))
check("rapid7 inbox rule detect (now the merged Active Directory / Cloud Activity profile)", r2["label"] == "Entra")
check("rapid7 inbox rule user", r2["canonical"]["user"] == "jdoe@contoso.com")
check("rapid7 inbox rule client_ip", r2["canonical"]["client_ip"] == "203.0.113.20")
check("rapid7 inbox rule rule_name", r2["canonical"]["rule_name"] == "survey")
check("rapid7 inbox rule move_to_folder", r2["canonical"]["move_to_folder"] == "survey")
check("rapid7 inbox rule forward_to (absent -> blank)", r2["canonical"]["forward_to"] == "")
check("rapid7 inbox rule stop_processing_rules", r2["canonical"]["stop_processing_rules"] == "True")
check("rapid7 inbox rule all_parameters flattened", "MoveToFolder=survey" in r2["canonical"]["all_parameters"])
check("rapid7 inbox rule all_parameters has multiple entries", r2["canonical"]["all_parameters"].count("=") >= 5)

# --- Endpoint process (Rapid7 InsightIDR / Insight Agent) ---
r3 = mapper.parse(json.dumps(PROCESS_LOG))
check("rapid7 process detect", r3["label"] == "Endpoint Activity")
check("rapid7 process host", r3["canonical"]["host"] == "WORKSTATION-07")
check("rapid7 process name", r3["canonical"]["process"] == "svchost.exe")
check("rapid7 process cmdline", "LocalServiceNetworkRestricted" in r3["canonical"]["cmdline"])
check("rapid7 process parent", r3["canonical"]["parent_process"] == "services.exe")
check("rapid7 process sha256", r3["canonical"]["process_sha256"].startswith("949bfb5b"))
check("rapid7 process signing status", r3["canonical"]["process_signing_status"] == "SIGNED_VALID")
check("rapid7 process signer (list index lookup)", "Microsoft Windows Publisher" in r3["canonical"]["process_signer"])
check("rapid7 process parent sha256", r3["canonical"]["parent_sha256"].startswith("e3b0c442"))
check("rapid7 process working_dir", "system32" in r3["canonical"]["working_dir"])

# --- Unknown / generic format still falls back cleanly ---
unknown = {"hostname": "srv-99", "username": "bsmith", "srcip": "8.8.8.8", "note": "custom siem export"}
r4 = mapper.parse(json.dumps(unknown))
check("generic fallback used", r4["matched"] is False)
check("generic host", r4["canonical"]["host"] == "srv-99")
check("generic user", r4["canonical"]["user"] == "bsmith")

# --- Bad input ---
r5 = mapper.parse("not json at all {{{")
check("bad input handled", r5["label"] is None and r5["record_count"] == 0)

# ---------------------------------------------------------------------
# Microsoft Sentinel / Defender for Endpoint log samples (real sanitized
# values as provided by the analyst, pulled from Sentinel KQL queries /
# Sentinel alerts)
# ---------------------------------------------------------------------

# --- transform unit tests, in isolation from any profile ---
check("join_list joins a list into a '; '-separated string", TRANSFORMS["join_list"](["a", "b", "c"]) == "a; b; c")
check("join_list drops None/empty entries", TRANSFORMS["join_list"](["a", "", None, "b"]) == "a; b")
check("join_list passes a scalar value through unchanged", TRANSFORMS["join_list"]("just-one-host") == "just-one-host")
check("join_list returns '' for None", TRANSFORMS["join_list"](None) == "")

PARAMS_JSON_STRING = (
    '[{"Name":"MoveToFolder","Value":"Operations"},{"Name":"StopProcessingRules","Value":"True"}]'
)
check(
    "flatten_name_value_json_string parses a JSON-encoded string then flattens it",
    TRANSFORMS["flatten_name_value_json_string"](PARAMS_JSON_STRING) == "MoveToFolder=Operations; StopProcessingRules=True",
)
check("flatten_name_value_json_string returns '' for invalid JSON text", TRANSFORMS["flatten_name_value_json_string"]("not json") == "")
check("flatten_name_value_json_string returns '' for a non-string value", TRANSFORMS["flatten_name_value_json_string"](None) == "")

# --- Sentinel excessive failed logins (Asset Authentication alert) ---
SENTINEL_FAILED_LOGINS_LOG = {
    "EventID": 4625,
    "Account": "CONTOSO\\jdoe",
    "LogonTypeName": "3 - Network",
    "SubStatus": "0xc000006a",
    "Reason": "User logon with misspelled or bad password",
    "AccountType": "User",
    "WorkstationName": "WORKSTATION-07",
    "Process": "-",
    "StartTime": "2026-07-02T19:46:04.5496648Z",
    "EndTime": "2026-07-03T00:33:00.8958800Z",
    "Computer": ["srv-dc01.contoso.com", "srv-dc02.contoso.com"],
    "IpAddressList": ["203.0.113.10", "203.0.113.11"],
    "sum_CountToday": 51,
    "sum_CountPrev7day": 0,
    "avg_Avg7Day": "NaN",
    "timestamp": "2026-07-02T19:46:04.5496648Z",
    "NTDomain": "CONTOSO",
    "Name": "jdoe",
    "HostName": "srv-dc01",
    "DnsDomain": "contoso.com",
}
rfl = mapper.parse(json.dumps(SENTINEL_FAILED_LOGINS_LOG))
check("sentinel failed logins detect", rfl["label"] == "Asset Authentications")
check("sentinel failed logins matched exactly", rfl["matched"] is True)
check("sentinel failed logins user", rfl["canonical"]["user"] == "CONTOSO\\jdoe")
check("sentinel failed logins host aggregates Computer list via join_list", rfl["canonical"]["host"] == "srv-dc01.contoso.com; srv-dc02.contoso.com")
check("sentinel failed logins src_ip aggregates IpAddressList via join_list", rfl["canonical"]["src_ip"] == "203.0.113.10; 203.0.113.11")
check("sentinel failed logins sub_status", rfl["canonical"]["sub_status"] == "0xc000006a")
check("sentinel failed logins logon_type", rfl["canonical"]["logon_type"] == "3 - Network")
check("sentinel failed logins count_today", rfl["canonical"]["count_today"] == "51")
check("sentinel failed logins result", rfl["canonical"]["result"] == "Failure")
check("sentinel failed logins event_id", rfl["canonical"]["event_id"] == "4625")

# --- Sentinel SigninLogs (now verified against a real sample; detect_keys
# changed to UserPrincipalName/AppDisplayName/IPAddress since the real
# sample doesn't carry ResultType) ---
SENTINEL_SIGNIN_LOG = {
    "UserPrincipalName": "jdoe@contoso.com",
    "Location": "PH",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "IPAddress": "198.51.100.20",
    "AppDisplayName": "Office Online Core SSO",
    "MfaDetail": None,
    "DeviceDetail": {
        "deviceId": "",
        "operatingSystem": "Windows10",
        "browser": "Chrome 149.0.0",
        "isCompliant": False,
        "isManaged": False,
    },
    "LocationDetails": {
        "city": "Santa Teresita",
        "state": "Batangas",
        "countryOrRegion": "PH",
        "geoCoordinates": {"latitude": 13.866669654846191, "longitude": 120.96666717529295},
    },
}
rsi = mapper.parse(json.dumps(SENTINEL_SIGNIN_LOG))
check("sentinel signin detect", rsi["label"] == "SigninLogs")
check("sentinel signin matched exactly", rsi["matched"] is True)
check("sentinel signin user", rsi["canonical"]["user"] == "jdoe@contoso.com")
check("sentinel signin domain (via transform)", rsi["canonical"]["domain"] == "contoso.com")
check("sentinel signin src_ip", rsi["canonical"]["src_ip"] == "198.51.100.20")
check("sentinel signin event_id", rsi["canonical"]["event_id"] == "Office Online Core SSO")
check("sentinel signin location", rsi["canonical"]["location"] == "Santa Teresita")
check("sentinel signin device_os", rsi["canonical"]["device_os"] == "Windows10")
check("sentinel signin device_browser", rsi["canonical"]["device_browser"] == "Chrome 149.0.0")
check("sentinel signin device_compliant", rsi["canonical"]["device_compliant"] == "False")
check("sentinel signin location_state", rsi["canonical"]["location_state"] == "Batangas")
check("sentinel signin geo_latitude", rsi["canonical"]["geo_latitude"] == "13.866669654846191")
check("sentinel signin result blank when ResultType absent from real sample", rsi["canonical"]["result"] == "")

# --- Sentinel USB file copy (DeviceEvents), including the 'all:' prefix
# cross-record aggregation - an analyst commonly pastes one JSON object
# per file copied rather than a single record ---
SENTINEL_USB_COPY_LOG = {
    "ReportId": 118034,
    "DeviceId": "df918b3c-1234-4a5b-9c6d-abcdef123456",
    "InitiatingProcessAccountDomain": "CONTOSO",
    "InitiatingProcessAccountName": "jdoe",
    "InitiatingProcessAccountUpn": "jdoe@contoso.com",
    "FileName": "budget_2026.xlsx",
    "FolderPath": "C:\\Users\\jdoe\\Documents",
    "SHA256": "",
    "TimeGenerated": "2026-06-30T21:23:04.1627322Z",
    "SensitivityLabel": "",
    "IsAzureInfoProtectionApplied": None,
    "DeviceName": "WORKSTATION-07",
    "DriveLetter": "D:",
    "MountTime": "2026-06-30T21:20:05.9286593Z",
    "ProductName": "UDisk",
    "SerialNumber": "AA00112233",
    "Manufacturer": "General",
    "HostName": "WORKSTATION-07",
    "DnsDomain": "contoso.com",
    "FileHashAlgorithm": "SHA256",
}
rusb = mapper.parse(json.dumps(SENTINEL_USB_COPY_LOG))
check("sentinel usb copy detect", rusb["label"] == "Files Copied to USB")
check("sentinel usb copy matched exactly", rusb["matched"] is True)
check("sentinel usb copy user (upn preferred)", rusb["canonical"]["user"] == "jdoe@contoso.com")
check("sentinel usb copy domain (via transform)", rusb["canonical"]["domain"] == "contoso.com")
check("sentinel usb copy host", rusb["canonical"]["host"] == "WORKSTATION-07")
check("sentinel usb copy drive_letter", rusb["canonical"]["drive_letter"] == "D:")
check("sentinel usb copy serial_number", rusb["canonical"]["serial_number"] == "AA00112233")
check("sentinel usb copy single-record file_names (all: on one record)", rusb["canonical"]["file_names"] == "budget_2026.xlsx")
check("sentinel usb copy single-record folder_paths (all: on one record)", rusb["canonical"]["folder_paths"] == "C:\\Users\\jdoe\\Documents")

USB_COPY_MULTI_RECORD = json.dumps([
    {
        "DeviceName": "WORKSTATION-07", "DriveLetter": "D:", "MountTime": "2026-06-30T21:20:05Z",
        "SerialNumber": "AA00112233", "FileName": "budget_2026.xlsx", "FolderPath": "C:\\Users\\jdoe\\Documents",
    },
    {
        "DeviceName": "WORKSTATION-07", "DriveLetter": "D:", "MountTime": "2026-06-30T21:20:05Z",
        "SerialNumber": "AA00112233", "FileName": "employee_roster.csv", "FolderPath": "C:\\Users\\jdoe\\Desktop",
    },
])
rusbm = mapper.parse(USB_COPY_MULTI_RECORD)
check("usb copy multi-record still detects the profile", rusbm["label"] == "Files Copied to USB")
check(
    "usb copy multi-record 'all:FileName' aggregates every pasted record",
    rusbm["canonical"]["file_names"] == "budget_2026.xlsx; employee_roster.csv",
)
check(
    "usb copy multi-record 'all:FolderPath' aggregates every pasted record",
    rusbm["canonical"]["folder_paths"] == "C:\\Users\\jdoe\\Documents; C:\\Users\\jdoe\\Desktop",
)
check(
    "usb copy multi-record warning names the aggregated fields",
    any("file_names, folder_paths were aggregated across all 2 records" in w for w in rusbm["warnings"]),
)

# --- Sentinel OfficeActivity (Exchange Admin / Inbox Rule operation) -
# Parameters arrives as a JSON-encoded STRING (double-serialized by the
# O365 Management Activity API), not a real nested array ---
SENTINEL_OFFICE_ACTIVITY_LOG = {
    "RecordType": "ExchangeAdmin",
    "TimeGenerated": "2026-06-26T19:43:53.0000000Z",
    "Operation": "New-InboxRule",
    "OrganizationId": "667f07f9-f14f-49bf-aac8-fde5b741da25",
    "UserType": "Admin",
    "UserKey": "jdoe@contoso.com",
    "OfficeWorkload": "Exchange",
    "ResultStatus": "True",
    "OfficeObjectId": "NAMPR01A011.PROD.OUTLOOK.COM/.../survey",
    "ClientIP": "203.0.113.20",
    "AccountName": "jdoe",
    "AccountUPNSuffix": "contoso.com",
    "Parameters": (
        '[{"Name":"AlwaysDeleteOutlookRulesBlob","Value":"False"},'
        '{"Name":"Force","Value":"False"},'
        '{"Name":"MoveToFolder","Value":"Operations"},'
        '{"Name":"Name","Value":"Auto-archive"},'
        '{"Name":"StopProcessingRules","Value":"True"}]'
    ),
}
roa = mapper.parse(json.dumps(SENTINEL_OFFICE_ACTIVITY_LOG))
check("sentinel office activity detect", roa["label"] == "OfficeActivity")
check("sentinel office activity matched exactly", roa["matched"] is True)
check("sentinel office activity user (UserKey preferred)", roa["canonical"]["user"] == "jdoe@contoso.com")
check("sentinel office activity src_ip", roa["canonical"]["src_ip"] == "203.0.113.20")
check("sentinel office activity event_id", roa["canonical"]["event_id"] == "New-InboxRule")
check("sentinel office activity result", roa["canonical"]["result"] == "True")
check(
    "sentinel office activity all_parameters flattens the JSON-string Parameters field",
    roa["canonical"]["all_parameters"]
    == "AlwaysDeleteOutlookRulesBlob=False; Force=False; MoveToFolder=Operations; Name=Auto-archive; StopProcessingRules=True",
)

# --- Sentinel Device Network Events (DeviceNetworkEvents) ---
SENTINEL_DEVICE_NETWORK_LOG = {
    "ActionType": "SslConnectionInspected",
    "AdditionalFields": {
        "server_name": "outlook.office365.com",
        "version": "TLSv12",
        "subject": "CN=outlook.office365.com,O=Microsoft Corporation",
        "issuer": "CN=Microsoft TLS G2 ECC CA OCSP 06,O=Microsoft Corporation,C=US",
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "ja3": "091f51a7a1c3a4504a224cc081ce9cee",
        "ja3s": "42ec7b1db61428bf1cc6e01b9ef02b04",
        "ja4": "t12d1809h2_4b22cbed5bed_7af1ed941c26",
        "ja4s": "t1206h2_c02c_9bd66850b8f2",
    },
    "DeviceName": "WORKSTATION-07",
    "InitiatingProcessAccountDomain": "CONTOSO",
    "InitiatingProcessAccountName": "jdoe",
    "InitiatingProcessAccountUpn": "jdoe@contoso.com",
    "InitiatingProcessCommandLine": "C:\\Program Files\\Outlook\\outlook.exe",
    "InitiatingProcessFileName": "outlook.exe",
    "InitiatingProcessParentFileName": "explorer.exe",
    "InitiatingProcessSHA256": "f58b4b4f816d81eb1d1f6b4931e7620f24bb0ad96d576535769fdb56ede8aec2",
    "LocalIP": "10.0.0.15",
    "LocalPort": 51234,
    "Protocol": "Tcp",
    "RemoteIP": "40.97.0.10",
    "RemotePort": 443,
    "TimeGenerated": "2026-07-03T16:39:40.2234363Z",
}
rdn = mapper.parse(json.dumps(SENTINEL_DEVICE_NETWORK_LOG))
check("sentinel device network detect", rdn["label"] == "Device Network Events")
check("sentinel device network matched exactly", rdn["matched"] is True)
check("sentinel device network host", rdn["canonical"]["host"] == "WORKSTATION-07")
check("sentinel device network src_ip", rdn["canonical"]["src_ip"] == "10.0.0.15")
check("sentinel device network dst_ip", rdn["canonical"]["dst_ip"] == "40.97.0.10")
check("sentinel device network process", rdn["canonical"]["process"] == "outlook.exe")
check("sentinel device network remote_port", rdn["canonical"]["remote_port"] == "443")
check("sentinel device network server_name (nested AdditionalFields)", rdn["canonical"]["server_name"] == "outlook.office365.com")
check("sentinel device network ja4", rdn["canonical"]["ja4"] == "t12d1809h2_4b22cbed5bed_7af1ed941c26")

# --- Sentinel Device Process Events (DeviceProcessEvents) ---
SENTINEL_DEVICE_PROCESS_LOG = {
    "AccountDomain": "nt authority",
    "AccountName": "system",
    "AccountSid": "S-1-5-18",
    "ActionType": "ProcessCreated",
    "DeviceName": "WORKSTATION-07",
    "FileName": "svchost.exe",
    "FolderPath": "C:\\Windows\\System32\\svchost.exe",
    "InitiatingProcessAccountDomain": "nt authority",
    "InitiatingProcessAccountName": "system",
    "InitiatingProcessCommandLine": "services.exe",
    "InitiatingProcessFileName": "services.exe",
    "InitiatingProcessId": 1168,
    "InitiatingProcessSHA256": "f58b4b4f816d81eb1d1f6b4931e7620f24bb0ad96d576535769fdb56ede8aec2",
    "InitiatingProcessSignatureStatus": "Valid",
    "InitiatingProcessSignerType": "OsVendor",
    "LogonId": 999,
    "MD5": "8ec922c7a58a8701ab481b7be9644536",
    "ProcessCommandLine": "svchost.exe -k wusvcs -p -s WaaSMedicSvc",
    "ProcessCreationTime": "2026-07-03T16:42:22.7967544Z",
    "ProcessId": 5664,
    "ProcessIntegrityLevel": "System",
    "SHA1": "3f64c98f22da277a07cab248c44c56eedb796a81",
    "SHA256": "949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b",
}
rdp = mapper.parse(json.dumps(SENTINEL_DEVICE_PROCESS_LOG))
check("sentinel device process detect", rdp["label"] == "Device Process Events")
check("sentinel device process matched exactly", rdp["matched"] is True)
check("sentinel device process user", rdp["canonical"]["user"] == "system")
check("sentinel device process host", rdp["canonical"]["host"] == "WORKSTATION-07")
check("sentinel device process cmdline", rdp["canonical"]["cmdline"] == "svchost.exe -k wusvcs -p -s WaaSMedicSvc")
check("sentinel device process parent_process", rdp["canonical"]["parent_process"] == "services.exe")
check("sentinel device process account_sid", rdp["canonical"]["account_sid"] == "S-1-5-18")
check("sentinel device process logon_id", rdp["canonical"]["logon_id"] == "999")
check("sentinel device process process_sha256", rdp["canonical"]["process_sha256"].startswith("949bfb5b"))
check("sentinel device process parent_signature_status", rdp["canonical"]["parent_signature_status"] == "Valid")

# --- fill_template: {field} and #tag syntax ---
data = {"user": "jdoe", "host": "srv1", "src_ip": "1.2.3.4"}
check(
    "fill_template {field} substitutes, missing shows marker",
    fill_template("User {user} on {host}. Missing: {process}", data)
    == "User jdoe on srv1. Missing: [process]",
)
check(
    "fill_template #tag substitutes known field",
    fill_template("seen from #src_ip on #host", data) == "seen from 1.2.3.4 on srv1",
)
check(
    "fill_template #tag leaves unknown tag untouched (no corruption)",
    fill_template("see ticket #1234 for #unknown_field details", data)
    == "see ticket #1234 for #unknown_field details",
)
check(
    "fill_template mixes {field} and #tag in one string",
    fill_template("{user} logged in from #src_ip", data) == "jdoe logged in from 1.2.3.4",
)

# --- find_unresolved_tag_spans: powers the "highlight unresolved tags"
# feature in the ticket output box (bold+yellow) - in isolation from any
# Tkinter widget, since the span-finding logic itself is pure ---
KNOWN_TAG_FIELDS = {"user", "host", "src_ip", "analysis"}
UNRESOLVED_SAMPLE_TEXT = (
    "User {user} from #src_ip, ticket #1234, host [host], "
    "note [redacted], missing {process}"
)
unresolved_spans = find_unresolved_tag_spans(UNRESOLVED_SAMPLE_TEXT, KNOWN_TAG_FIELDS)
unresolved_matches = [UNRESOLVED_SAMPLE_TEXT[s:e] for s, e in unresolved_spans]
check("find_unresolved_tag_spans flags a {field} placeholder", "{user}" in unresolved_matches)
check(
    "find_unresolved_tag_spans flags {field} even when the field name isn't in known_fields",
    "{process}" in unresolved_matches,
)
check("find_unresolved_tag_spans flags a recognized #tag", "#src_ip" in unresolved_matches)
check("find_unresolved_tag_spans flags a recognized [field] marker", "[host]" in unresolved_matches)
check("find_unresolved_tag_spans leaves an unrelated #ticket-number hashtag alone", "#1234" not in unresolved_matches)
check("find_unresolved_tag_spans leaves unrelated bracketed text alone", "[redacted]" not in unresolved_matches)
check("find_unresolved_tag_spans returns exactly the 4 expected hits", len(unresolved_matches) == 4)
check(
    "find_unresolved_tag_spans span offsets round-trip back to the exact substring",
    all(UNRESOLVED_SAMPLE_TEXT[s:e] == m for (s, e), m in zip(unresolved_spans, unresolved_matches)),
)
check("find_unresolved_tag_spans on fully-resolved text returns nothing", find_unresolved_tag_spans("User jdoe from 1.2.3.4, ticket #1234", KNOWN_TAG_FIELDS) == [])
check("find_unresolved_tag_spans on empty text returns nothing", find_unresolved_tag_spans("", KNOWN_TAG_FIELDS) == [])
check("find_unresolved_tag_spans field-name matching is case-insensitive", find_unresolved_tag_spans("seen on #HOST", {"host"}) == [(8, 13)])

# --- remove_unresolved_tags: powers the "Remove Unresolved Tags" button in
# the Incident Workspace, built directly on find_unresolved_tag_spans ---
removed_sample = remove_unresolved_tags(UNRESOLVED_SAMPLE_TEXT, KNOWN_TAG_FIELDS)
check("remove_unresolved_tags strips a {field} placeholder", "{user}" not in removed_sample)
check("remove_unresolved_tags strips a {field} placeholder not in known_fields", "{process}" not in removed_sample)
check("remove_unresolved_tags strips a recognized #tag", "#src_ip" not in removed_sample)
check("remove_unresolved_tags strips a recognized [field] marker", "[host]" not in removed_sample)
check("remove_unresolved_tags leaves an unrelated #ticket-number hashtag alone", "#1234" in removed_sample)
check("remove_unresolved_tags leaves unrelated bracketed text alone", "[redacted]" in removed_sample)
check("remove_unresolved_tags on fully-resolved text returns it unchanged", remove_unresolved_tags("User jdoe from 1.2.3.4, ticket #1234", KNOWN_TAG_FIELDS) == "User jdoe from 1.2.3.4, ticket #1234")
check("remove_unresolved_tags on empty text returns empty text", remove_unresolved_tags("", KNOWN_TAG_FIELDS) == "")
check("remove_unresolved_tags collapses the space left behind mid-sentence", remove_unresolved_tags("login from #host now", {"host"}) == "login from now")
check("remove_unresolved_tags on a lone tag leaves no stray spaces", remove_unresolved_tags("#analysis", {"analysis"}) == "")
check(
    "remove_unresolved_tags removes a tag alone on its own line but keeps the blank line, not collapsing paragraph structure",
    remove_unresolved_tags("Line one\n#analysis\nLine two", {"analysis"}) == "Line one\n\nLine two",
)
check(
    "remove_unresolved_tags removes multiple tags in one pass without corrupting offsets",
    remove_unresolved_tags("{user} logged into {host} via #src_ip", {"user", "host", "src_ip"}) == "logged into via",
)

# --- sanitize_text: powers the Sanitize Logs tab. Every category redacts
# to the exact same plain "REDACTED" literal (not a numbered placeholder
# like EMAIL_1/IP_2/HOST_1) - the analyst asked for this explicitly so
# nothing about a real value (or even which category caught it) survives
# into the output text. `counts` still separately tracks how many
# DISTINCT values each category caught, purely for the on-screen summary;
# that bookkeeping is internal and never shows up in the sanitized text
# itself. ---
SANITIZE_SAMPLE = (
    '{"HostName": "WORKSTATION-07", "ClientIP": "10.1.2.3"}\n'
    "User john.doe@contoso.com logged in from 10.1.2.3 to srv-dc01.contoso.com\n"
    "Second event from john.doe@contoso.com and 10.1.2.3, also 10.1.2.4\n"
    "Ticket INC-1234 opened. MAC 00:1A:2B:3C:4D:5E. "
    "SID S-1-5-21-1111111111-2222222222-3333333333-1001\n"
    "Timestamp 12:30:45 should not become an IPv6 address.\n"
    "IPv6 seen: fe80::1a2b:3c4d:5e6f:7a8b\n"
)
san_out, san_counts, san_spans = sanitize_text(SANITIZE_SAMPLE)
check("sanitize_text redacts email addresses to the literal REDACTED (not EMAIL_1)", "john.doe@contoso.com" not in san_out)
check("sanitize_text counts a repeated email as one distinct value even though both mentions render identically", san_counts["email"] == 1)
check("sanitize_text redacts IPv4 addresses to the literal REDACTED (not IP_1)", "10.1.2.3" not in san_out and "10.1.2.4" not in san_out)
check("sanitize_text counts two distinct IPv4 values even though both render identically", san_counts["ipv4"] == 2)
check("sanitize_text redacts MAC addresses to the literal REDACTED (not MAC_1)", "00:1A:2B:3C:4D:5E" not in san_out)
check("sanitize_text redacts Windows SIDs to the literal REDACTED (not SID_1)", "S-1-5-21" not in san_out)
check("sanitize_text redacts IPv6 addresses to the literal REDACTED (not IPV6_1)", "fe80::" not in san_out)
check("sanitize_text leaves an HH:MM:SS timestamp alone (not mistaken for IPv6)", "12:30:45" in san_out)
check("sanitize_text leaves a ticket/incident number alone", "INC-1234" in san_out)
check(
    "sanitize_text preserves a JSON key name even when it collides with a hostname prefix",
    '"HostName"' in san_out and '"ClientIP"' in san_out,
)
check("sanitize_text redacts the JSON value next to a protected key", "WORKSTATION-07" not in san_out)
check(
    "sanitize_text counts reflect distinct values per category, not total occurrences, even though every category renders as REDACTED",
    # "HostName" (the JSON key) case-insensitively matches the "hostname"
    # entry in the JSON-key-based detection list, so "WORKSTATION-07" is
    # caught by json_fields BEFORE the regex-based hostname stage runs -
    # leaving only "srv-dc01" for that regex stage to catch on its own,
    # hence hostname: 1 here, not 2. hostname/domain each independently
    # count "srv-dc01" and "contoso.com" even though the domain stage's
    # own pattern ends up sweeping the already-redacted "REDACTED" text
    # together with ".contoso.com" into one merged replacement (see
    # sanitize_text's docstring) - the per-category counts recorded
    # BEFORE that merge happens are unaffected.
    san_counts == {"json_fields": 1, "email": 1, "mac": 1, "sid": 1, "ipv6": 1, "ipv4": 2, "hostname": 1, "domain": 1},
)
check(
    "sanitize_text spans exactly cover every REDACTED literal actually inserted",
    [san_out[s:e] for s, e in san_spans] == ["REDACTED"] * san_out.count("REDACTED"),
)
check(
    "sanitize_text spans don't overlap and are sorted",
    all(san_spans[i][1] <= san_spans[i + 1][0] for i in range(len(san_spans) - 1)),
)
check(
    "sanitize_text leaves untouched text (like the ticket number) outside any span",
    not any(s <= san_out.index("INC-1234") < e for s, e in san_spans),
)

# --- sanitize_text false-positive regressions: hostname/domain detection
# must not sweep up ordinary Windows/code terminology that merely LOOKS
# like a hostname prefix or a dotted domain name ---
san_ps_out, san_ps_counts, _ = sanitize_text(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
check(
    "sanitize_text does not mistake 'Windows'/'WindowsPowerShell' for a WIN-prefixed hostname",
    "REDACTED" not in san_ps_out and san_ps_out == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
)
check(
    "sanitize_text does not mistake 'powershell.exe' for a domain name (.exe isn't a TLD)",
    san_ps_counts["domain"] == 0,
)

san_wh_out, san_wh_counts, _ = sanitize_text(
    'Write-Host ("RankCalc A1 (unchanged?): {0}" -f $rc.Cells.Item(1,1).Value2)'
)
check(
    "sanitize_text does not mistake the Write-Host cmdlet for a bare 'Host' hostname",
    "REDACTED" not in san_wh_out and san_wh_counts["hostname"] == 0,
)
check(
    "sanitize_text does not mistake a dotted property chain ($rc.Cells.Item) for a domain",
    san_wh_counts["domain"] == 0 and "$rc.Cells.Item" in san_wh_out,
)

san_real_out, san_real_counts, _ = sanitize_text(
    "host WORKSTATION-07 talked to contoso.com from srv-dc01.fabrikam.net"
)
check(
    "sanitize_text still counts 2 distinct real hyphen/digit-suffixed hostnames after the false-positive fix",
    san_real_counts["hostname"] == 2 and "WORKSTATION-07" not in san_real_out and "srv-dc01" not in san_real_out,
)
check(
    "sanitize_text still counts 2 distinct real domains with recognized TLDs after the false-positive fix",
    san_real_counts["domain"] == 2 and "contoso.com" not in san_real_out and "fabrikam.net" not in san_real_out,
)
check(
    "sanitize_text output for the real hostname+domain sample contains only REDACTED where values were",
    san_real_out == "host REDACTED talked to REDACTED from REDACTED",
)

san_disabled, san_disabled_counts, _ = sanitize_text("Contact bob@example.com", categories={"email": False, "domain": False})
check("sanitize_text leaves a category alone when disabled", "bob@example.com" in san_disabled)
check("sanitize_text reports 0 for a disabled category", san_disabled_counts["email"] == 0)

san_kw, _, san_kw_spans = sanitize_text("Project CODENAME-FALCON is affected", keyword_pairs=[("CODENAME-FALCON", "PROJECT_X")])
check("sanitize_text applies custom keyword replacements (an analyst-chosen string, not REDACTED)", san_kw == "Project PROJECT_X is affected")
check(
    "sanitize_text keyword-replacement span lands at the exact replaced offset",
    san_kw_spans == [(8, 17)] and san_kw[8:17] == "PROJECT_X",
)

san_kw_ci, _, _ = sanitize_text("codename-falcon and CODENAME-FALCON", keyword_pairs=[("CODENAME-FALCON", "PROJECT_X")])
check("sanitize_text custom keyword replacement is case-insensitive", san_kw_ci == "PROJECT_X and PROJECT_X")

check(
    "sanitize_text on empty text returns empty with zero counts and no spans",
    sanitize_text("") == ("", {c: 0 for c in SANITIZE_CATEGORIES}, []),
)
check("SANITIZE_CATEGORIES and SANITIZE_CATEGORY_LABELS cover the same set", set(SANITIZE_CATEGORIES) == set(SANITIZE_CATEGORY_LABELS.keys()))

# --- sanitize_text: JSON-key-based detection. Regex alone can't
# recognize a bare username ("jdoe") or an unconventionally-named host
# ("SFO-FIN-01"), so sanitize_text also parses the pasted text as JSON
# and pulls values out of a fixed list of known dotted field paths. These
# fields mix usernames, device/asset names, and Windows domain names, so
# rather than mischaracterize them under separate "account"/"hostname"
# categories, every one of them is redacted with a plain "REDACTED"
# literal (no numbering) under one "json_fields" category. Same value
# seen via different keys (or in free text elsewhere in the log) must
# still be swept and redacted too. ---
JSON_KEY_SAMPLE_LOG = {
    "hostname": "SFO-FIN-01",
    "destination_asset": "SFO-FIN-01",
    "source_asset": "jdoe-laptop",
    "account": "jdoe",
    "process": {
        "username": "jdoe",
        "account_domain": "CONTOSO",
        "exe_file": {"owner": "CONTOSO\\jdoe"},
    },
    "parent_process": {
        "username": "SYSTEM",
        "account_domain": "NT AUTHORITY",
        "exe_file": {"owner": "NT AUTHORITY\\SYSTEM"},
    },
}
JSON_KEY_SAMPLE_TEXT = (
    json.dumps(JSON_KEY_SAMPLE_LOG)
    + "\nUser jdoe logged into SFO-FIN-01 from jdoe-laptop, escalated by CONTOSO\\jdoe"
)
jk_out, jk_counts, jk_spans = sanitize_text(JSON_KEY_SAMPLE_TEXT)
check(
    "sanitize_text JSON-key detection redacts an unconventional hostname (no WORKSTATION/SERVER/etc prefix) via the 'hostname' JSON key",
    "SFO-FIN-01" not in jk_out and '"hostname": "REDACTED"' in jk_out,
)
check(
    "sanitize_text JSON-key detection redacts destination_asset carrying the same value as hostname",
    '"destination_asset": "REDACTED"' in jk_out,
)
check(
    "sanitize_text JSON-key detection fully redacts a different asset value (source_asset) as one clean whole, not a partial fragment",
    "jdoe-laptop" not in jk_out and '"source_asset": "REDACTED"' in jk_out and "REDACTED-laptop" not in jk_out,
)
check(
    "sanitize_text JSON-key detection redacts a bare username via 'account' and 'process.username'",
    '"account": "REDACTED"' in jk_out and '"process": {"username": "REDACTED"' in jk_out,
)
check(
    "sanitize_text JSON-key detection redacts process.account_domain (a Windows domain, not a username/host) as REDACTED too",
    '"account_domain": "REDACTED"' in jk_out,
)
check(
    "sanitize_text JSON-key detection redacts parent_process fields (username/account_domain both different real values than the child process)",
    '"parent_process": {"username": "REDACTED", "account_domain": "REDACTED"' in jk_out and "SYSTEM" not in jk_out,
)
check(
    "sanitize_text JSON-key propagation: the same values mentioned again in free text outside any JSON key are redacted too",
    "User REDACTED logged into REDACTED from REDACTED, escalated by REDACTED" in jk_out,
)
check(
    "sanitize_text JSON-key detection counts several distinct values even though they all render as the same REDACTED text",
    jk_counts["json_fields"] >= 6,
)

# --- json_fields detection is case-insensitive and skipped when the
# category is disabled ---
jk_ci_out, jk_ci_counts, _ = sanitize_text('{"user": "JDoe"}\nUser jdoe signed in.')
check(
    "sanitize_text JSON-key detection is case-insensitive across JSON and free text",
    "JDoe" not in jk_ci_out and "jdoe" not in jk_ci_out and jk_ci_out.count("REDACTED") == 2,
)
jk_disabled_out, jk_disabled_counts, _ = sanitize_text(
    '{"hostname": "SFO-FIN-01", "account": "jdoe"}', categories={"json_fields": False}
)
check(
    "sanitize_text JSON-key detection is skipped entirely when json_fields is disabled",
    "SFO-FIN-01" in jk_disabled_out and "jdoe" in jk_disabled_out and jk_disabled_counts["json_fields"] == 0,
)

# --- source_account/destination_account are also recognized JSON keys
# (added after the analyst flagged these were missing from the original
# key list) ---
SRC_DST_ACCOUNT_TEXT = (
    '{"source_account": "jdoe", "destination_account": "asmith"}'
    "\nUser jdoe accessed a resource as asmith"
)
sda_out, sda_counts, _ = sanitize_text(SRC_DST_ACCOUNT_TEXT)
check(
    "sanitize_text redacts source_account via the JSON key list",
    "jdoe" not in sda_out and '"source_account": "REDACTED"' in sda_out,
)
check(
    "sanitize_text redacts destination_account via the JSON key list",
    "asmith" not in sda_out and '"destination_account": "REDACTED"' in sda_out,
)
check(
    "sanitize_text source_account/destination_account values propagate to free text outside the JSON",
    "User REDACTED accessed a resource as REDACTED" in sda_out,
)
check("sanitize_text source_account/destination_account count 2 distinct values", sda_counts["json_fields"] == 2)

# --- DB layer ---
with tempfile.TemporaryDirectory() as d:
    db_path = os.path.join(d, "test.db")
    db = DB(db_path)
    templates = db.list_templates()
    check("seed templates loaded", len(templates) == 6)
    names = {t["name"] for t in templates}
    check("seed includes O365 auth escalation", "Suspicious O365 Authentication" in names)
    check("seed includes inbox rule escalation", "Suspicious O365 Inbox Rule" in names)
    check("seed includes process escalation", "Malicious Process Execution" in names)
    check(
        "seed names don't have a redundant category suffix",
        not any(n.endswith("- Escalation") or "- False Positive" in n for n in names),
    )
    categories = {t["category"] for t in templates}
    check("seed uses escalation/false_positive categories", categories == {"escalation", "false_positive"})

    tid = db.add_template("false_positive", "Test FP", "Test", "Body {user}")
    t = db.get_template(tid)
    check("template add/get", t["name"] == "Test FP" and t["category"] == "false_positive")

    db.update_template(tid, "false_positive", "Test FP 2", "Test", "Body2 {user}")
    t2 = db.get_template(tid)
    check("template update", t2["name"] == "Test FP 2")

    db.delete_template(tid)
    check("template delete", db.get_template(tid) is None)

    iid = db.add_incident("Test Incident", "{}", "analysis text", "output text", "{}")
    inc = db.get_incident(iid)
    check("incident add/get", inc["title"] == "Test Incident")

    db.update_incident(iid, "Renamed Incident", "{}", "a2", "o2", "{}")
    inc2 = db.get_incident(iid)
    check("incident update", inc2["title"] == "Renamed Incident")

    results = db.list_incidents("Renamed")
    check("incident search", len(results) == 1)

    db.rename_incident(iid, "INC-1234 - Phishing Case")
    inc3 = db.get_incident(iid)
    check("rename_incident changes title", inc3["title"] == "INC-1234 - Phishing Case")
    check("rename_incident leaves other fields untouched", inc3["analysis"] == "a2" and inc3["output"] == "o2")

    check("new incidents default to Open status", inc3["status"] == "Open")

    db.update_incident_status(iid, "Escalated")
    inc4 = db.get_incident(iid)
    check("update_incident_status changes status", inc4["status"] == "Escalated")
    check("update_incident_status leaves title untouched", inc4["title"] == "INC-1234 - Phishing Case")

    iid2 = db.add_incident("Second Incident", "{}", "a", "o", "{}")
    escalated_only = db.list_incidents(status="Escalated")
    check("list_incidents status filter returns just the matching incident", len(escalated_only) == 1 and escalated_only[0]["id"] == iid)
    closed_only = db.list_incidents(status="Closed")
    check("list_incidents status filter excludes non-matching incidents", closed_only == [])
    all_statuses = db.list_incidents(status="all")
    check("list_incidents status='all' returns everything", len(all_statuses) == 2)
    db.delete_incident(iid2)

    check("INCIDENT_STATUSES includes the expected values", set(INCIDENT_STATUSES) == {"Open", "Escalated", "Closed", "False Positive"})

    db.delete_incident(iid)
    check("incident delete", db.get_incident(iid) is None)

    nid = db.add_note("KB00001 - VPN Split Tunnel", "Reference: this is expected for remote sales staff.")
    note = db.get_note(nid)
    check("note add/get", note["title"] == "KB00001 - VPN Split Tunnel")

    db.update_note(nid, "KB00001 - VPN Split Tunnel (updated)", "New body text")
    note2 = db.get_note(nid)
    check("note update", note2["title"] == "KB00001 - VPN Split Tunnel (updated)" and note2["body"] == "New body text")

    note_results = db.list_notes("VPN")
    check("note search", len(note_results) == 1)
    check("note search no match returns empty", db.list_notes("nonexistent_xyz") == [])

    db.delete_note(nid)
    check("note delete", db.get_note(nid) is None)

    kid = db.add_sanitize_keyword("Project Falcon", "PROJECT_X")
    kw = db.get_sanitize_keyword(kid)
    check("sanitize_keyword add/get", kw["keyword"] == "Project Falcon" and kw["replacement"] == "PROJECT_X")

    db.update_sanitize_keyword(kid, "Project Falcon", "PROJECT_Y")
    kw2 = db.get_sanitize_keyword(kid)
    check("sanitize_keyword update", kw2["replacement"] == "PROJECT_Y")

    kid2 = db.add_sanitize_keyword("acme corp", "CLIENT_A")
    kw_list = db.list_sanitize_keywords()
    check("list_sanitize_keywords returns every saved keyword", len(kw_list) == 2)
    check(
        "list_sanitize_keywords is ordered alphabetically case-insensitively",
        [k["keyword"] for k in kw_list] == ["acme corp", "Project Falcon"],
    )

    db.delete_sanitize_keyword(kid2)
    check("sanitize_keyword delete", db.get_sanitize_keyword(kid2) is None)
    check("list_sanitize_keywords reflects the delete", len(db.list_sanitize_keywords()) == 1)

    db.delete_sanitize_keyword(kid)

# --- migration: an existing DB with the old 'canned' category and old
# suffixed template names gets cleaned up automatically on open ---
with tempfile.TemporaryDirectory() as d:
    db_path = os.path.join(d, "legacy.db")
    db2 = DB(db_path)
    # simulate a leftover row from an older version of the app
    db2.conn.execute(
        "INSERT INTO templates (category, name, alert_type, body, created_at, updated_at) "
        "VALUES ('canned', 'My Custom Canned Response - Escalation', 'Test', 'Body', '', '')"
    )
    db2.conn.commit()
    db2._migrate_template_category_and_names()
    rows = {t["name"]: t["category"] for t in db2.list_templates()}
    check("legacy 'canned' category migrated to 'false_positive'", rows["My Custom Canned Response - Escalation"] == "false_positive")
    check("legacy seed name suffix migrated on re-open", "Suspicious O365 Authentication" in rows and rows["Suspicious O365 Authentication"] == "escalation")

# --- migration: an incidents table from before the status column existed
# gets the column added automatically (defaulting existing rows to
# 'Open') the next time the DB is opened, with no data loss. ---
with tempfile.TemporaryDirectory() as d:
    db_path = os.path.join(d, "legacy_status.db")
    raw_conn = sqlite3.connect(db_path)
    raw_conn.execute(
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "title TEXT, raw_logs TEXT, analysis TEXT, output TEXT, "
        "extracted_json TEXT, created_at TEXT, updated_at TEXT)"
    )
    raw_conn.execute(
        "INSERT INTO incidents (title, raw_logs, analysis, output, "
        "extracted_json, created_at, updated_at) VALUES "
        "('Pre-migration Incident', '{}', 'a', 'o', '{}', '', '')"
    )
    raw_conn.commit()
    raw_conn.close()

    db_legacy_status = DB(db_path)
    legacy_inc = db_legacy_status.list_incidents()[0]
    check("legacy incidents table gains a status column on open", "status" in legacy_inc)
    check("legacy incident rows default to Open status", legacy_inc["status"] == "Open")
    db_legacy_status.update_incident_status(legacy_inc["id"], "Closed")
    check("status column is fully usable after migration", db_legacy_status.get_incident(legacy_inc["id"])["status"] == "Closed")

# --- template export/import: sharing templates between analysts ---
with tempfile.TemporaryDirectory() as d:
    db_path = os.path.join(d, "export_test.db")
    db3 = DB(db_path)

    all_export = db3.export_templates()
    check("export_templates returns every template by default", len(all_export) == 6)
    check("export_templates omits id/timestamps", "id" not in all_export[0] and "created_at" not in all_export[0])

    some_ids = [t["id"] for t in db3.list_templates()[:2]]
    subset_export = db3.export_templates(some_ids)
    check("export_templates(ids) returns only the requested templates", len(subset_export) == 2)

    # importing into a fresh DB: brand-new names come straight in
    db_path2 = os.path.join(d, "import_test.db")
    db4 = DB(db_path2)
    db4.conn.execute("DELETE FROM templates")
    db4.conn.commit()
    imported, skipped = db4.import_templates(all_export)
    check("import_templates imports all new templates", imported == 6 and skipped == [])
    check("import_templates round-trip preserves names", {t["name"] for t in db4.list_templates()} == {t["name"] for t in all_export})

    # importing again without overwrite: everything is a duplicate by name
    imported2, skipped2 = db4.import_templates(all_export)
    check("import_templates skips existing names by default", imported2 == 0 and len(skipped2) == 6)

    # importing with overwrite=True updates the existing rows in place
    modified = [dict(all_export[0])]
    modified[0]["body"] = "CHANGED BODY"
    imported3, skipped3 = db4.import_templates(modified, overwrite=True)
    check("import_templates overwrite updates existing template", imported3 == 1 and skipped3 == [])
    updated_row = next(t for t in db4.list_templates() if t["name"] == modified[0]["name"])
    check("import_templates overwrite actually changed the body", updated_row["body"] == "CHANGED BODY")

# --- field mapping profile export/import: sharing custom log types ---
with tempfile.TemporaryDirectory() as d:
    mapping_path = os.path.join(d, "mappings.json")
    with open(mapping_path, "w", encoding="utf-8") as f:
        json.dump(mapper.config, f)
    mapper2 = FieldMapper(mapping_path)

    original_count = len(mapper2.config["profiles"])
    one_id = mapper2.config["profiles"][0]["id"]
    exported_one = mapper2.export_profiles([one_id])
    check("export_profiles(ids) returns just the requested profile", len(exported_one) == 1 and exported_one[0]["id"] == one_id)

    exported_all = mapper2.export_profiles()
    check("export_profiles() returns every profile", len(exported_all) == original_count)

    # importing a profile whose id already exists is skipped by default
    imported_p, skipped_p = mapper2.import_profiles(exported_one)
    check("import_profiles skips an existing id by default", imported_p == 0 and skipped_p == [one_id])
    check("import_profiles skip leaves profile count unchanged", len(mapper2.config["profiles"]) == original_count)

    # importing with overwrite=True replaces it in place
    changed = json.loads(json.dumps(exported_one))
    changed[0]["label"] = "CHANGED LABEL"
    imported_p2, skipped_p2 = mapper2.import_profiles(changed, overwrite=True)
    check("import_profiles overwrite replaces the existing profile", imported_p2 == 1 and skipped_p2 == [])
    check("import_profiles overwrite actually changed the label", mapper2.config["profiles"][0]["label"] == "CHANGED LABEL")
    check("import_profiles overwrite doesn't change profile count", len(mapper2.config["profiles"]) == original_count)

    # importing a brand-new profile id appends it
    new_profile = {
        "id": "custom_phishing_alert",
        "label": "Custom Phishing Alert",
        "detect_keys": ["phish_indicator"],
        "fields": {"user": "user", "src_ip": "src_ip"},
    }
    imported_p3, skipped_p3 = mapper2.import_profiles([new_profile])
    check("import_profiles appends a brand-new profile id", imported_p3 == 1 and skipped_p3 == [])
    check("import_profiles new profile count grew by one", len(mapper2.config["profiles"]) == original_count + 1)
    check("import_profiles persisted the new profile to disk", any(p["id"] == "custom_phishing_alert" for p in json.load(open(mapping_path))["profiles"]))

# --- field reordering: a profile's "fields" dict order IS its display
# order - both in the Field Mappings tab's tree and, more importantly, in
# FieldMapper.parse()'s field_order for the Extracted Fields table - this
# is the mechanism the Field Mappings tab's Move Field Up/Down buttons
# rely on. Verify reordering a profile's fields dict survives a
# save_config() -> reload round trip, and that parse() picks up the new
# order afterward. ---
with tempfile.TemporaryDirectory() as d:
    reorder_mapping_path = os.path.join(d, "reorder_mappings.json")
    with open(reorder_mapping_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "profiles": [
                    {
                        "id": "reorder_test",
                        "label": "Reorder Test",
                        "detect_keys": ["marker_key"],
                        "fields": {"user": "user", "host": "host", "timestamp": "timestamp"},
                    }
                ],
                "generic_fallback": {},
            },
            f,
        )
    reorder_mapper = FieldMapper(reorder_mapping_path)
    reorder_profile = reorder_mapper.config["profiles"][0]
    check("fields dict starts in insertion order", list(reorder_profile["fields"].keys()) == ["user", "host", "timestamp"])

    # Simulate "Move Field Up" on 'timestamp' (swap it with its immediate
    # predecessor 'host') - the same list-swap-and-rebuild
    # _move_selected_mapping_field does in app.py.
    reorder_keys = list(reorder_profile["fields"].keys())
    reorder_idx = reorder_keys.index("timestamp")
    reorder_keys[reorder_idx], reorder_keys[reorder_idx - 1] = reorder_keys[reorder_idx - 1], reorder_keys[reorder_idx]
    reorder_profile["fields"] = {k: reorder_profile["fields"][k] for k in reorder_keys}
    reorder_mapper.save_config(reorder_mapper.config)
    check("reordered fields dict has the new order in memory", list(reorder_profile["fields"].keys()) == ["user", "timestamp", "host"])

    reloaded_mapper = FieldMapper(reorder_mapping_path)
    reloaded_profile = reloaded_mapper.config["profiles"][0]
    check(
        "reordered field order survives a save_config -> reload round trip through disk",
        list(reloaded_profile["fields"].keys()) == ["user", "timestamp", "host"],
    )

    reorder_parse_result = reloaded_mapper.parse(json.dumps({"marker_key": "x", "user": "jdoe", "host": "h1", "timestamp": "t1"}))
    check(
        "FieldMapper.parse()'s field_order reflects the reordered fields dict, not "
        "the original insertion order - this is what actually reorders the "
        "Extracted Fields table's rows after Move Field Up/Down",
        reorder_parse_result["field_order"] == ["user", "timestamp", "host"],
    )

# --- note export/import: sharing KB articles/saved queries between analysts ---
with tempfile.TemporaryDirectory() as d:
    db_path = os.path.join(d, "notes_export_test.db")
    db5 = DB(db_path)
    db5.add_note("Note A", "Body A")
    db5.add_note("Note B", "Body B")

    all_notes_export = db5.export_notes()
    check("export_notes returns every note by default", len(all_notes_export) == 2)
    check("export_notes omits id/timestamps", "id" not in all_notes_export[0] and "created_at" not in all_notes_export[0])

    some_note_ids = [n["id"] for n in db5.list_notes()[:1]]
    subset_notes_export = db5.export_notes(some_note_ids)
    check("export_notes(ids) returns only the requested notes", len(subset_notes_export) == 1)

    db_path2 = os.path.join(d, "notes_import_test.db")
    db6 = DB(db_path2)
    db6.conn.execute("DELETE FROM notes")
    db6.conn.commit()
    imported_n, skipped_n = db6.import_notes(all_notes_export)
    check("import_notes imports all new notes", imported_n == 2 and skipped_n == [])
    check("import_notes round-trip preserves titles", {n["title"] for n in db6.list_notes()} == {n["title"] for n in all_notes_export})

    imported_n2, skipped_n2 = db6.import_notes(all_notes_export)
    check("import_notes skips existing titles by default", imported_n2 == 0 and len(skipped_n2) == 2)

    modified_notes = [dict(all_notes_export[0])]
    modified_notes[0]["body"] = "CHANGED NOTE BODY"
    imported_n3, skipped_n3 = db6.import_notes(modified_notes, overwrite=True)
    check("import_notes overwrite updates existing note", imported_n3 == 1 and skipped_n3 == [])
    updated_note = next(n for n in db6.list_notes() if n["title"] == modified_notes[0]["title"])
    check("import_notes overwrite actually changed the body", updated_note["body"] == "CHANGED NOTE BODY")

# --------------------------------------------------------------------------
# Text Tools tab: individual text_tool_* functions, then apply_text_tools()
# pipeline ordering/combination behavior.
# --------------------------------------------------------------------------

check(
    "TEXT_TOOL_OPERATIONS keys are unique and match _TEXT_TOOL_FUNCS-style lookup",
    len({key for key, _label, _func in TEXT_TOOL_OPERATIONS}) == len(TEXT_TOOL_OPERATIONS),
)

# --- text_tool_base64_decode ---
b64_payload = base64.b64encode("user jdoe logged in".encode("utf-8")).decode("ascii")
check(
    "text_tool_base64_decode decodes a clean base64 string",
    text_tool_base64_decode(b64_payload) == "user jdoe logged in",
)
check(
    "text_tool_base64_decode strips surrounding non-base64 junk (quotes, newlines) before decoding",
    text_tool_base64_decode(f"\"{b64_payload[:10]}\n{b64_payload[10:]}\"") == "user jdoe logged in",
)
b64_no_padding = base64.b64encode(b"abc").decode("ascii").rstrip("=")
check(
    "text_tool_base64_decode re-pads a base64 string missing its trailing '='",
    text_tool_base64_decode(b64_no_padding) == "abc",
)
b64_with_nulls = base64.b64encode("jdoe".encode("utf-16")).decode("ascii")
check(
    "text_tool_base64_decode drops NUL bytes left over from a UTF-16 source",
    "\x00" not in text_tool_base64_decode(b64_with_nulls) and "jdoe" in text_tool_base64_decode(b64_with_nulls),
)
check(
    "text_tool_base64_decode reports an error (not a crash) on an empty/junk-only input",
    text_tool_base64_decode("!!!@@@###").startswith("[base64 decode error"),
)
check(
    "text_tool_base64_decode reports an error (not a crash) on a cleaned string with invalid base64 length",
    text_tool_base64_decode("!!!a!!!").startswith("[base64 decode error"),
)

# --- text_tool_hex_decode ---
hex_payload = "user jdoe logged in".encode("utf-8").hex()
check("text_tool_hex_decode decodes a clean hex string", text_tool_hex_decode(hex_payload) == "user jdoe logged in")
check(
    "text_tool_hex_decode strips separators (spaces, colons, 0x prefix) before decoding",
    text_tool_hex_decode("0x" + " ".join(hex_payload[i:i + 2] for i in range(0, len(hex_payload), 2))) == "user jdoe logged in",
)
check(
    "text_tool_hex_decode drops a dangling trailing nibble instead of erroring",
    text_tool_hex_decode(hex_payload + "a") == "user jdoe logged in",
)
check(
    "text_tool_hex_decode reports an error (not a crash) when there's nothing to decode",
    text_tool_hex_decode("zzzz").startswith("[hex decode error"),
)

# --- text_tool_url_decode ---
check(
    "text_tool_url_decode decodes percent-escapes and '+' as space",
    text_tool_url_decode("user=jdoe%40contoso.com&query=a+b") == "user=jdoe@contoso.com&query=a b",
)
check("text_tool_url_decode leaves plain text untouched", text_tool_url_decode("no encoding here") == "no encoding here")

# --- text_tool_extract_emails / text_tool_extract_ips ---
IOC_TEXT = "Contact jdoe@contoso.com or asmith@contoso.com from 10.1.2.3 and 8.8.8.8 (also ::1 loopback)"
check(
    "text_tool_extract_emails pulls every email address, one per line, in order",
    text_tool_extract_emails(IOC_TEXT) == "jdoe@contoso.com\nasmith@contoso.com",
)
check(
    "text_tool_extract_ips pulls every IPv4 address, one per line, in order",
    "10.1.2.3" in text_tool_extract_ips(IOC_TEXT) and "8.8.8.8" in text_tool_extract_ips(IOC_TEXT),
)
check("text_tool_extract_emails returns empty string when nothing matches", text_tool_extract_emails("no emails here") == "")

# --- text_tool_extract_paths ---
PATH_TEXT = (
    "Attached the report.pdf to the ticket. Also grab "
    "C:\\Users\\jdoe\\Documents\\notes.txt and \\\\fileserver\\share\\archive.zip, "
    "plus C:\\Program Files\\Contoso App\\uninstall.exe, and ./local/script.sh. "
    "Ignore version 10.0.19041 and the word application itself."
)
extracted_paths = text_tool_extract_paths(PATH_TEXT)
check(
    "text_tool_extract_paths finds a bare filename with no path in front of it",
    "report.pdf" in extracted_paths,
)
check(
    "text_tool_extract_paths finds a full Windows path with a drive letter",
    "C:\\Users\\jdoe\\Documents\\notes.txt" in extracted_paths,
)
check(
    "text_tool_extract_paths finds a UNC path",
    "\\\\fileserver\\share\\archive.zip" in extracted_paths,
)
check(
    "text_tool_extract_paths handles a directory segment containing a space (e.g. 'Program Files')",
    "C:\\Program Files\\Contoso App\\uninstall.exe" in extracted_paths,
)
check(
    "text_tool_extract_paths finds a relative Unix-style path",
    "./local/script.sh" in extracted_paths,
)
check(
    "text_tool_extract_paths does not mistake a bare version number for a file path",
    "10.0.19041" not in extracted_paths,
)
check(
    "text_tool_extract_paths does not match an ordinary word with no recognized extension",
    "application" not in extracted_paths,
)
check(
    "text_tool_extract_paths returns empty string when nothing matches",
    text_tool_extract_paths("nothing to see here") == "",
)

# --- text_tool_remove_whitespace ---
check(
    "text_tool_remove_whitespace collapses runs of spaces/tabs to a single space",
    text_tool_remove_whitespace("a   b\t\tc") == "a b c",
)
check(
    "text_tool_remove_whitespace collapses multiple blank lines down to none between real lines",
    text_tool_remove_whitespace("line one\n\n\n\nline two") == "line one\nline two",
)
check(
    "text_tool_remove_whitespace trims leading/trailing whitespace per line",
    text_tool_remove_whitespace("   padded line   \n  another  ") == "padded line\nanother",
)

# --- text_tool_sort_alphabetically ---
check(
    "text_tool_sort_alphabetically sorts lines case-insensitively while preserving original case",
    text_tool_sort_alphabetically("Zebra\napple\nMango") == "apple\nMango\nZebra",
)
check(
    "text_tool_sort_alphabetically drops blank lines",
    text_tool_sort_alphabetically("banana\n\napple") == "apple\nbanana",
)

# --- text_tool_remove_duplicates ---
check(
    "text_tool_remove_duplicates drops case-insensitive repeats, keeping first occurrence's case and order",
    text_tool_remove_duplicates("jdoe\nJDoe\nasmith\nJDOE") == "jdoe\nasmith",
)
check("text_tool_remove_duplicates leaves an already-unique list unchanged", text_tool_remove_duplicates("a\nb\nc") == "a\nb\nc")

# --- text_tool_defang ---
check(
    "text_tool_defang escapes '://' and '.' and swaps http/https for hxxp/hxxps",
    text_tool_defang("Visit http://bad.example.com/path or https://1.2.3.4")
    == "Visit hxxp[://]bad[.]example[.]com/path or hxxps[://]1[.]2[.]3[.]4",
)
check(
    "text_tool_defang preserves capitalization style when swapping http for hxxp (Title-case and ALL-CAPS)",
    text_tool_defang("Http://a.com").startswith("Hxxp") and text_tool_defang("HTTP://a.com").startswith("HXXP"),
)

# --- apply_text_tools: pipeline ordering + combined extraction ---
check(
    "apply_text_tools with no operations selected returns the input unchanged",
    apply_text_tools("unchanged text", []) == "unchanged text",
)
check(
    "apply_text_tools ignores unknown operation keys instead of erroring",
    apply_text_tools("hello", ["not_a_real_operation"]) == "hello",
)
check(
    "apply_text_tools runs a single selected operation the same as calling it directly",
    apply_text_tools("Zebra\napple", ["sort"]) == text_tool_sort_alphabetically("Zebra\napple"),
)
check(
    "apply_text_tools applies base64 decode before extracting emails, regardless of selection order",
    apply_text_tools(
        base64.b64encode(b"contact jdoe@contoso.com now").decode("ascii"),
        ["extract_emails", "base64_decode"],
    ) == "jdoe@contoso.com",
)
check(
    "apply_text_tools combines Extract Email Addresses + Extract IP Addresses from the same source text "
    "rather than feeding one's output into the other",
    apply_text_tools(IOC_TEXT, ["extract_emails", "extract_ips"])
    == text_tool_extract_emails(IOC_TEXT) + "\n" + text_tool_extract_ips(IOC_TEXT),
)
IOC_TEXT_WITH_PATH = IOC_TEXT + " (see report.pdf for details)"
check(
    "apply_text_tools combines all three extraction operations (Email + IP + File Path) from the same "
    "source text, emails first then IPs then paths",
    apply_text_tools(IOC_TEXT_WITH_PATH, ["extract_paths", "extract_emails", "extract_ips"])
    == text_tool_extract_emails(IOC_TEXT_WITH_PATH) + "\n"
    + text_tool_extract_ips(IOC_TEXT_WITH_PATH) + "\n"
    + text_tool_extract_paths(IOC_TEXT_WITH_PATH),
)
check(
    "apply_text_tools runs Defang after extraction so defanged '[.]'/[://]' text doesn't break IP/email matching",
    apply_text_tools(IOC_TEXT, ["extract_ips", "defang"]) == text_tool_defang(text_tool_extract_ips(IOC_TEXT)),
)
check(
    "apply_text_tools chains clean-up operations (whitespace -> sort -> dedupe) in that fixed order",
    apply_text_tools("banana\n\n  Apple  \nbanana", ["dedupe", "sort", "remove_whitespace"])
    == text_tool_remove_duplicates(text_tool_sort_alphabetically(text_tool_remove_whitespace("banana\n\n  Apple  \nbanana"))),
)

# --- FieldMapper.parse(forced_profile_id=...): manual profile override ---
# Isolated synthetic config (not the live field_mappings.json, which is a
# moving target) with two profiles engineered so auto-detect's normal
# "first profile in array order to exact-match wins" rule picks the wrong
# one - reproducing the class of bug the override dropdown exists to let
# an analyst work around by hand.
with tempfile.TemporaryDirectory() as d:
    forced_mapping_path = os.path.join(d, "forced_mappings.json")
    with open(forced_mapping_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "profiles": [
                    {
                        "id": "generic_wins_by_default",
                        "label": "Generic Alert (auto-detect default)",
                        "detect_keys": ["shared_key"],
                        "fields": {"user": "shared_key", "note": "literal:generic"},
                    },
                    {
                        "id": "specific_profile",
                        "label": "Specific Profile (needs override)",
                        "detect_keys": ["shared_key", "specific_only_key"],
                        "fields": {"user": "shared_key", "note": "literal:specific"},
                    },
                ],
                "generic_fallback": {},
            },
            f,
        )
    forced_mapper = FieldMapper(forced_mapping_path)
    AMBIGUOUS_LOG = json.dumps({"shared_key": "x", "specific_only_key": "y"})

    auto_result = forced_mapper.parse(AMBIGUOUS_LOG)
    check(
        "auto-detect picks the first exact-matching profile in array order "
        "(the ambiguity this feature exists to let an analyst override)",
        auto_result["label"] == "Generic Alert (auto-detect default)",
    )

    forced_result = forced_mapper.parse(AMBIGUOUS_LOG, forced_profile_id="specific_profile")
    check("forced_profile_id overrides auto-detect's choice", forced_result["label"] == "Specific Profile (needs override)")
    check("forced_profile_id extracts fields per the forced profile's own mapping", forced_result["canonical"]["note"] == "specific")
    check("forced_profile_id still reports matched=True", forced_result["matched"] is True)
    check(
        "forced_profile_id surfaces a warning that auto-detect was bypassed",
        any("manually set" in w.lower() and "specific profile" in w.lower() for w in forced_result["warnings"]),
    )

    stale_result = forced_mapper.parse(AMBIGUOUS_LOG, forced_profile_id="deleted_profile_id")
    check(
        "an unknown/stale forced_profile_id falls back to auto-detect's result",
        stale_result["label"] == "Generic Alert (auto-detect default)",
    )
    check(
        "an unknown/stale forced_profile_id warns instead of silently ignoring the override",
        any("could not be found" in w.lower() for w in stale_result["warnings"]),
    )

# --- virustotal_url: Extracted Fields table's "VT" quick-lookup link ---
check(
    "virustotal_url builds a file lookup URL for a bare SHA256",
    virustotal_url("949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b")
    == "https://www.virustotal.com/gui/file/949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b",
)
check(
    "virustotal_url builds a file lookup URL for a bare SHA1",
    virustotal_url("3f64c98f22da277a07cab248c44c56eedb796a81")
    == "https://www.virustotal.com/gui/file/3f64c98f22da277a07cab248c44c56eedb796a81",
)
check(
    "virustotal_url builds a file lookup URL for a bare MD5",
    virustotal_url("8ec922c7a58a8701ab481b7be9644536")
    == "https://www.virustotal.com/gui/file/8ec922c7a58a8701ab481b7be9644536",
)
check(
    "virustotal_url lowercases a mixed-case hash for the URL",
    virustotal_url("8EC922C7A58A8701AB481B7BE9644536")
    == "https://www.virustotal.com/gui/file/8ec922c7a58a8701ab481b7be9644536",
)
check(
    "virustotal_url builds an ip-address lookup URL for a bare IPv4",
    virustotal_url("199.243.204.140") == "https://www.virustotal.com/gui/ip-address/199.243.204.140",
)
check(
    "virustotal_url builds an ip-address lookup URL for a bare IPv6",
    virustotal_url("2001:4860:4860::8888") == "https://www.virustotal.com/gui/ip-address/2001:4860:4860::8888",
)
check("virustotal_url returns None for an empty value", virustotal_url("") is None)
check("virustotal_url returns None for None", virustotal_url(None) is None)
check("virustotal_url returns None for an ordinary hostname", virustotal_url("WORKSTATION-07") is None)
check("virustotal_url returns None for an ordinary username/email", virustotal_url("jdoe@contoso.com") is None)
check(
    "virustotal_url returns None for a join_list-aggregated multi-IP value "
    "(never link to just the first of several values)",
    virustotal_url("203.0.113.10; 203.0.113.11") is None,
)
check(
    "virustotal_url returns None for a hex string of the wrong length to be a hash",
    virustotal_url("deadbeef") is None,
)
check(
    "virustotal_url returns None for a version number that happens to have 4 dot-separated parts",
    virustotal_url("10.0.19041.1") is None,
)

# --- virustotal_url: URL lookups. Unlike hashes/IPs (fullmatch on the
# WHOLE value), a URL is found WITHIN the value - the identifier is the
# URL itself, base64 (URL-safe) encoded with '=' padding stripped, which
# is the same scheme VirusTotal's own API/GUI uses. This is computed
# entirely locally (no network call, no API key) - just building a link,
# exactly like the hash/IP cases above. ---
def _expected_vt_url_id(u):
    return base64.urlsafe_b64encode(u.encode("utf-8")).decode("ascii").rstrip("=")

check(
    "virustotal_url builds a url lookup for a bare https URL",
    virustotal_url("https://evil.example.com/payload.exe")
    == "https://www.virustotal.com/gui/url/" + _expected_vt_url_id("https://evil.example.com/payload.exe"),
)
check(
    "virustotal_url builds a url lookup for a plain http URL (not just https)",
    virustotal_url("http://evil.example.com/payload.exe")
    == "https://www.virustotal.com/gui/url/" + _expected_vt_url_id("http://evil.example.com/payload.exe"),
)
check(
    "virustotal_url finds a URL embedded in a longer field value, not just a bare URL",
    virustotal_url("GET https://contoso.com/api/login HTTP/1.1")
    == "https://www.virustotal.com/gui/url/" + _expected_vt_url_id("https://contoso.com/api/login"),
)
check(
    "virustotal_url strips trailing sentence punctuation that isn't part of the URL",
    virustotal_url("See https://evil.example.com/x for details.")
    == "https://www.virustotal.com/gui/url/" + _expected_vt_url_id("https://evil.example.com/x"),
)
check(
    "virustotal_url strips a trailing wrapping parenthesis",
    virustotal_url("(https://evil.example.com/x)")
    == "https://www.virustotal.com/gui/url/" + _expected_vt_url_id("https://evil.example.com/x"),
)
check(
    "virustotal_url returns None for a join_list-aggregated multi-URL value "
    "(never link to just the first of several values)",
    virustotal_url("http://a.example.com; http://b.example.com") is None,
)
check("virustotal_url returns None for text with no URL in it", virustotal_url("no link here") is None)

# --- find_misspelled_word_spans / spelling_suggestions (spell-check) ---
# pyspellchecker is an optional dependency (the app degrades to "no
# spelling issues found" without it) - probe for it directly here so this
# test file degrades the same way instead of hard-failing the whole
# suite over a missing optional package.
try:
    import spellchecker as _spellchecker_probe  # noqa: F401
    _SPELLCHECK_AVAILABLE = True
except ImportError:
    _SPELLCHECK_AVAILABLE = False

check("find_misspelled_word_spans returns [] for empty text", find_misspelled_word_spans("") == [])
check("spelling_suggestions returns [] for an empty word", spelling_suggestions("") == [])

if _SPELLCHECK_AVAILABLE:
    SPELLCHECK_SAMPLE = "The analsyt confirmed the user athenticated from an unfamilar location."
    spellcheck_spans = find_misspelled_word_spans(SPELLCHECK_SAMPLE)
    spellcheck_words = {w for _, _, w in spellcheck_spans}
    check("find_misspelled_word_spans catches a real misspelling", "analsyt" in spellcheck_words)
    check("find_misspelled_word_spans catches a second real misspelling", "athenticated" in spellcheck_words)
    check(
        "find_misspelled_word_spans span offsets are correct (slice matches the flagged word)",
        all(SPELLCHECK_SAMPLE[s:e] == w for s, e, w in spellcheck_spans),
    )
    check(
        "find_misspelled_word_spans skips ALL-CAPS acronyms (SOC, VT, etc. are not misspellings)",
        find_misspelled_word_spans("The SOC used VT for the lookup.") == [],
    )
    check("find_misspelled_word_spans skips words under 3 letters", find_misspelled_word_spans("Go to it.") == [])
    check(
        "find_misspelled_word_spans's bundled tech-terms list covers common SOC vocabulary "
        "(malware/webshell/exfiltration/hostname shouldn't be flagged)",
        find_misspelled_word_spans("The malware used a webshell for exfiltration via the hostname.") == [],
    )
    check(
        "find_misspelled_word_spans respects the analyst's own custom dictionary",
        find_misspelled_word_spans("AlertForge helped triage this quickly.", known_words=["alertforge"]) == [],
    )
    check(
        "find_misspelled_word_spans still flags a brand name not yet in the custom dictionary",
        any(w == "AlertForge" for _, _, w in find_misspelled_word_spans("AlertForge helped triage this quickly.")),
    )

    recieved_suggestions = spelling_suggestions("recieved")
    check("spelling_suggestions returns at least one candidate for a common misspelling", len(recieved_suggestions) > 0)
    check("spelling_suggestions's top suggestion for 'recieved' is 'received'", recieved_suggestions[0] == "received")
else:
    print("[SKIP] pyspellchecker not installed in this environment - spell-check content checks skipped (optional dependency)")

# --- DB.custom_dictionary CRUD (spell-check's "Add to Dictionary") ---
with tempfile.TemporaryDirectory() as d:
    dict_db_path = os.path.join(d, "dictionary_test.db")
    dict_db = DB(dict_db_path)
    check("custom dictionary starts empty", dict_db.list_custom_dictionary_words() == [])
    dict_db.add_custom_dictionary_word("AlertForge")
    words = dict_db.list_custom_dictionary_words()
    check("add_custom_dictionary_word adds a word", len(words) == 1 and words[0]["word"] == "AlertForge")
    dict_db.add_custom_dictionary_word("alertforge")
    check(
        "add_custom_dictionary_word is case-insensitively unique - adding the same word "
        "again (different case) doesn't create a duplicate",
        len(dict_db.list_custom_dictionary_words()) == 1,
    )
    dict_db.add_custom_dictionary_word("InsightIDR")
    check("add_custom_dictionary_word adds a second, distinct word", len(dict_db.list_custom_dictionary_words()) == 2)
    dict_db.add_custom_dictionary_word("  ")
    check("add_custom_dictionary_word ignores blank/whitespace-only input", len(dict_db.list_custom_dictionary_words()) == 2)
    wid = next(w["id"] for w in dict_db.list_custom_dictionary_words() if w["word"] == "InsightIDR")
    dict_db.delete_custom_dictionary_word(wid)
    check(
        "delete_custom_dictionary_word removes just that word",
        [w["word"] for w in dict_db.list_custom_dictionary_words()] == ["AlertForge"],
    )

# --- DB.query_templates CRUD (Query Builder tab: LEQL/KQL) ---
with tempfile.TemporaryDirectory() as d:
    qt_db_path = os.path.join(d, "query_templates_test.db")
    qt_db = DB(qt_db_path)

    check(
        "query_templates seeds SEED_QUERY_TEMPLATES on first open",
        len(qt_db.list_query_templates()) == len(SEED_QUERY_TEMPLATES),
    )
    check(
        "SEED_QUERY_TEMPLATES has 14 starter templates",
        len(SEED_QUERY_TEMPLATES) == 14,
    )
    check(
        "SEED_QUERY_TEMPLATES includes the analyst's own Ingress Authentication LEQL example",
        any(
            syntax == "leql" and profile_id == "rapid7_o365_signin" and "where(account=" in body
            for syntax, profile_id, label, body in SEED_QUERY_TEMPLATES
        ),
    )

    leql_rows = qt_db.list_query_templates(syntax="leql")
    check(
        "list_query_templates(syntax='leql') returns only leql rows",
        len(leql_rows) > 0 and all(r["syntax"] == "leql" for r in leql_rows),
    )
    kql_rows = qt_db.list_query_templates(syntax="kql")
    check(
        "list_query_templates(syntax='kql') returns only kql rows",
        len(kql_rows) > 0 and all(r["syntax"] == "kql" for r in kql_rows),
    )
    check(
        "leql + kql rows account for every seeded template",
        len(leql_rows) + len(kql_rows) == len(SEED_QUERY_TEMPLATES),
    )

    scoped_rows = qt_db.list_query_templates(syntax="leql", profile_id="rapid7_o365_signin")
    check(
        "list_query_templates scoped to a profile includes that profile's own templates",
        any(r["profile_id"] == "rapid7_o365_signin" for r in scoped_rows),
    )
    check(
        "list_query_templates scoped to a profile also includes generic (profile_id='') templates",
        any(r["profile_id"] == "" for r in scoped_rows),
    )
    check(
        "list_query_templates scoped to a profile excludes other profiles' templates",
        not any(r["profile_id"] not in ("rapid7_o365_signin", "") for r in scoped_rows),
    )
    check(
        "list_query_templates(profile_id=None) (the default) does not filter by profile at all",
        len(qt_db.list_query_templates(syntax="leql")) == len(leql_rows),
    )

    new_id = qt_db.add_query_template("leql", "rapid7_endpoint_process", "Pivot by Parent Process", "where(parent_process=#parent_process)")
    added = qt_db.get_query_template(new_id)
    check(
        "add_query_template + get_query_template round-trip the new row",
        added is not None
        and added["syntax"] == "leql"
        and added["profile_id"] == "rapid7_endpoint_process"
        and added["label"] == "Pivot by Parent Process"
        and added["body"] == "where(parent_process=#parent_process)",
    )

    qt_db.update_query_template(new_id, "leql", "rapid7_endpoint_process", "Pivot by Parent Process (updated)", "where(parent_process=#parent_process AND result=#result)")
    updated = qt_db.get_query_template(new_id)
    check(
        "update_query_template changes label/body in place (same id)",
        updated["id"] == new_id
        and updated["label"] == "Pivot by Parent Process (updated)"
        and updated["body"] == "where(parent_process=#parent_process AND result=#result)",
    )

    qt_db.delete_query_template(new_id)
    check("delete_query_template removes the row", qt_db.get_query_template(new_id) is None)

    exported = qt_db.export_query_templates()
    check(
        "export_query_templates returns syntax/profile_id/label/body dicts with no id/timestamps",
        len(exported) == len(SEED_QUERY_TEMPLATES)
        and all(set(e.keys()) == {"syntax", "profile_id", "label", "body"} for e in exported),
    )
    some_ids = [r["id"] for r in qt_db.list_query_templates()[:2]]
    exported_subset = qt_db.export_query_templates(some_ids)
    check("export_query_templates(ids=...) exports just the requested rows", len(exported_subset) == 2)

    imported, skipped = qt_db.import_query_templates(exported)
    check(
        "import_query_templates skips every row that already matches by (syntax, label)",
        imported == 0 and len(skipped) == len(SEED_QUERY_TEMPLATES),
    )

    brand_new = [{"syntax": "kql", "profile_id": "", "label": "Pivot by Custom Field", "body": 'search "#user"'}]
    imported2, skipped2 = qt_db.import_query_templates(brand_new)
    check(
        "import_query_templates imports a genuinely new (syntax, label) combination",
        imported2 == 1 and skipped2 == [],
    )
    check(
        "the newly imported query template is now present in the DB",
        any(r["label"] == "Pivot by Custom Field" and r["syntax"] == "kql" for r in qt_db.list_query_templates()),
    )

    overwrite_target = next(r for r in qt_db.list_query_templates() if r["label"] == "Pivot by Custom Field")
    imported3, skipped3 = qt_db.import_query_templates(
        [{"syntax": "kql", "profile_id": "", "label": "Pivot by Custom Field", "body": 'search "#user" and #host'}],
        overwrite=True,
    )
    reloaded = qt_db.get_query_template(overwrite_target["id"])
    check(
        "import_query_templates(overwrite=True) replaces the existing row's body in place",
        imported3 == 1 and skipped3 == [] and reloaded["body"] == 'search "#user" and #host',
    )

    # fill_template is reused as-is for "Insert Filled Query" - confirm it
    # resolves both {field} and #tag placeholders inside an LEQL/KQL body
    # exactly the same way it does for the existing Templates feature.
    leql_body = next(b for s, p, l, b in SEED_QUERY_TEMPLATES if l == "Pivot by Account (Ingress Authentication)")
    filled_leql = fill_template(leql_body, {"account": "bob@contoso.com", "result": "SUCCESS"})
    check(
        "fill_template resolves #tag placeholders inside a seeded LEQL query body",
        filled_leql == "where(account=bob@contoso.com AND result=SUCCESS)",
    )
    kql_body = next(b for s, p, l, b in SEED_QUERY_TEMPLATES if l == "Pivot by User (SigninLogs)")
    filled_kql = fill_template(kql_body, {"user": "jdoe@contoso.com"})
    check(
        "fill_template resolves #tag placeholders inside a seeded KQL query body",
        'UserPrincipalName == "jdoe@contoso.com"' in filled_kql,
    )

print("\nALL TESTS PASSED")
