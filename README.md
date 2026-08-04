# AlertForge

A lightweight desktop note-taking tool for SOC analysts. Paste raw logs in,
write your analysis, auto-fill an escalation template or false-positive
response from the parsed log fields, and copy the finished write-up into
your ticketing system.

## Features

- **Incident Workspace** — paste raw JSON logs, parse them to auto-extract
  key fields, write free-form analysis, and assemble a final ticket
  write-up you can copy to clipboard. No manual ticket ID / title /
  analyst fields — that context comes from your ticketing system, so the
  workspace just tracks the log + analysis + output.
- **Log parser** — built around **Rapid7 InsightIDR** exports (O365
  authentication logs, O365 inbox rule logs, and Insight Agent endpoint
  process logs) and **Microsoft Sentinel / Defender for Endpoint** logs
  pulled from KQL queries or Sentinel alerts (sign-in activity, excessive
  failed logins, USB file copies, Exchange/inbox-rule OfficeActivity
  events, device network connections, and device process creation), plus
  raw Windows Security/Sysmon process creation events. The O365
  authentication profile also recognizes and parses Rapid7's Azure AD /
  Entra ID sign-in logs, since they share the same outer envelope and are
  handled identically from a SOC perspective — no separate profile
  needed. Falls back to generic key-name matching for anything
  unrecognized.
- **Templates** — two categories, **Escalation** and **False Positive**.
  6 starter templates (one of each for auth, inbox rule, and process
  alerts), fully editable, with placeholders that auto-fill from whatever
  was just parsed.
- **Query Builder tab** — build a **Rapid7 LEQL** or **Microsoft Sentinel
  KQL** pivot query prefilled from a parsed log, the same way Templates
  prefills a ticket write-up. Paste a log and click **Parse Logs** (it
  reuses the exact same field-mapping/profile-detection logic as Incident
  Workspace, including the manual profile override dropdown), pick **LEQL**
  or **KQL** (parsing a log auto-picks whichever syntax matches it, if it
  only has queries in one), and choose a query from the dropdown — it
  lists every query for that syntax across every log source, not just the
  one just parsed, each prefixed with its log source (or `[Generic]` for
  an any-profile query), so an analyst can deliberately pivot into a
  related query for the same investigation — and click
  **Insert Filled Query** to drop it into the output box with `{field}`/
  `#field` placeholders already resolved. 14 starter queries ship out of
  the box (pivot-by-user, pivot-by-host/IP, and pivot-by-hash/process for
  the Rapid7 Ingress Authentication and Endpoint Activity profiles and
  several Sentinel tables, plus one generic full-text search per syntax).
  The **Manage Query Templates** panel on the right works exactly like the
  Templates tab: **New / Delete / Export... / Import...**, with each query
  scoped to a specific profile or left generic (any-profile). LEQL query
  bodies are fully editable/addable by the analyst — AlertForge doesn't
  guess at Rapid7 query syntax beyond the starter set.
- **Two placeholder styles**: `{field}` (shows `[field]` if missing — use
  for things that must be filled in) and `#field` inline tags (e.g. "seen
  from #source_ip" — left untouched if the field isn't available, so plain
  text with `#` in it, like ticket numbers, is never corrupted). A
  **Resolve #Tags in Output** button lets you type tags directly into your
  notes/output and resolve them against the currently parsed log at any
  time, not just when inserting a template. A **Remove Unresolved Tags**
  button next to it deletes any placeholder that's still unresolved (e.g. a
  leftover `#analysis` tag from a template that didn't end up needing it)
  straight out of the output text, instead of hunting it down by hand.
- **Unresolved tags are highlighted** — any `#field`, `{field}`, or
  `[field]` still sitting unresolved in the ticket output box, or typed
  directly into the Analysis box, is shown in bold on a yellow highlight,
  live as you type or paste, so it's obvious at a glance what still needs
  attention before the write-up goes out. Only recognized field names are
  flagged, so ticket numbers (`#1234`) and unrelated bracketed text
  (`[redacted]`) are never mistaken for a broken placeholder. The
  highlight clears itself the moment a tag is resolved (via **Resolve
  #Tags in Output**, inserting a template, or just typing over it).
- **Incidents** — every incident (logs, analysis, output, extracted
  fields) can be saved and reloaded later, searchable across its content.
  Titles are auto-generated from the parsed log (event type + host/user),
  but can be overridden any time with **Rename Selected** (a ticket
  number, short description, etc.) — once renamed, later saves keep your
  title instead of regenerating it. Each incident also tracks a **status**
  (Open / Escalated / Closed / False Positive, defaulting to Open) —
  select one or more rows, pick a status, and click **Apply Status** to
  triage them; a Status filter next to Search narrows the list to just
  one status at a time.
- **Notes tab** — a quick-reference spot for KB articles, saved queries,
  or anything else worth keeping handy, separate from Incidents (which
  track actual case work). Searchable by title/body — opening a note that
  matched on body text (or re-running the search while one's already
  open) highlights every occurrence of the search term right in the note
  and jumps the view to the first hit, so finding where a Windows event
  code or similar is mentioned doesn't mean re-reading the whole note.
  Save and Copy buttons let you pull a note straight to clipboard, plus
  Export/Import for
  sharing notes with a teammate the same way templates and field mappings
  can be shared. Notes are the only place in the app with rich text: a
  **B / I / U / S / Heading / Clear Formatting** toolbar above the note
  box lets you select text and format it directly (bold, italic,
  underline, strikethrough, or a larger bold heading line) — select
  nothing and the buttons do nothing, so it's safe to click around.
  Copying a note to clipboard always copies plain text, so formatting
  doesn't leak into whatever you paste it into. Notes saved before this
  feature existed still open fine, just unformatted.
- **Sanitize Logs tab** — redact sensitive values from pasted logs before
  sharing them outside the team (a vendor, a public ticket, a write-up).
  Detects email addresses, IPv4/IPv6 addresses, domain names, hostnames
  (recognized computer-name conventions like `WORKSTATION-07`/`srv-dc01`
  only — not "any hyphenated word", so it never swallows ticket/incident
  references like `INC-1234`, and requires a hyphen or digit suffix so it
  doesn't mistake ordinary words like "Windows" or the PowerShell
  `Write-Host` cmdlet for a hostname), Windows SIDs, MAC addresses, and
  **account/username fields**, each toggleable independently. Domain
  detection is validated against a list of recognized TLDs, so a dotted
  code identifier or file name (like `$rc.Cells.Item` or `powershell.exe`)
  is never mistaken for a domain name just because it has dots in it.
  Because regex alone can never reliably recognize a bare username
  (`jdoe`) or an unconventionally-named host (`SFO-FIN-01`), the sanitizer
  also parses the pasted text as JSON and pulls values straight out of a
  fixed list of known field paths: `source_user`, `destination_user`,
  `source_account`, `destination_account`, `account`, `user`,
  `process.username`, `parent_process.username`, `destination_asset`,
  `source_asset`, `hostname`, `process.account_domain`,
  `parent_process.account_domain`, `process.exe_file.owner`, and
  `parent_process.exe_file.owner` (case-insensitive key matching).
  Whichever way a sensitive value is first found — a regex pattern or one
  of these JSON keys — every other occurrence of that exact value
  anywhere else in the pasted text (inside another JSON field, or out in
  free-form log text below/above the JSON) is swept up too, so a username
  or host mentioned once in structured JSON and again in a plain-text log
  line still gets fully redacted. **Every category redacts to the exact
  same plain word `REDACTED`** — not a numbered placeholder like `IP_1` /
  `HOST_1` — so nothing about a real value, or even which category caught
  it, survives into the output text; the summary below the output still
  reports how many *distinct* values each category caught, even though
  they all render identically. Everything that was actually changed is
  bold+green-highlighted in the sanitized output box, so it's obvious at
  a glance what got redacted. JSON key names are protected even when they
  collide with a detected pattern (e.g. `"HostName": "WORKSTATION-07"`
  redacts the value but leaves the `"HostName"` key alone), since the
  tool works on raw pasted text rather than parsed JSON. A **Custom
  Find/Replace** list below the main sanitizer is saved and reused across
  sessions — type a keyword and its replacement and press Enter (or click
  **Add / Save**) to add a company name, an internal project codename, or
  anything else no generic pattern would catch; it's applied
  (case-insensitive, exact replacement text you choose) before the
  automatic detectors run, every time you sanitize. Select a row and press
  **Delete**/**Backspace** (or click **Delete Selected**), or just type a
  keyword's exact name into the Keyword field and click **Delete
  Selected** without first selecting its row, to remove a saved custom
  replacement. This is heuristic/best-effort, same spirit as the rest of
  the app's field-mapping fallbacks — review the sanitized output before
  sharing it.
- **Text Tools tab** — a scratch pad for general-purpose log/text munging
  that's independent of the structured log parser above. Paste any text,
  check one or more operations, and click **Apply** to run them and show
  the result: **Base64 Decode** (strips anything outside the base64
  alphabet before decoding and drops NUL bytes — handy for a Base64
  blob with stray labels/quotes/newlines around it, though a label made
  of letters/digits glued directly onto the payload can't be told apart
  from real data and will corrupt the decode), **From Hex Code** (strips
  `0x` prefixes and any non-hex characters first, tolerating spaces/
  colons/newlines as separators), **URL Decode** (percent-escapes and
  `+` as a space), **Extract Email Addresses**, **Extract IP Addresses**
  (IPv4 and IPv6), **Extract File Names/Paths** (matches a bare filename
  like `report.pdf` or a full Windows/UNC/relative path in front of it,
  against a built-in list of common document, executable, archive,
  script, media, and log extensions — directory segments may contain
  spaces the way real Windows paths do, but the filename itself may not,
  so a match can't run past the end of a sentence), **Remove Extra
  Whitespace** (collapses runs of spaces/tabs and blank lines down to one
  line break between entries), **Sort Alphabetically**,
  **Remove Duplicates** (case-insensitive), and
  **Defang URLs/IPs** (`http`/`https` → `hxxp`/`hxxps`, `://` → `[://]`,
  every `.` → `[.]`, preserving capitalization style). Multiple
  operations always run in the same fixed order regardless of the order
  you checked them in — decode, then extract, then clean up, then defang
  last — so a given set of checked boxes always produces the same
  result; checking any combination of email, IP, and file path
  extraction runs them all against the same pasted text and combines the
  results (rather than feeding one's output into the other, which would
  find nothing). A **Copy Output to
  Clipboard** button and a **Clear** button sit above the result box.
- **Field Mappings tab** — a friendly list/add UI, not raw JSON. Add a
  field to an existing profile, or create a brand-new profile for a log
  or alert type that isn't recognized yet, just by naming it and typing
  the JSON key(s) that identify and populate it. Select a field and click
  **Move Field Up** / **Move Field Down** to reorder it - a profile's
  field order is what determines the row order in the Incident
  Workspace's Extracted Fields table after parsing, so this is how you
  put `timestamp` at the top or group related fields together instead of
  a newly-added field being stuck at the bottom. A **Test a Sample Log**
  toggle lets you paste a log and preview which profile matches and what
  fields would be extracted, right there in the tab, without switching to
  the Incident Workspace. A raw-JSON editor is still available behind an
  "Advanced" toggle for power edits.
- **Share templates, notes, and field mappings between analysts** —
  Export/Import buttons on the Templates, Notes, and Field Mappings tabs
  write/read small JSON files, so a teammate's custom escalation
  template, KB note, or profile for a new alert type can be handed off
  with a file instead of retyping it.
- **Backup/Restore Database** — under the File menu, **Backup Database...**
  copies `alertforge.db` (all templates, incidents, and notes) to a
  location you choose; **Restore Database...** replaces the live database
  with a previously backed-up file after a confirmation prompt.
- **Dark mode** — on by default. A Dark Mode toggle in the top-right
  corner switches between the dark blue theme and a light theme; your
  choice isn't tied to Windows' system theme.
- **Adjustable font size** — **A-** / **A+** buttons next to the Dark
  Mode toggle (or **Ctrl+-** / **Ctrl+=** / **Ctrl+0** to reset, also in
  the new **View** menu) scale the text across every tab, table, and
  text box in the app.
- **Resize-friendly toolbars** — button rows across every tab wrap onto
  additional lines instead of disappearing off-screen when the window
  (or a split pane inside it) gets narrow, e.g. side-by-side with a
  browser window. The app is comfortable running in a real split-screen
  layout at well under half a monitor's width (down to a 640×480 minimum
  window size).
- **Right-click edit menu everywhere** — every text box and single-line
  field in the app supports a right-click menu with Cut/Copy/Paste/Select
  All, plus Undo/Redo on any multi-line box. Right-clicking inside an
  existing selection preserves it (so Copy/Cut still act on what you
  selected); right-clicking elsewhere moves the cursor there first, like
  any normal text editor.
- **Live spell-check** on the Analysis box. Misspelled words get a
  colored underline as you type (a short pause after typing, not on every
  keystroke); right-click one for spelling suggestions or **Add to
  Dictionary** to permanently allowlist a word (a product name, an
  internal codename, etc.) from then on. Scoped deliberately to just
  Analysis — raw pasted logs, JSON paths, and the Sanitize Logs boxes are
  full of legitimate non-dictionary tokens that would just be noise, and
  Ticket Output/Notes/the Template editor simply don't need it. A bundled
  list of common SOC/IT terms (`malware`, `hostname`, `exfiltration`,
  `MFA`, etc.) is pre-allowlisted so it doesn't fight you over everyday
  vocabulary. Spell-check is an optional feature: if the `pyspellchecker`
  package isn't installed, the rest of the app works exactly the same,
  just without the underlines.

## Running it

Requires Python 3.8+ (tkinter and sqlite3 ship with standard Python on
Windows — no extra install needed for those).

```
python app.py
```

Install `pip install -r requirements.txt` first if you want live spell-
check (the `pyspellchecker` package) — it's optional, and everything else
in the app works fine without it.

On first run it creates `alertforge.db` (your data) next to `app.py` and
seeds 6 starter templates you can edit or delete. If you'd previously run
an older version of this app, any saved incidents are migrated
automatically on first launch — nothing is lost. If you're upgrading from
when this app was called SOC Notes, its `soc_notes.db` is copied over to
`alertforge.db` automatically the first time you launch the renamed app,
so none of your existing templates/incidents/notes are orphaned by the
rename.

## Files

| File | Purpose |
|---|---|
| `app.py` | Tkinter UI — the app entry point |
| `parser_core.py` | Log parsing, field extraction, and the SQLite data layer (no UI dependency) |
| `field_mappings.json` | Editable config: which JSON keys map to which field, per log source |
| `test_parser.py` | Regression tests for the parser and DB layer, using your real sample logs |
| `alertforge.db` | Created automatically — your templates and saved incidents |

## Using the log parser

Paste one of the following into the "raw logs" box and click **Parse Logs**:

- A single JSON object
- A JSON array of objects
- Newline-delimited JSON (one object per line)

**Partial pastes are fine.** Auth and process logs tend to have their most
useful fields near the top, so it's common to only paste the first chunk
of a log rather than the whole thing. The parser handles this two ways:
if the pasted text is missing its outer `{ }` braces (a fragment copied
out of the middle of a larger log), it's repaired automatically; and a
log profile is detected off a *majority* of its identifying fields rather
than requiring every single one, so a partial paste still gets recognized
correctly. Any field that wasn't included in what you pasted just shows
blank rather than causing an error, and a warning tells you when either
of these kicked in so you know to double check the results.

**Unescaped backslashes (raw Windows paths) are fixed automatically.** A
very common way a SIEM export otherwise "looks complete" (matched braces
and everything) but still fails to parse is a raw Windows file path or
command line pasted straight into a JSON string value —
`"service_cmdline": "C:\WINDOWS\system32\svchost.exe -k Something"` — where
the backslashes were never escaped. In real JSON, a backslash is only
legal right before `"` `\` `/` `b` `f` `n` `r` `t` or a `\uXXXX` unicode
escape, so a Windows path separator like `\W` or `\s` breaks the whole
document even though it looks fine to the eye. The parser now detects
this pattern and escapes those backslashes automatically before parsing,
preserving the log's full nested structure (so profile detection and
field mapping still work normally, unlike the flatter `wrapped`/`scraped`
fallbacks below). A warning is shown whenever this repair runs, so you
know to double check any path/command-line fields in the result. JSON
that's already valid (including logs that already have properly escaped
backslashes, e.g. `\\`) is never touched by this repair.

The parser first checks whether the log matches one of the known profiles
in `field_mappings.json` (by looking for a set of telltale key names). If
it matches, fields are pulled using that profile's exact mapping and the
Extracted Fields table shows exactly that profile's field set (different
log types surface different fields — an auth log shows GeoIP/device
fields, a process log shows hashes/signing status, etc.). If nothing
matches, it falls back to generic key-name matching and shows a warning
so you know to double check the values.

**Manual profile override.** Next to Parse Logs is a "Profile:" dropdown,
defaulting to "Auto-detect (recommended)". Auto-detect is right the vast
majority of the time, but two profiles can occasionally share enough
generic field names that the wrong one wins - if that happens (or you
just want to force a specific profile's field mapping onto a log
auto-detect doesn't recognize yet), pick it by name from the dropdown and
click Parse Logs again; that profile's fields are used no matter what
auto-detect would have picked, and the status line notes that the
override is active. The dropdown always lists whatever profiles currently
exist in `field_mappings.json` and resets to Auto-detect on New Incident,
so a forced choice from a previous log never silently carries over onto
an unrelated one.

**VirusTotal quick lookups.** Any row in the Extracted Fields table whose
value is - in its entirety - a plain IPv4/IPv6 address or an MD5/SHA1/
SHA256 hash, or whose value *contains* exactly one `http(s)://` URL
somewhere in it, gets a small underlined "VT" link, in your theme's
accent color, in a third column; click it to open a VirusTotal lookup for
that exact value/URL in your default browser, or hover over it first to
preview the exact URL. This is value-based, not tied to specific field
names, so it works for any IP/hash/URL field across every profile
(including custom ones you add yourself) without needing to be
configured per profile. A field holding several values joined together
(e.g. `host` aggregated via `join_list` into `"srv-dc01.contoso.com;
srv-dc02.contoso.com"`, or two URLs in the same field) deliberately does
*not* get a link, since a single click linking to only the first of
several values would be misleading. The VT URL link is built entirely
locally (VirusTotal's own base64-encoded URL identifier scheme) - no
lookup or API call happens until you actually click it.

Every profile also fills a common baseline (`user`, `domain`, `host`,
`src_ip`, `dst_ip`, `process`, `cmdline`, `parent_process`,
`parent_cmdline`, `timestamp`, `event_id`, `event_type`, `result`,
`location`, `device_os`) where applicable, so generic escalation templates
using `{host}`/`{process}`/etc. work no matter which log type you parsed.

### Built-in profiles

**Verified against real sample logs:**
- `rapid7_o365_signin` — Rapid7 InsightIDR O365 authentication/sign-in log.
  Also detects and parses this SIEM's Azure AD / Entra ID sign-in logs,
  which arrive in the same outer envelope with a different `source_json`
  shape (`source_json.properties.*` instead of O365's
  `DeviceProperties`/`Operation`) — shared fields (host, device OS,
  compliance/managed/trust status, browser) resolve from whichever shape
  the log actually has, plus Azure-specific bonus fields
  (`azure_app_display_name`, `azure_user_agent`, `azure_device_id`,
  `azure_auth_method`, `azure_auth_step_result_detail`,
  `azure_auth_requirement`).
- `Active Directory` (label "Entra") — covers
  both Windows Active Directory auth/asset events (`source_asset`,
  `destination_asset`, `source_account`, `destination_account`, e.g. a
  4648 explicit-credential logon) and Rapid7 InsightIDR O365 inbox rule
  change logs (`action`, `source_user`, `New-InboxRule`/`Set-InboxRule` —
  formerly the separate `rapid7_o365_inbox_rule` profile, merged in since
  both log shapes share the same generic Rapid7-normalized field names
  and kept colliding under two profiles). Detection uses 6 keys
  (`source_asset`, `action`, `source_user`, `destination_asset`,
  `source_account`, `destination_account`); since no single log carries
  all 6 (AD events and O365 events are mutually exclusive subsets), this
  profile is always matched by the partial/majority-match pass rather
  than an exact match — an AD-only log matches 4 of 6, an O365-only log
  matches 3 of 6 (right at the `ceil(6/2)=3` threshold). That's expected
  and by design, not a parsing error — just be aware a partial log paste
  has less margin before it drops below threshold and fails to detect.
- `rapid7_endpoint_process` — Rapid7 Insight Agent process telemetry
  (process + parent details, hashes, signing status/signer, reputation).
- `sentinel_signin` — Microsoft Sentinel `SigninLogs`. Detected off
  `UserPrincipalName`/`AppDisplayName`/`IPAddress` (a real sample doesn't
  carry `ResultType`, so that's no longer required to match). Bonus
  fields include `user_agent`, `mfa_detail`, device compliance/managed
  status, browser, and full location detail (city/state/country/geo
  coordinates).
- `sentinel_excessive_failed_logins` — Sentinel "Excessive Failed Logins"
  Asset Authentication alert (EventID 4625). `host` and `src_ip` aggregate
  the alert's `Computer`/`IpAddressList` arrays into a single
  `"a; b; c"`-style string via the new `join_list` transform, since these
  alerts can span more than one host/source IP.
- `files_copied_to_usb` (label "Files Copied to USB") — Sentinel/Defender
  `DeviceEvents` USB file-copy alert. `user`/`domain` prefer the UPN
  (falling back to the plain account name/domain if UPN isn't present).
  `file_names` and `folder_paths` use the `all:` field-spec prefix to
  aggregate across every JSON record you paste, not just the first — this
  is the profile to use when pasting one JSON object per file copied.
- `sentinel_office_activity` — Sentinel `OfficeActivity` (Exchange Admin
  operations, most commonly inbox rule creation). `all_parameters` uses
  the new `flatten_name_value_json_string` transform, since Sentinel's
  `Parameters` field is a JSON-encoded *string* rather than a real nested
  array (the underlying O365 Management Activity API double-serializes
  it).
- `sentinel_device_network` — Sentinel/Defender `DeviceNetworkEvents`.
  Local/remote IP and port, protocol, initiating process, and TLS/JA3/JA4
  connection details.
- `sentinel_device_process` — Sentinel/Defender `DeviceProcessEvents`.
  Process + parent process details, hashes, signature status, account
  SID/UPN, and logon ID.
- `windows_process_creation` — Windows Security / Sysmon process creation
  (4688 / Sysmon Event ID 1).

## Adding your own field mappings (Field Mappings tab)

This is how you support a brand-new alert or log type without touching
code. The tab shows every existing profile and its mapped fields in a
tree — expand a profile to see its fields and the JSON key/path each one
pulls from.

**To add a field to an existing profile:** pick the profile from the
dropdown, type a field name (this becomes `{field}` / `#field` in
templates) and the JSON key or path to pull it from, optionally pick a
transform, then click **Add / Update Field**.

**To support a whole new alert/log type:** under "Create a New Profile",
give it a name and one or more JSON key names that uniquely identify that
log (used to auto-detect it when you paste a log later). It's created
with the standard baseline fields blank — then use "Add / Update Field"
above to map its real JSON keys. This is the workflow for building a
custom template around a log type AlertForge doesn't already know: create
the profile, map the fields you care about, then write a template that
references them.

Path syntax supported in the "JSON key / path" box:
- `a.b.c` — plain nested key traversal
- `a.b[0].c` — numeric index into a list
- `a.b[Name=Foo].Value` — find a `{"Name": "Foo", "Value": ...}`-style
  entry in a list (the pattern O365/Rapid7 audit logs use for
  `ExtendedProperties`, `Parameters`, `DeviceProperties`, etc.)
- `literal:Some Text` — a fixed value instead of a path
- `pathA::transformA||pathB::transformB` — try each `||`-separated
  candidate in order, keeping the first one that resolves to a non-empty
  value (used when the same field can come from two different log
  shapes under one profile)
- `all:a.b` — aggregate that path's value across *every* JSON record you
  paste (not just the first), joined as `"a; b; c"`. Use this for a field
  that's one-value-per-record when an analyst commonly pastes several
  related records at once, e.g. one JSON object per file copied to USB.

Transforms available: `domain_from_email`, `azure_result`,
`windows_auth_event_label`, `windows_auth_result`,
`flatten_name_value_pairs` (turns a real Name/Value array into one
`"Name1=Value1; Name2=Value2"` string), `flatten_name_value_json_string`
(same, but for a field that holds a *JSON-encoded string* of that array
instead of a real nested array — e.g. Sentinel `OfficeActivity`'s
`Parameters` field), `join_list` (joins a list value into
`"a; b; c"`, passing a scalar value through unchanged — e.g. a Sentinel
watchlist alert's `Computer`/`IpAddressList` fields, which are arrays
when the alert spans more than one host/IP) — see `TRANSFORMS` in
`parser_core.py` to add more.

An "Advanced: Raw JSON" toggle at the bottom of the tab still exposes the
full `field_mappings.json` as text for anything the friendly UI doesn't
cover.

### Sharing field mapping profiles

Select one or more profiles in the tree (or select none to export
everything) and click **Export Profile(s)...** to write them to a JSON
file — a natural unit to hand off is a single profile, since it fully
describes one log/alert type. A teammate opens the Field Mappings tab and
clicks **Import Profile(s)...**, picks that file, and the profile(s) are
added. If a profile with the same id already exists, you're asked whether
to overwrite it or leave your own version alone.

## Templates

Two categories: **Escalation** and **False Positive**. In the body text:

- `{field}` — explicit placeholder; shows `[field]` if the value is
  missing, so you notice and fill it in by hand.
- `#field` — inline tag, e.g. `"from #source_ip"`; if `field` isn't
  available it's left as literal text, so plain `#` usage (ticket numbers,
  etc.) is never corrupted.

Use any common baseline field or any source-specific field shown in the
Extracted Fields table for the log type you're working with (e.g.
`#geoip_city`, `#device_compliant`, `#rule_name`, `#forward_to`,
`#process_sha256`, `#process_signing_status`) — or any custom field you
added yourself in the Field Mappings tab. `#analysis` / `{analysis}` is
always available too — it pulls in whatever's currently typed in the
Analysis box, so a template can fold your write-up straight in when you
click **Insert Filled Template**, instead of you copy/pasting it in
separately. A **Copy Analysis** button next to the Analysis box also lets
you copy just that text to the clipboard on its own.

You can also type tags directly into your analysis or output text (not
just inside a saved template) and click **Resolve #Tags in Output** to
fill them in against whatever log is currently parsed.

### Sharing templates

Select one or more templates in the list (or select none to export
everything currently shown) and click **Export...** to write them to a
JSON file. A teammate opens the Templates tab and clicks **Import...**,
picks that file, and the templates are added — matched by name, so a
name that already exists on their machine is skipped unless they choose
to overwrite it with the imported version.

## Building a standalone .exe

```
pip install -r requirements.txt
build.bat
```

This runs PyInstaller in `--onefile --windowed` mode and copies
`field_mappings.json` next to the resulting `dist\AlertForge.exe`. Keep
`field_mappings.json` in the same folder as the exe — the app reads/writes
it (and creates `alertforge.db`) next to wherever the exe is running from,
so both files need to travel with the executable if you move it.

Note: this only produces a Windows exe when built on Windows (PyInstaller
does not cross-compile).

## Testing

`test_parser.py` is a standalone regression test for the parsing logic and
database layer (no GUI needed) — it includes your real Rapid7 and
Microsoft Sentinel/Defender sample logs, the unescaped-backslash repair
(a real Windows Security Event Log with an unescaped `service_cmdline`
path, checked for nested-structure preservation and that already-valid
JSON with real escapes is left untouched), the bracket-path lookups, the
`flatten_name_value_pairs`/`flatten_name_value_json_string`/`join_list`
transforms, the `all:` cross-record aggregation prefix, both placeholder
styles, the `find_unresolved_tag_spans` logic behind the ticket output
box's unresolved-tag highlighting, the `remove_unresolved_tags` logic
behind the Remove Unresolved Tags button, the `sanitize_text` logic behind the
Sanitize Logs tab (each category redacting to the same `REDACTED`
literal, distinct-value counting, the JSON-key protection, the JSON-key-
based account/asset detection and its cross-log redaction propagation,
and the custom keyword list), the `text_tool_*` functions and
`apply_text_tools` pipeline ordering behind the Text Tools tab, the
`find_misspelled_word_spans`/`spelling_suggestions` logic and bundled
tech-terms allowlist behind spell-check (skipped automatically if
`pyspellchecker` isn't installed in the environment running the tests),
the `custom_dictionary` table CRUD behind Add to Dictionary, the
`query_templates` table seeding/CRUD/export/import behind the Query
Builder tab (including that `fill_template` resolves `{field}`/`#field`
placeholders inside a seeded LEQL/KQL query body the same way it does for
a regular template), and the incident/template/note/profile/sanitize-
keyword CRUD and export/import.
Run it after editing `field_mappings.json` or `parser_core.py`:

```
python test_parser.py
```
