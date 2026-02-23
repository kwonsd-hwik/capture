# ChromeTracker (macOS, Chrome-only)

A native macOS utility that tracks the currently active Chrome tab and records time spent per site (domain).

## Build

```bash
cd /Users/kstintelligence/Documents/capture
swift build -c release
```

```bash
make app          # Creates .build/chrome-tracker-app/ChromeTracker.app
make dmg          # Creates dist/ChromeTracker-YYYY-MM-DD.dmg (app + Applications link)
make pkg          # Creates dist/ChromeTracker-YYYY-MM-DD.pkg (installer package)
make install-pkg  # Installs the pkg into /Applications
```

`dmg` is a distribution image, not an installer folder.  
Drag `ChromeTracker.app` from the image into the `Applications` folder to install it.

## Runtime modes

### 1) Menu bar mode (default)

```bash
./.build/release/ChromeTracker
```

- Shows a status icon and today's total in the menu bar.
- Menu options:
  - Export JSON/CSV
  - Manage blocked sites
  - Quit
- Tracking stops when you choose `Quit`.

Site filter:
- Enter a list of domains in `Blocked Sites` from the menu; those sites are immediately blocked when active and also blocked at the system level via `/etc/hosts`.
- Input accepts domain/host entries separated by newlines or commas.
- You will be prompted for admin password once at startup to apply system-level blocking.

### 2) Export JSON/CSV

```bash
./.build/release/ChromeTracker --export-json
./.build/release/ChromeTracker --export-csv
```

- Default output path: `~/Downloads/ChromeTracker-YYYY-MM-DD.json` or `.csv`
- Custom path:

```bash
./.build/release/ChromeTracker --export-json ~/Desktop/visit.json
./.build/release/ChromeTracker --export-csv ~/Desktop/visit.csv
```

## Behavior rules

- Chrome only is supported (`com.google.Chrome`).
- Sessions end when Chrome is not the foreground application.
- Site transitions are determined by domain.
- Visits under 3 seconds are not recorded.
- AppleScript permission (browser control) may be required on first run.

## Storage location

- Default DB: `~/Library/Application Support/ChromeTracker/visits.sqlite`
- Falls back to a temporary folder if this path is not writable.

## Available commands

```bash
./.build/release/ChromeTracker --help
```
