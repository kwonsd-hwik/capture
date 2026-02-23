import AppKit
import Foundation
import SQLite3

private let chromeBundleID = "com.google.Chrome"
private let minimumVisitSeconds = 3

struct ChromeTab {
    let url: String
    let title: String
    let domain: String
}

struct ActiveSession {
    let domain: String
    var url: String
    let startedAt: Date
    var title: String
}

struct FinalizedVisit {
    let domain: String
    let url: String
    let title: String
    let startedAt: Date
    let endedAt: Date

    var seconds: Int {
        Int(max(0, endedAt.timeIntervalSince(startedAt)))
    }
}

final class WebsiteFilterManager {
    private let blocklistKey = "ChromeTracker.blockedDomains"
    private let defaults = UserDefaults.standard

    var blockedDomains: [String] {
        get {
            Self.normalizeDomains(storedList(for: blocklistKey))
        }
        set {
            defaults.set(newValue, forKey: blocklistKey)
        }
    }

    func shouldBlock(domain: String) -> Bool {
        let normalized = Self.normalizeDomain(domain)
        guard !normalized.isEmpty else { return false }
        guard !blockedDomains.isEmpty else { return false }
        return blockedDomains.contains(where: { Self.matches(domain: normalized, pattern: $0) })
    }

    func setBlockedDomains(_ domains: [String]) {
        blockedDomains = Self.normalizeDomains(domains)
    }

    static func normalizeDomains(_ domains: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for domain in domains {
            let normalized = normalizeDomain(domain)
            if normalized.isEmpty || normalized == "*" { continue }
            if !seen.contains(normalized) {
                seen.insert(normalized)
                result.append(normalized)
            }
        }
        return result
    }

    static func normalizeDomain(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }

        var valueWithoutPrefix = trimmed.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if valueWithoutPrefix.hasPrefix("www.") {
            valueWithoutPrefix = String(valueWithoutPrefix.dropFirst(4))
        }

        if let url = URL(string: valueWithoutPrefix), let host = url.host {
            let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            return normalized.hasPrefix("www.") ? String(normalized.dropFirst(4)) : normalized
        }

        if !valueWithoutPrefix.contains("://"), let url = URL(string: "https://\(valueWithoutPrefix)"), let host = url.host {
            let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            return normalized.hasPrefix("www.") ? String(normalized.dropFirst(4)) : normalized
        }

        let plainHost = valueWithoutPrefix.split(separator: "/").first.map(String.init) ?? valueWithoutPrefix
        let hostWithoutPort = plainHost.split(separator: ":").first.map(String.init) ?? plainHost
        if hostWithoutPort.isEmpty {
            return ""
        }

        let normalized = hostWithoutPort.lowercased()
        if normalized == "*" {
            return "*"
        }

        return normalized.hasPrefix("www.") ? String(normalized.dropFirst(4)) : normalized
    }

    static func parseDomainInput(_ input: String) -> [String] {
        let normalizedInput = input.replacingOccurrences(of: ",", with: "\n")
        let components = normalizedInput
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        return normalizeDomains(components)
    }

    static func matches(domain: String, pattern: String) -> Bool {
        let normalizedDomain = normalizeDomain(domain)
        let normalizedPattern = normalizeDomain(pattern)
        guard !normalizedDomain.isEmpty, !normalizedPattern.isEmpty else {
            return false
        }

        if normalizedPattern == "*" {
            return true
        }

        if normalizedPattern.hasPrefix("*.") {
            let suffix = String(normalizedPattern.dropFirst(2))
            return normalizedDomain == suffix || normalizedDomain.hasSuffix(".\(suffix)")
        }

        return normalizedDomain == normalizedPattern
            || normalizedDomain.hasSuffix(".\(normalizedPattern)")
    }

    private func storedList(for key: String) -> [String] {
        defaults.stringArray(forKey: key) ?? []
    }
}

final class SystemHostsBlocker {
    private let markerStart = "# ChromeTracker START"
    private let markerEnd = "# ChromeTracker END"
    private let hostsPath = "/etc/hosts"
    private var cachedSudoPassword: String?

    func authorizeAtLaunch() -> (success: Bool, message: String) {
        return requestAndCachePassword(
            title: "Administrator Authentication",
            message: "Enter your macOS administrator password to apply system-level blocking."
        )
    }

    func applyBlockedDomains(_ domains: [String]) -> (success: Bool, message: String) {
        let hostEntries = buildHostEntries(from: domains)
        let script = buildShellScript(with: hostEntries)
        let result = runPrivilegedScript(script)
        if !result.success {
            return result
        }

        if hostEntries.isEmpty {
            return (true, "System blocking removed")
        }

            return (true, "Applied system-level block for \(hostEntries.count) entries")
    }

    private func buildHostEntries(from domains: [String]) -> [String] {
        var entries = Set<String>()
        for original in WebsiteFilterManager.normalizeDomains(domains) {
            var normalized = original
            if normalized.hasPrefix("*.") {
                normalized = String(normalized.dropFirst(2))
            }
            normalized = WebsiteFilterManager.normalizeDomain(normalized)

            guard isValidHost(normalized) else {
                continue
            }

            entries.insert(normalized)
            if !normalized.hasPrefix("www.") {
                entries.insert("www.\(normalized)")
            }
        }

        return entries.sorted()
    }

    private func isValidHost(_ value: String) -> Bool {
        guard !value.isEmpty else {
            return false
        }

        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
        return value.rangeOfCharacter(from: allowed.inverted) == nil
    }

    private func buildShellScript(with hosts: [String]) -> String {
        var lines: [String] = [
            "#!/bin/bash",
            "set -euo pipefail",
            "HOSTS=\"\(hostsPath)\"",
            "START=\"\(markerStart)\"",
            "END=\"\(markerEnd)\"",
            "TMP=\"$(mktemp)\"",
            "awk -v s=\"$START\" -v e=\"$END\" '",
            "$0==s {skip=1; next}",
            "$0==e {skip=0; next}",
            "!skip {print}",
            "' \"$HOSTS\" > \"$TMP\""
        ]

        if !hosts.isEmpty {
            lines.append("{")
            lines.append("echo \"\"")
            lines.append("echo \"$START\"")
            for host in hosts {
                lines.append("echo \"0.0.0.0 \(host)\"")
            }
            lines.append("echo \"$END\"")
            lines.append("} >> \"$TMP\"")
        }

        lines.append("cat \"$TMP\" > \"$HOSTS\"")
        lines.append("rm -f \"$TMP\"")
        lines.append("/usr/bin/dscacheutil -flushcache || true")
        lines.append("/usr/bin/killall -HUP mDNSResponder || true")
        return lines.joined(separator: "\n")
    }

    private func runPrivilegedScript(_ script: String) -> (success: Bool, message: String) {
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("chrometracker-hosts-\(UUID().uuidString).sh")

        do {
            try script.write(to: tempURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: tempURL.path)
        } catch {
            return (false, "Failed to create temporary script: \(error.localizedDescription)")
        }

        defer {
            try? FileManager.default.removeItem(at: tempURL)
        }

        guard let currentPassword = cachedSudoPassword else {
            return (false, "No administrator authentication. Restart the app and authenticate.")
        }

        let cachedRun = runSudo(arguments: ["/bin/bash", tempURL.path], password: currentPassword)
        if cachedRun.success {
            return (true, "ok")
        }

        let reAuth = requestAndCachePassword(
            title: "Refresh Administrator Authentication",
            message: "Administrator authentication expired or failed. Please re-enter your password."
        )
        guard reAuth.success, let refreshedPassword = cachedSudoPassword else {
            return (false, reAuth.message)
        }

        let retriedRun = runSudo(arguments: ["/bin/bash", tempURL.path], password: refreshedPassword)
        if retriedRun.success {
            return (true, "ok")
        }

        return (false, retriedRun.message)
    }

    private func requestAndCachePassword(title: String, message: String) -> (success: Bool, message: String) {
        var promptMessage = message
        while true {
            guard let password = requestPasswordWithAlert(title: title, message: promptMessage) else {
                return (false, "User canceled administrator authentication.")
            }

            guard !password.isEmpty else {
                promptMessage = "The password is empty. Please enter it again."
                continue
            }

            let verify = runSudo(arguments: ["-v"], password: password)
            if verify.success {
                cachedSudoPassword = password
            return (true, "Initial administrator authentication completed (UI)")
            }

            promptMessage = "Password is incorrect. Please try again."
        }
    }

    private func runSudo(arguments: [String], password: String) -> (success: Bool, message: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = ["-S", "-p", ""] + arguments

        let stdinPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            return (false, "sudo execution failed: \(error.localizedDescription)")
        }

        if let data = (password + "\n").data(using: .utf8) {
            stdinPipe.fileHandleForWriting.write(data)
        }
        try? stdinPipe.fileHandleForWriting.close()

        process.waitUntilExit()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrMessage = String(data: stderrData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        if process.terminationStatus == 0 {
            return (true, "ok")
        }

        if stderrMessage.isEmpty {
            return (false, "sudo failed (status: \(process.terminationStatus))")
        }

        return (false, stderrMessage)
    }

    private func requestPasswordWithAlert(title: String, message: String) -> String? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational

        let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = input
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = input

        let result = alert.runModal()
        if result == .alertFirstButtonReturn {
            return input.stringValue
        }
        return nil
    }
}

final class ChromeURLProvider {
    private let scriptSource = """
        tell application "Google Chrome"
            if not running then return ""
            if (count of windows) = 0 then return ""
            set tabURL to URL of active tab of front window
            set tabTitle to title of active tab of front window
            return tabURL & "\n" & tabTitle
        end tell
        """

    func currentTab() -> ChromeTab? {
        guard let script = NSAppleScript(source: scriptSource) else {
            return nil
        }

        var error: NSDictionary?
        let result = script.executeAndReturnError(&error)
        if error != nil {
            return nil
        }

        guard let value = result.stringValue else {
            return nil
        }

        let parts = value
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { !$0.isEmpty }

        guard let urlString = parts.first, let domain = Self.domain(from: urlString) else {
            return nil
        }

        let title = parts.dropFirst().joined(separator: "\n")
        return ChromeTab(url: urlString, title: title, domain: domain)
    }

    @discardableResult
    func blockActiveTab() -> Bool {
        let script = """
        tell application "Google Chrome"
            if not running then return false
            if (count of windows) = 0 then return false
            set URL of active tab of front window to "about:blank"
            return true
        end tell
        """

        guard let appleScript = NSAppleScript(source: script) else {
            return false
        }

        var error: NSDictionary?
        let result = appleScript.executeAndReturnError(&error)
        return error == nil && result.booleanValue
    }

    private static func domain(from value: String) -> String? {
        let ignorePrefixes = ["about:", "chrome://", "file://", "javascript:"]
        if ignorePrefixes.contains(where: { value.hasPrefix($0) }) {
            return nil
        }

        guard let url = URL(string: value), let host = url.host else {
            return nil
        }

        return host.lowercased().hasPrefix("www.")
            ? String(host.dropFirst(4))
            : host.lowercased()
    }
}

final class VisitStore {
    struct SummaryRow: Codable {
        let domain: String
        let seconds: Int
    }

    struct VisitExport: Codable {
        let domain: String
        let url: String
        let title: String
        let startedAt: String
        let endedAt: String
        let durationSec: Int
    }

    struct ExportPayload: Codable {
        let generatedAt: String
        let date: String
        let totalSeconds: Int
        let summaries: [SummaryRow]
        let visits: [VisitExport]
    }

    private static let databaseFileName = "visits.sqlite"
    private var db: OpaquePointer?

    static func storagePath() -> String {
        let candidates = candidateDirectories()
        for candidate in candidates {
            do {
                try FileManager.default.createDirectory(at: candidate, withIntermediateDirectories: true)
                return candidate.appendingPathComponent(databaseFileName).path
            } catch {
                continue
            }
        }
        let fallback = FileManager.default.temporaryDirectory
            .appendingPathComponent("ChromeTracker", isDirectory: true)
        return fallback.appendingPathComponent(databaseFileName).path
    }

    private static func candidateDirectories() -> [URL] {
        var candidates: [URL] = []
        if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            candidates.append(appSupport.appendingPathComponent("ChromeTracker", isDirectory: true))
        }
        candidates.append(FileManager.default.temporaryDirectory.appendingPathComponent("ChromeTracker", isDirectory: true))
        return candidates
    }

    init?() {
        let dbPath = Self.storagePath()
        let dbURL = URL(fileURLWithPath: dbPath)

        if sqlite3_open(dbURL.path, &db) != SQLITE_OK {
            return nil
        }

        let createSQL = """
        CREATE TABLE IF NOT EXISTS visits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            url TEXT NOT NULL,
            title TEXT,
            app_bundle_id TEXT NOT NULL,
            started_at REAL NOT NULL,
            ended_at REAL NOT NULL,
            duration_sec INTEGER NOT NULL
        );
        """
        _ = execute(createSQL)
    }

    deinit {
        sqlite3_close(db)
    }

    @discardableResult
    private func execute(_ query: String) -> Bool {
        guard let db else { return false }
        return sqlite3_exec(db, query, nil, nil, nil) == SQLITE_OK
    }

    func insert(_ visit: FinalizedVisit) {
        guard let db else { return }

        let sql = """
        INSERT INTO visits(domain, url, title, app_bundle_id, started_at, ended_at, duration_sec)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """

        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, sql, -1, &statement, nil) != SQLITE_OK {
            return
        }

        let domain = visit.domain
        let url = visit.url
        let title = visit.title

        _ = domain.withCString { sqlDomain in
            sqlite3_bind_text(statement, 1, sqlDomain, -1, nil)
        }
        _ = url.withCString { sqlURL in
            sqlite3_bind_text(statement, 2, sqlURL, -1, nil)
        }

        if title.isEmpty {
            sqlite3_bind_null(statement, 3)
        } else {
            _ = title.withCString { sqlTitle in
                sqlite3_bind_text(statement, 3, sqlTitle, -1, nil)
            }
        }

        _ = chromeBundleID.withCString { sqlBundle in
            sqlite3_bind_text(statement, 4, sqlBundle, -1, nil)
        }
        sqlite3_bind_double(statement, 5, visit.startedAt.timeIntervalSince1970)
        sqlite3_bind_double(statement, 6, visit.endedAt.timeIntervalSince1970)
        sqlite3_bind_int64(statement, 7, Int64(visit.seconds))

        _ = sqlite3_step(statement)
        sqlite3_finalize(statement)
    }

    func summary(for date: Date) -> [SummaryRow] {
        let calendar = Calendar.current
        let dayStart = calendar.startOfDay(for: date)
        let dayEnd = calendar.date(byAdding: .day, value: 1, to: dayStart) ?? date

        let query = """
        SELECT domain, SUM(duration_sec) AS total_seconds
        FROM visits
        WHERE started_at >= ? AND started_at < ?
        GROUP BY domain
        ORDER BY total_seconds DESC;
        """

        guard let db else { return [] }
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) != SQLITE_OK {
            return []
        }

        sqlite3_bind_double(statement, 1, dayStart.timeIntervalSince1970)
        sqlite3_bind_double(statement, 2, dayEnd.timeIntervalSince1970)

        var results: [SummaryRow] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if let cDomain = sqlite3_column_text(statement, 0) {
                let domain = String(cString: cDomain)
                let seconds = Int(sqlite3_column_int64(statement, 1))
                results.append(SummaryRow(domain: domain, seconds: seconds))
            }
        }
        sqlite3_finalize(statement)
        return results
    }

    func totalSeconds(for date: Date) -> Int {
        let calendar = Calendar.current
        let dayStart = calendar.startOfDay(for: date)
        let dayEnd = calendar.date(byAdding: .day, value: 1, to: dayStart) ?? date

        let query = """
        SELECT COALESCE(SUM(duration_sec), 0)
        FROM visits
        WHERE started_at >= ? AND started_at < ?;
        """

        guard let db else { return 0 }
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) != SQLITE_OK {
            return 0
        }

        sqlite3_bind_double(statement, 1, dayStart.timeIntervalSince1970)
        sqlite3_bind_double(statement, 2, dayEnd.timeIntervalSince1970)

        var total = 0
        if sqlite3_step(statement) == SQLITE_ROW {
            total = Int(sqlite3_column_int64(statement, 0))
        }
        sqlite3_finalize(statement)
        return total
    }

    func visits(for date: Date) -> [VisitExport] {
        let calendar = Calendar.current
        let dayStart = calendar.startOfDay(for: date)
        let dayEnd = calendar.date(byAdding: .day, value: 1, to: dayStart) ?? date
        let query = """
        SELECT domain, url, title, started_at, ended_at, duration_sec
        FROM visits
        WHERE started_at >= ? AND started_at < ?
        ORDER BY started_at ASC;
        """

        guard let db else { return [] }
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) != SQLITE_OK {
            return []
        }

        sqlite3_bind_double(statement, 1, dayStart.timeIntervalSince1970)
        sqlite3_bind_double(statement, 2, dayEnd.timeIntervalSince1970)

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        var rows: [VisitExport] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard
                let domainData = sqlite3_column_text(statement, 0),
                let urlData = sqlite3_column_text(statement, 1)
            else {
                continue
            }
            let title = sqlite3_column_text(statement, 2).map { String(cString: $0) } ?? ""
            let startedAt = Date(timeIntervalSince1970: sqlite3_column_double(statement, 3))
            let endedAt = Date(timeIntervalSince1970: sqlite3_column_double(statement, 4))
            let duration = Int(sqlite3_column_int64(statement, 5))
            rows.append(
                VisitExport(
                    domain: String(cString: domainData),
                    url: String(cString: urlData),
                    title: title,
                    startedAt: formatter.string(from: startedAt),
                    endedAt: formatter.string(from: endedAt),
                    durationSec: duration
                )
            )
        }
        sqlite3_finalize(statement)
        return rows
    }

    func exportJSON(for date: Date, to fileURL: URL) throws {
        let summaryRows = summary(for: date)
        let total = summaryRows.reduce(0) { $0 + $1.seconds }
        let payload = ExportPayload(
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            date: ISO8601DateFormatter().string(from: Calendar.current.startOfDay(for: date)),
            totalSeconds: total,
            summaries: summaryRows,
            visits: visits(for: date)
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(payload)
        try data.write(to: fileURL, options: .atomic)
    }

    func exportCSV(for date: Date, to fileURL: URL) throws {
        let rows = visits(for: date)

        var lines = ["domain,url,title,started_at,ended_at,duration_sec"]
        lines.reserveCapacity(rows.count + 1)

        for row in rows {
            lines.append([
                escapeCSV(row.domain),
                escapeCSV(row.url),
                escapeCSV(row.title),
                escapeCSV(row.startedAt),
                escapeCSV(row.endedAt),
                String(row.durationSec)
            ].joined(separator: ","))
        }

        let content = lines.joined(separator: "\n")
        try content.data(using: .utf8)?.write(to: fileURL, options: .atomic)
    }

    private func escapeCSV(_ value: String) -> String {
        let needsQuote = value.contains(",") || value.contains("\n") || value.contains("\"")
        let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
        return needsQuote ? "\"\(escaped)\"" : escaped
    }
}

final class ChromeTracker: NSObject {
    private let urlProvider = ChromeURLProvider()
    private let store: VisitStore
    private let filterManager: WebsiteFilterManager
    private var currentSession: ActiveSession?
    private var timer: Timer?
    private(set) var isChromeActive = false
    var onUpdate: (() -> Void)?

    init(store: VisitStore, filterManager: WebsiteFilterManager) {
        self.store = store
        self.filterManager = filterManager
    }

    func start() {
        observeActiveAppChanges()
        isChromeActive = NSWorkspace.shared.frontmostApplication?.bundleIdentifier == chromeBundleID
        timer = Timer.scheduledTimer(timeInterval: 1.0, target: self, selector: #selector(pollChrome), userInfo: nil, repeats: true)
        if let timer {
            RunLoop.main.add(timer, forMode: .common)
        }

        pollChrome()
    }

    func stop() {
        finalizeCurrentSession()
        timer?.invalidate()
        timer = nil
        NSWorkspace.shared.notificationCenter.removeObserver(self)
    }

    func refreshAfterFilterChange() {
        guard isChromeActive else {
            onUpdate?()
            return
        }

        pollChrome()
        onUpdate?()
    }

    func currentState() -> (isChromeActive: Bool, domain: String?, elapsedSec: Int) {
        guard let session = currentSession else {
            return (isChromeActive, nil, 0)
        }
        let elapsed = Int(max(0, Date().timeIntervalSince(session.startedAt)))
        return (isChromeActive, session.domain, elapsed)
    }

    private func observeActiveAppChanges() {
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        workspaceCenter.addObserver(
            self,
            selector: #selector(appChanged(_:)),
            name: NSWorkspace.didActivateApplicationNotification,
            object: nil
        )
        workspaceCenter.addObserver(
            self,
            selector: #selector(systemAwakeOrSleep(_:)),
            name: NSWorkspace.willSleepNotification,
            object: nil
        )
        workspaceCenter.addObserver(
            self,
            selector: #selector(systemAwakeOrSleep(_:)),
            name: NSWorkspace.didWakeNotification,
            object: nil
        )
    }

    @objc private func systemAwakeOrSleep(_ notification: Notification) {
        if notification.name == NSWorkspace.willSleepNotification {
            isChromeActive = false
            finalizeCurrentSession()
        }

        if notification.name == NSWorkspace.didWakeNotification {
            isChromeActive = NSWorkspace.shared.frontmostApplication?.bundleIdentifier == chromeBundleID
            pollChrome()
        }

        onUpdate?()
    }

    @objc private func appChanged(_ notification: Notification) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
            return
        }

        let active = app.bundleIdentifier == chromeBundleID
        if isChromeActive != active {
            isChromeActive = active
            if !active {
                finalizeCurrentSession()
            } else {
                pollChrome()
            }
            onUpdate?()
        }
    }

    @objc private func pollChrome() {
        if !isChromeActive {
            return
        }

        guard let tab = urlProvider.currentTab() else {
            return
        }

        if filterManager.shouldBlock(domain: tab.domain) {
            if currentSession != nil {
                finalizeCurrentSession()
            }
            _ = urlProvider.blockActiveTab()
            onUpdate?()
            return
        }

        if var session = currentSession {
            if session.domain != tab.domain {
                finalizeCurrentSession()
                startNewSession(using: tab)
            } else {
                session.url = tab.url
                session.title = tab.title
                currentSession = session
            }
            onUpdate?()
            return
        }

        startNewSession(using: tab)
        onUpdate?()
    }

    private func startNewSession(using tab: ChromeTab) {
        currentSession = ActiveSession(domain: tab.domain, url: tab.url, startedAt: Date(), title: tab.title)
    }

    private func finalizeCurrentSession() {
        guard let session = currentSession else {
            return
        }

        let now = Date()
        let visit = FinalizedVisit(
            domain: session.domain,
            url: session.url,
            title: session.title,
            startedAt: session.startedAt,
            endedAt: now
        )

        if visit.seconds >= minimumVisitSeconds {
            store.insert(visit)
        }

        currentSession = nil
    }
}

final class MenuBarController: NSObject {
    private let menuBarItem: NSStatusItem
    private let menu = NSMenu()
    private let tracker: ChromeTracker
    private let store: VisitStore
    private let filterManager: WebsiteFilterManager
    private let hostsBlocker: SystemHostsBlocker
    private var refreshTimer: Timer?

    init(tracker: ChromeTracker, store: VisitStore, filterManager: WebsiteFilterManager, hostsBlocker: SystemHostsBlocker) {
        self.tracker = tracker
        self.store = store
        self.filterManager = filterManager
        self.hostsBlocker = hostsBlocker
        self.menuBarItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()

        setupMenuBar()
        tracker.onUpdate = { [weak self] in
            DispatchQueue.main.async {
                self?.refreshMenu()
            }
        }
    }

    func start() {
        refreshMenu()
        refreshTimer = Timer.scheduledTimer(timeInterval: 5.0, target: self, selector: #selector(refreshMenu), userInfo: nil, repeats: true)
        if let timer = refreshTimer {
            RunLoop.main.add(timer, forMode: .common)
        }
    }

    func stop() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    private func setupMenuBar() {
        menuBarItem.menu = menu
        menuBarItem.button?.title = "◉"
        menuBarItem.button?.toolTip = "ChromeTracker"
    }

    private func updateStatusTitle(totalSeconds: Int, currentDomain: String?) {
        let timerString = format(seconds: totalSeconds)
        let symbol = currentDomain == nil ? "◌" : "◉"
        menuBarItem.button?.title = "\(symbol) \(timerString)"
        menuBarItem.button?.toolTip = currentDomain == nil
            ? "ChromeTracker: Total \(timerString)"
            : "Current: \(currentDomain!)\nTotal: \(timerString)"
    }

    @objc private func refreshMenu() {
        let todayTotal = store.totalSeconds(for: Date())

        let state = tracker.currentState()
        let effectiveTotal = todayTotal + (state.isChromeActive ? state.elapsedSec : 0)
        updateStatusTitle(totalSeconds: effectiveTotal, currentDomain: state.domain)

        menu.removeAllItems()

        let exportJSONItem = NSMenuItem(title: "Export JSON", action: #selector(exportJSON), keyEquivalent: "j")
        exportJSONItem.target = self
        menu.addItem(exportJSONItem)

        let exportCSVItem = NSMenuItem(title: "Export CSV", action: #selector(exportCSV), keyEquivalent: "c")
        exportCSVItem.target = self
        menu.addItem(exportCSVItem)

        menu.addItem(NSMenuItem.separator())

        let blocklistItem = NSMenuItem(title: "Blocked Sites", action: #selector(setBlocklist), keyEquivalent: "b")
        blocklistItem.target = self
        menu.addItem(blocklistItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    @objc private func exportJSON() {
        do {
            let path = exportPath(nil, extension: "json")
            try store.exportJSON(for: Date(), to: path)
            postNotification(title: "JSON export complete", message: path.path)
        } catch {
            postNotification(title: "JSON export failed", message: error.localizedDescription)
        }
    }

    @objc private func exportCSV() {
        do {
            let path = exportPath(nil, extension: "csv")
            try store.exportCSV(for: Date(), to: path)
            postNotification(title: "CSV export complete", message: path.path)
        } catch {
            postNotification(title: "CSV export failed", message: error.localizedDescription)
        }
    }

    @objc private func quitApp() {
        tracker.stop()
        stop()
        NSApplication.shared.terminate(nil)
    }

    private func postNotification(title: String, message: String) {
        print("[ChromeTracker] \(title): \(message)")
    }

    @objc private func setBlocklist() {
        let input = requestDomainList(
            title: "Blocked Sites",
            message: "Enter domains to block. One per line, separated by newlines or commas.",
            initial: filterManager.blockedDomains.joined(separator: "\n")
        )
        guard let input else {
            return
        }

        filterManager.setBlockedDomains(WebsiteFilterManager.parseDomainInput(input))
        let hostsResult = hostsBlocker.applyBlockedDomains(filterManager.blockedDomains)
        tracker.refreshAfterFilterChange()
        if hostsResult.success {
            postNotification(title: "Blocking list applied", message: "\(filterManager.blockedDomains.count) entries, \(hostsResult.message)")
        } else {
            postNotification(title: "Blocking list applied (system block failed)", message: hostsResult.message)
        }
    }

    private func requestDomainList(title: String, message: String, initial: String) -> String? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational

        let textView = NSTextView(frame: NSRect(x: 0, y: 0, width: 340, height: 140))
        textView.string = initial
        textView.font = .systemFont(ofSize: 12)

        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 340, height: 140))
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = false

        alert.accessoryView = scroll
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = textView

        let result = alert.runModal()
        if result == .alertFirstButtonReturn {
            return textView.string
        }

        return nil
    }

    private func format(seconds: Int) -> String {
        let remaining = max(0, seconds)
        let hours = remaining / 3600
        let minutes = (remaining % 3600) / 60
        let secs = remaining % 60
        if hours > 0 {
            return String(format: "%02d:%02d:%02d", hours, minutes, secs)
        }
        return String(format: "%02d:%02d", minutes, secs)
    }

}

enum RunMode {
    case runMenu
    case exportJSON(path: String?)
    case exportCSV(path: String?)
    case help
}

func printUsage() {
    print("Usage:")
    print("  ChromeTracker")
    print("    Run with menu bar tracker.")
    print("  ChromeTracker --export-json [path]")
    print("    Export today's data as JSON. Default path: ~/Downloads/ChromeTracker-<date>.json")
    print("  ChromeTracker --export-csv [path]")
    print("    Export today's data as CSV. Default path: ~/Downloads/ChromeTracker-<date>.csv")
    print("  ChromeTracker --help")
}

func parseMode() -> RunMode {
    let args = Array(CommandLine.arguments.dropFirst())
    guard !args.isEmpty else {
        return .runMenu
    }

    let firstArg = args[0]
    switch firstArg {
    case "--help", "-h":
        return .help
    case "--export-json":
        if args.count >= 2 && !args[1].hasPrefix("-") {
            return .exportJSON(path: args[1])
        }
        return .exportJSON(path: nil)
    case "--export-csv":
        if args.count >= 2 && !args[1].hasPrefix("-") {
            return .exportCSV(path: args[1])
        }
        return .exportCSV(path: nil)
    default:
        return .runMenu
    }
}

func exportPath(_ optionalPath: String?, extension ext: String) -> URL {
    if let optionalPath {
        return URL(fileURLWithPath: optionalPath)
    }

    let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        ?? FileManager.default.homeDirectoryForCurrentUser
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    let filename = "ChromeTracker-\(formatter.string(from: Date())).\(ext)"
    return downloads.appendingPathComponent(filename)
}

let mode = parseMode()
guard let store = VisitStore() else {
    print("Failed to open database.")
    exit(1)
}

switch mode {
case .help:
    printUsage()
    exit(0)

case .exportJSON(let optionalPath):
    do {
        let target = exportPath(optionalPath, extension: "json")
        try store.exportJSON(for: Date(), to: target)
        print("JSON exported: \(target.path)")
    } catch {
        print("Failed to export JSON: \(error)")
        exit(1)
    }
    exit(0)

case .exportCSV(let optionalPath):
    do {
        let target = exportPath(optionalPath, extension: "csv")
        try store.exportCSV(for: Date(), to: target)
        print("CSV exported: \(target.path)")
    } catch {
        print("Failed to export CSV: \(error)")
        exit(1)
    }
    exit(0)

case .runMenu:
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)

    let filterManager = WebsiteFilterManager()
    let hostsBlocker = SystemHostsBlocker()
    let authResult = hostsBlocker.authorizeAtLaunch()
    guard authResult.success else {
        print("Initial administrator authentication failed: \(authResult.message)")
        exit(1)
    }
    print("[ChromeTracker] \(authResult.message)")

    let tracker = ChromeTracker(store: store, filterManager: filterManager)
    let menuBar = MenuBarController(
        tracker: tracker,
        store: store,
        filterManager: filterManager,
        hostsBlocker: hostsBlocker
    )
    menuBar.start()
    tracker.start()

    let signalQueue = DispatchQueue.main
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)

    let terminateAndExit = {
        tracker.stop()
        menuBar.stop()
        app.terminate(nil)
    }

    let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
    sigint.setEventHandler(handler: terminateAndExit)
    sigint.resume()

    let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
    sigterm.setEventHandler(handler: terminateAndExit)
    sigterm.resume()

    app.run()
}
