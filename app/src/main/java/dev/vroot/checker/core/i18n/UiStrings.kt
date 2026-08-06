package dev.vroot.checker.core.i18n

/**
 * Every user-visible string in one typed catalogue.
 *
 * A data class is used instead of a key/value map on purpose: adding a string
 * here breaks compilation until every language provides it, so a translation
 * can never silently degrade into a blank label or an English leftover.
 *
 * Report chrome lives here too, because the Markdown export has to be
 * renderable in a language the device is not currently running in.
 */
data class UiStrings(
    // Navigation and shell
    val tagline: String,
    val navDashboard: String,
    val navLog: String,
    val navAbout: String,
    val navSettings: String,

    // Scanning
    val btnScan: String,
    val btnRescan: String,
    val btnCancel: String,
    val scanning: String,
    val scanProgress: String,
    val noReportYet: String,
    val noReportHint: String,

    // Verdict block
    val verdict: String,
    val overallRisk: String,
    val checksTriggered: String,
    val scanStarted: String,
    val forcedUp: String,
    val elapsed: String,

    // Device block
    val device: String,
    val colField: String,
    val colValue: String,
    val devManufacturer: String,
    val devModel: String,
    val devProductHwBoard: String,
    val devAndroid: String,
    val devBuildTypeTags: String,
    val devAbi: String,
    val devFingerprint: String,
    val devKernel: String,

    // Buckets
    val riskByCategory: String,
    val colBucket: String,
    val colRisk: String,
    val colScale: String,
    val colHits: String,

    // Findings
    val keyFindings: String,
    val nothingTriggered: String,
    val why: String,
    val method: String,
    val evidence: String,
    val confidence: String,
    val contribution: String,
    val weight: String,
    val whyItMatters: String,
    val colKey: String,

    // Per-probe detail
    val perCheckDetails: String,
    val category: String,
    val bucket: String,
    val status: String,
    val noData: String,
    val statusTimeout: String,
    val statusError: String,
    val statusTriggered: String,
    val statusClean: String,
    val executionError: String,
    val colCheck: String,
    val colLevel: String,

    // Log
    val fullLog: String,
    val expandLog: String,
    val logSearch: String,
    val logEmpty: String,
    val logNoMatches: String,

    // Export
    val export: String,
    val exportHint: String,
    val copyJson: String,
    val copyMarkdown: String,
    val copyLog: String,
    val shareJson: String,
    val shareMarkdown: String,
    val saveJson: String,
    val saveMarkdown: String,
    val copied: String,
    val savedTo: String,
    val exportFailed: String,

    // About
    val aboutGithub: String,
    val aboutAuthor: String,
    val aboutIssues: String,
    val aboutReleases: String,
    val aboutLicense: String,
    val aboutVersion: String,

    // Settings
    val settingsLanguage: String,
    val settingsLanguageHint: String,
    val settingsChecks: String,
    val settingsChecksHint: String,
    val enableAll: String,
    val disableAll: String,
    val checksEnabledOf: String,
    val checkDisabled: String,

    // Report footer
    val reportTitleSuffix: String,
    val footerBuiltWith: String,
    val footerAuthor: String,
    val footerLicense: String,
    val secondsShort: String,
) {
    companion object {
        val EN = UiStrings(
            tagline = "Root, virtualization and hooking diagnostics",
            navDashboard = "Overview",
            navLog = "Log",
            navAbout = "About",
            navSettings = "Settings",

            btnScan = "Run diagnostics",
            btnRescan = "Scan again",
            btnCancel = "Cancel",
            scanning = "Scanning",
            scanProgress = "%1$d of %2$d",
            noReportYet = "No scan yet",
            noReportHint = "Run the diagnostics to see what this device looks like from the inside.",

            verdict = "Verdict",
            overallRisk = "Overall risk",
            checksTriggered = "%1$d of %2$d checks triggered",
            scanStarted = "Scan",
            forcedUp = "Verdict raised by a critical finding",
            elapsed = "Elapsed",

            device = "Device",
            colField = "Field",
            colValue = "Value",
            devManufacturer = "Manufacturer",
            devModel = "Model",
            devProductHwBoard = "Product / Hardware / Board",
            devAndroid = "Android",
            devBuildTypeTags = "Build type / tags",
            devAbi = "ABI",
            devFingerprint = "Fingerprint",
            devKernel = "Kernel",

            riskByCategory = "Risk by category",
            colBucket = "Bucket",
            colRisk = "Risk",
            colScale = "Scale",
            colHits = "Hits",

            keyFindings = "Key findings",
            nothingTriggered = "No check triggered.",
            why = "Why",
            method = "Method",
            evidence = "Evidence",
            confidence = "confidence",
            contribution = "contribution",
            weight = "Weight",
            whyItMatters = "why it matters",
            colKey = "Key",

            perCheckDetails = "Per-check details",
            category = "Category",
            bucket = "bucket",
            status = "status",
            noData = "No data.",
            statusTimeout = "timed out",
            statusError = "failed",
            statusTriggered = "%1$d triggered",
            statusClean = "clean",
            executionError = "Execution error",
            colCheck = "Check",
            colLevel = "Level",

            fullLog = "Full scan log",
            expandLog = "Expand the log",
            logSearch = "Search the log",
            logEmpty = "The log is empty - run a scan first",
            logNoMatches = "Nothing matches the current filter",

            export = "Export report",
            exportHint = "The full log is included in every format.",
            copyJson = "Copy JSON",
            copyMarkdown = "Copy Markdown",
            copyLog = "Copy log only",
            shareJson = "Share .json",
            shareMarkdown = "Share .md",
            saveJson = "Save .json to Downloads",
            saveMarkdown = "Save .md to Downloads",
            copied = "Copied to clipboard",
            savedTo = "Saved to Downloads",
            exportFailed = "Export failed",

            aboutGithub = "GitHub repository",
            aboutAuthor = "Author",
            aboutIssues = "Report an issue",
            aboutReleases = "Releases",
            aboutLicense = "License",
            aboutVersion = "Version",

            settingsLanguage = "Language",
            settingsLanguageHint = "Applies to the interface and to exported reports, independently of the system language.",
            settingsChecks = "Checks",
            settingsChecksHint = "Disabled checks are skipped entirely and do not affect the score.",
            enableAll = "Enable all",
            disableAll = "Disable all",
            checksEnabledOf = "%1$d of %2$d enabled",
            checkDisabled = "disabled",

            reportTitleSuffix = "diagnostics report",
            footerBuiltWith = "Report produced by",
            footerAuthor = "author",
            footerLicense = "license",
            secondsShort = "s",
        )
    }
}
