package dev.vroot.checker.report

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import dev.vroot.checker.About
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.model.DiagnosticsReport
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Export formats. One report, two representations. */
enum class ExportFormat(
    val label: String,
    val ext: String,
    val mime: String,
    val icon: String,
) {
    JSON("JSON", "json", "application/json", "ic_code"),
    MARKDOWN("Markdown", "md", "text/markdown", "ic_description"),
}

/** Result of an export operation - the UI shows it in a snackbar. */
data class ExportResult(val ok: Boolean, val message: String)

/**
 * Every way of getting the report out of the app:
 *  - copy to the clipboard (JSON / Markdown),
 *  - send as a file through the share sheet,
 *  - save to the Downloads folder,
 *  - quick copy of the log alone.
 *
 * Every export carries the full scan log by default, and every entry point
 * takes the language explicitly so the exported document matches what the user
 * sees on screen.
 */
object Exporter {

    fun render(
        report: DiagnosticsReport,
        format: ExportFormat,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
    ): String = when (format) {
        ExportFormat.JSON -> JsonReport.toJson(report, lang = lang, includeLog = includeLog)
        ExportFormat.MARKDOWN -> MarkdownReport.toMarkdown(report, lang = lang, includeLog = includeLog)
    }

    fun fileName(report: DiagnosticsReport, format: ExportFormat): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(report.startedAt))
        val model = report.device.model.replace(Regex("[^A-Za-z0-9]+"), "-").trim('-').ifEmpty { "device" }
        return "vroot-" + model + "-" + stamp + "." + format.ext
    }

    // ---------- clipboard ----------

    fun copy(
        context: Context,
        report: DiagnosticsReport,
        format: ExportFormat,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
    ): ExportResult {
        val s = Tr.strings(lang)
        val text = render(report, format, lang, includeLog)
        return copyText(context, About.APP_NAME + " " + format.label, text, lang).let {
            if (it.ok) {
                ExportResult(true, s.copied + " - " + format.label + " (" + human(text.length) + ")")
            } else {
                it
            }
        }
    }

    /** Copy of the log alone as plain text - handy for pasting into a chat. */
    fun copyLog(context: Context, report: DiagnosticsReport, lang: Lang = Lang.DEFAULT): ExportResult {
        val s = Tr.strings(lang)
        val text = buildString {
            appendLine(About.APP_NAME + " - " + s.fullLog)
            appendLine(About.REPO_URL)
            appendLine()
            report.log.forEach { l ->
                appendLine(
                    String.format(
                        Locale.US,
                        "[%7.3fs] %s [%s] %s",
                        l.sinceStartMs / 1000.0,
                        l.level.tag,
                        l.tag,
                        l.message,
                    ),
                )
                l.detail?.lineSequence()?.forEach { line ->
                    if (line.isNotBlank()) appendLine("        " + line)
                }
            }
        }
        return copyText(context, "Vroot log", text, lang).let {
            if (it.ok) ExportResult(true, s.copied + " (" + report.log.size + ")") else it
        }
    }

    fun copyText(
        context: Context,
        label: String,
        text: String,
        lang: Lang = Lang.DEFAULT,
    ): ExportResult = runCatching {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        ExportResult(true, Tr.strings(lang).copied)
    }.getOrElse { ExportResult(false, Tr.strings(lang).exportFailed + ": " + it.message) }

    // ---------- share as a file ----------

    fun share(
        context: Context,
        report: DiagnosticsReport,
        format: ExportFormat,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
    ): ExportResult = runCatching {
        val s = Tr.strings(lang)
        val name = fileName(report, format)
        val uri = cacheFileUri(context, name, render(report, format, lang, includeLog))
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = format.mime
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(
                Intent.EXTRA_SUBJECT,
                About.APP_NAME + " - " + Tr.verdictTitle(lang, report.verdict) +
                    " (" + report.totalScore + "/100)",
            )
            putExtra(Intent.EXTRA_TEXT, About.exportFooter)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(intent, s.export)
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
        ExportResult(true, name)
    }.getOrElse { ExportResult(false, Tr.strings(lang).exportFailed + ": " + it.message) }

    private fun cacheFileUri(context: Context, name: String, content: String): Uri {
        val dir = File(context.cacheDir, "exports").apply { mkdirs() }
        dir.listFiles()?.forEach { old -> if (old.name != name) old.delete() }
        val file = File(dir, name)
        file.writeText(content)
        return FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
    }

    // ---------- save to Downloads ----------

    fun saveToDownloads(
        context: Context,
        report: DiagnosticsReport,
        format: ExportFormat,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
    ): ExportResult = runCatching {
        val s = Tr.strings(lang)
        val name = fileName(report, format)
        val content = render(report, format, lang, includeLog)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, format.mime)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return ExportResult(false, s.exportFailed)
            resolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
        } else {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            dir.mkdirs()
            File(dir, name).writeText(content)
        }
        ExportResult(true, s.savedTo + ": " + name)
    }.getOrElse { ExportResult(false, Tr.strings(lang).exportFailed + ": " + it.message) }

    /** Language-neutral size, so no translation is needed for a snackbar. */
    private fun human(chars: Int): String =
        if (chars < 1024) chars.toString() + " B" else String.format(Locale.US, "%.1f KB", chars / 1024.0)
}
