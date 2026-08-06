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
import dev.vroot.checker.core.model.DiagnosticsReport
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Форматы экспорта. Один отчёт — два представления. */
enum class ExportFormat(
    val label: String,
    val ext: String,
    val mime: String,
    val icon: String,
) {
    JSON("JSON", "json", "application/json", "ic_code"),
    MARKDOWN("Markdown", "md", "text/markdown", "ic_description"),
}

/** Результат операции экспорта — UI показывает его в snackbar. */
data class ExportResult(val ok: Boolean, val message: String)

/**
 * Все способы отдать отчёт наружу:
 *  • копия в буфер (JSON / Markdown),
 *  • отправка файлом через share sheet,
 *  • сохранение в Каталог загрузок,
 *  • быстрая копия только лога.
 * Любой экспорт по умолчанию содержит ПОЛНЫЙ лог сканирования.
 */
object Exporter {

    fun render(report: DiagnosticsReport, format: ExportFormat, includeLog: Boolean = true): String =
        when (format) {
            ExportFormat.JSON -> JsonReport.toJson(report, includeLog = includeLog)
            ExportFormat.MARKDOWN -> MarkdownReport.toMarkdown(report, includeLog = includeLog)
        }

    fun fileName(report: DiagnosticsReport, format: ExportFormat): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(report.startedAt))
        val model = report.device.model.replace(Regex("[^A-Za-z0-9]+"), "-").trim('-').ifEmpty { "device" }
        return "vroot-" + model + "-" + stamp + "." + format.ext
    }

    // ────────── буфер обмена ──────────

    fun copy(context: Context, report: DiagnosticsReport, format: ExportFormat, includeLog: Boolean = true): ExportResult {
        val text = render(report, format, includeLog)
        return copyText(context, About.APP_NAME + " " + format.label, text).let {
            if (it.ok) ExportResult(true, format.label + " скопирован в буфер (" + human(text.length) + ")") else it
        }
    }

    /** Копия только лога в виде простого текста — удобно кидать в чат. */
    fun copyLog(context: Context, report: DiagnosticsReport): ExportResult {
        val text = buildString {
            appendLine(About.APP_NAME + " — лог сканирования")
            appendLine(About.REPO_URL)
            appendLine()
            report.log.forEach { l ->
                appendLine(
                    String.format(Locale.US, "[%7.3fs] %s [%s] %s", l.sinceStartMs / 1000.0, l.level.tag, l.tag, l.message),
                )
                l.detail?.lineSequence()?.forEach { line ->
                    if (line.isNotBlank()) appendLine("        " + line)
                }
            }
        }
        return copyText(context, "Vroot log", text).let {
            if (it.ok) ExportResult(true, "Лог скопирован (" + report.log.size + " строк)") else it
        }
    }

    fun copyText(context: Context, label: String, text: String): ExportResult = runCatching {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        ExportResult(true, "Скопировано")
    }.getOrElse { ExportResult(false, "Не удалось скопировать: " + it.message) }

    // ────────── отправка файлом ──────────

    fun share(context: Context, report: DiagnosticsReport, format: ExportFormat, includeLog: Boolean = true): ExportResult =
        runCatching {
            val name = fileName(report, format)
            val uri = cacheFileUri(context, name, render(report, format, includeLog))
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = format.mime
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, About.APP_NAME + " — " + report.verdict.title + " (" + report.totalScore + "/100)")
                putExtra(Intent.EXTRA_TEXT, About.exportFooter)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            val chooser = Intent.createChooser(intent, "Отправить " + format.label)
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(chooser)
            ExportResult(true, "Файл " + name + " готов к отправке")
        }.getOrElse { ExportResult(false, "Не удалось отправить: " + it.message) }

    private fun cacheFileUri(context: Context, name: String, content: String): Uri {
        val dir = File(context.cacheDir, "exports").apply { mkdirs() }
        dir.listFiles()?.forEach { old -> if (old.name != name) old.delete() }
        val file = File(dir, name)
        file.writeText(content)
        return FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
    }

    // ────────── сохранение в Загрузки ──────────

    fun saveToDownloads(
        context: Context,
        report: DiagnosticsReport,
        format: ExportFormat,
        includeLog: Boolean = true,
    ): ExportResult = runCatching {
        val name = fileName(report, format)
        val content = render(report, format, includeLog)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, format.mime)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return ExportResult(false, "Система не дала создать файл")
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
        ExportResult(true, "Сохранено в Загрузки: " + name)
    }.getOrElse { ExportResult(false, "Не удалось сохранить: " + it.message) }

    private fun human(chars: Int): String =
        if (chars < 1024) chars.toString() + " симв." else String.format(Locale.US, "%.1f КБ", chars / 1024.0)
}
