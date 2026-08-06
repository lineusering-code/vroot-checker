package dev.vroot.checker.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.report.ExportFormat
import dev.vroot.checker.report.ExportResult
import dev.vroot.checker.report.Exporter

/**
 * Export sheet: clipboard, share sheet and Downloads - separately for JSON and
 * for Markdown. Every route carries the full log and renders in [lang].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportSheet(
    report: DiagnosticsReport,
    lang: Lang,
    onResult: (ExportResult) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val s = Tr.strings(lang)
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(Modifier.padding(bottom = 24.dp)) {
            Text(
                s.export,
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Text(
                Exporter.fileName(report, ExportFormat.JSON).substringBeforeLast('.') +
                    " · " + s.exportHint,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
            )
            Spacer(Modifier.height(12.dp))

            SheetSection(ExportFormat.JSON.label)
            ExportAction("ic_copy", s.copyJson) {
                onResult(Exporter.copy(context, report, ExportFormat.JSON, lang)); onDismiss()
            }
            ExportAction("ic_share", s.shareJson) {
                onResult(Exporter.share(context, report, ExportFormat.JSON, lang)); onDismiss()
            }
            ExportAction("ic_save", s.saveJson) {
                onResult(Exporter.saveToDownloads(context, report, ExportFormat.JSON, lang)); onDismiss()
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            SheetSection(ExportFormat.MARKDOWN.label)
            ExportAction("ic_copy", s.copyMarkdown) {
                onResult(Exporter.copy(context, report, ExportFormat.MARKDOWN, lang)); onDismiss()
            }
            ExportAction("ic_share", s.shareMarkdown) {
                onResult(Exporter.share(context, report, ExportFormat.MARKDOWN, lang)); onDismiss()
            }
            ExportAction("ic_save", s.saveMarkdown) {
                onResult(Exporter.saveToDownloads(context, report, ExportFormat.MARKDOWN, lang)); onDismiss()
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            SheetSection(s.fullLog)
            ExportAction("ic_terminal", s.copyLog) {
                onResult(Exporter.copyLog(context, report, lang)); onDismiss()
            }
        }
    }
}

@Composable
private fun SheetSection(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
    )
}

@Composable
private fun ExportAction(icon: String, title: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        NamedIcon(name = icon, modifier = Modifier.size(22.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(16.dp))
        Text(title, style = MaterialTheme.typography.titleMedium)
    }
}
