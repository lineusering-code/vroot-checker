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
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.report.ExportFormat
import dev.vroot.checker.report.ExportResult
import dev.vroot.checker.report.Exporter

/**
 * Лист экспорта: копия в буфер, отправка файлом и сохранение в Загрузки
 * — отдельно для JSON и для Markdown. Везде уезжает полный лог.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportSheet(
    report: DiagnosticsReport,
    onResult: (ExportResult) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(Modifier.padding(bottom = 24.dp)) {
            Text(
                "Экспорт отчёта",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Text(
                Exporter.fileName(report, ExportFormat.JSON).substringBeforeLast('.') +
                    " · полный лог (" + report.log.size + " строк) включён",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
            )
            Spacer(Modifier.height(12.dp))

            SheetSection("JSON — машиночитаемый")
            ExportAction("ic_copy", "Копировать JSON", "Весь отчёт в буфер обмена") {
                onResult(Exporter.copy(context, report, ExportFormat.JSON)); onDismiss()
            }
            ExportAction("ic_share", "Отправить .json", "Через любое приложение") {
                onResult(Exporter.share(context, report, ExportFormat.JSON)); onDismiss()
            }
            ExportAction("ic_save", "Сохранить .json", "В папку Загрузки") {
                onResult(Exporter.saveToDownloads(context, report, ExportFormat.JSON)); onDismiss()
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            SheetSection("Markdown — для чтения и issue")
            ExportAction("ic_copy", "Копировать Markdown", "Готово для вставки в GitHub") {
                onResult(Exporter.copy(context, report, ExportFormat.MARKDOWN)); onDismiss()
            }
            ExportAction("ic_share", "Отправить .md", "Файлом через share sheet") {
                onResult(Exporter.share(context, report, ExportFormat.MARKDOWN)); onDismiss()
            }
            ExportAction("ic_save", "Сохранить .md", "В папку Загрузки") {
                onResult(Exporter.saveToDownloads(context, report, ExportFormat.MARKDOWN)); onDismiss()
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            SheetSection("Только лог")
            ExportAction("ic_terminal", "Копировать лог", "Простой текст без разметки") {
                onResult(Exporter.copyLog(context, report)); onDismiss()
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
private fun ExportAction(icon: String, title: String, subtitle: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        NamedIcon(name = icon, modifier = Modifier.size(22.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(16.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
