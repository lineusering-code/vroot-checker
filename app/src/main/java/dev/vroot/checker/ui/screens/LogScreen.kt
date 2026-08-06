package dev.vroot.checker.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.vroot.checker.core.model.LogLevel
import dev.vroot.checker.core.model.LogLine
import dev.vroot.checker.ui.ScanUiState
import dev.vroot.checker.ui.components.EmptyState
import dev.vroot.checker.ui.components.MonoText
import dev.vroot.checker.ui.components.NamedIcon
import dev.vroot.checker.ui.theme.SeverityCritical
import dev.vroot.checker.ui.theme.SeverityMedium
import dev.vroot.checker.ui.theme.VerdictClean
import java.util.Locale

/**
 * Живой лог сканирования: что проверяли, что нашли и почему это важно.
 * Каждая строка раскрывается в подробное объяснение.
 */
@Composable
fun LogScreen(
    state: ScanUiState,
    onToggleLevel: (LogLevel) -> Unit,
    onQuery: (String) -> Unit,
    onCopyLog: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val lines = state.filteredLog

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = state.logQuery,
                onValueChange = onQuery,
                singleLine = true,
                label = { Text("Поиск по логу") },
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            NamedIcon(
                name = "ic_copy",
                contentDescription = "Копировать лог",
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .size(28.dp)
                    .clickable(onClick = onCopyLog),
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LogLevel.entries.forEach { level ->
                FilterChip(
                    selected = level in state.logLevels,
                    onClick = { onToggleLevel(level) },
                    label = { Text(level.name) },
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        HorizontalDivider()

        if (lines.isEmpty()) {
            EmptyState(
                icon = "ic_terminal",
                title = if (state.hasReport) "Ничего не найдено" else "Лог пуст",
                subtitle = if (state.hasReport) "Попробуйте смягчить фильтры" else "Запустите сканирование",
            )
            return
        }

        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                horizontal = 12.dp,
                vertical = 8.dp,
            ),
        ) {
            items(lines, key = { it.at.toString() + it.tag + it.message }) { line -> LogRow(line) }
        }
    }
}

@Composable
private fun LogRow(line: LogLine) {
    var expanded by remember { mutableStateOf(false) }
    val color = levelColor(line.level)
    val hasDetail = !line.detail.isNullOrBlank()

    Column(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = hasDetail) { expanded = !expanded }
            .padding(vertical = 4.dp),
    ) {
        Row(verticalAlignment = Alignment.Top) {
            MonoText(
                String.format(Locale.US, "%7.3f", line.sinceStartMs / 1000.0),
                color = MaterialTheme.colorScheme.outline,
            )
            Spacer(Modifier.width(8.dp))
            MonoText(line.level.tag, color = color)
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                MonoText(line.message, color = MaterialTheme.colorScheme.onSurface)
                MonoText(line.tag, color = MaterialTheme.colorScheme.outline)
            }
            if (hasDetail) {
                NamedIcon(
                    name = "ic_expand_more",
                    tint = MaterialTheme.colorScheme.outline,
                    modifier = Modifier.size(18.dp),
                )
            }
        }

        AnimatedVisibility(visible = expanded && hasDetail) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(start = 24.dp, top = 6.dp, bottom = 6.dp),
            ) {
                MonoText(line.detail.orEmpty(), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
    }
}

private fun levelColor(level: LogLevel): Color = when (level) {
    LogLevel.TRACE -> Color(0xFF8A8F98)
    LogLevel.INFO -> Color(0xFF4F86D6)
    LogLevel.HIT -> SeverityCritical
    LogLevel.CLEAN -> VerdictClean
    LogLevel.WARN -> SeverityMedium
    LogLevel.ERROR -> SeverityCritical
}
