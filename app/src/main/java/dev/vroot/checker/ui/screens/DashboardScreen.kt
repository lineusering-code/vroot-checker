package dev.vroot.checker.ui.screens

import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.vroot.checker.core.model.Bucket
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.ProbeReport
import dev.vroot.checker.ui.ScanUiState
import dev.vroot.checker.ui.components.EmptyState
import dev.vroot.checker.ui.components.KeyValueRow
import dev.vroot.checker.ui.components.MonoText
import dev.vroot.checker.ui.components.NamedIcon
import dev.vroot.checker.ui.components.ScoreBar
import dev.vroot.checker.ui.components.SignalCard
import dev.vroot.checker.ui.theme.accent
import dev.vroot.checker.ui.theme.container
import java.util.Locale

@Composable
fun DashboardScreen(
    state: ScanUiState,
    onScan: () -> Unit,
    onCancel: () -> Unit,
    onExport: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val report = state.report

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { ScanControls(state, onScan, onCancel, onExport) }

        if (state.error != null) {
            item {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                    ),
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Скан упал", style = MaterialTheme.typography.titleMedium)
                        MonoText(state.error)
                    }
                }
            }
        }

        if (report == null) {
            if (!state.scanning) {
                item {
                    EmptyState(
                        icon = "ic_shield_alert",
                        title = "Скан ещё не запускался",
                        subtitle = "Нажмите «Запустить скан», чтобы проверить среду",
                        modifier = Modifier.height(220.dp),
                    )
                }
            }
            return@LazyColumn
        }

        item { VerdictHero(report) }
        item { BucketsCard(report) }

        if (report.hits.isNotEmpty()) {
            item { SectionTitle("Ключевые находки", report.hits.size.toString()) }
            items(report.topSignals(6), key = { it.category.name + it.id }) { s ->
                SignalCard(signal = s, initiallyExpanded = false)
            }
        }

        Bucket.entries.forEach { bucket ->
            val probes = report.probes.filter { it.category.bucket == bucket }
            if (probes.isEmpty()) return@forEach
            item(key = "bucket-" + bucket.name) {
                SectionTitle(bucket.title, report.bucket(bucket).normalized.toString() + "/100")
            }
            items(probes, key = { it.probeId }) { p -> ProbeBlock(p) }
        }

        item { SectionTitle("Устройство", "") }
        item { DeviceCard(report) }
    }
}

@Composable
private fun ScanControls(
    state: ScanUiState,
    onScan: () -> Unit,
    onCancel: () -> Unit,
    onExport: () -> Unit,
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (state.scanning) {
                OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                    NamedIcon("ic_close", modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Остановить")
                }
            } else {
                Button(onClick = onScan, modifier = Modifier.weight(1f)) {
                    NamedIcon(if (state.hasReport) "ic_refresh" else "ic_play", modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(if (state.hasReport) "Пересканировать" else "Запустить скан")
                }
            }
            if (state.hasReport && !state.scanning) {
                Spacer(Modifier.width(10.dp))
                FilledTonalButton(onClick = onExport) {
                    NamedIcon("ic_share", modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Экспорт")
                }
            }
        }

        AnimatedVisibility(visible = state.scanning) {
            Column(Modifier.padding(top = 12.dp)) {
                val p = state.progress
                LinearProgressIndicator(
                    progress = { p?.fraction ?: 0f },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(6.dp))
                MonoText(
                    if (p == null) {
                        "Инициализация движка…"
                    } else {
                        p.done.toString() + "/" + p.total + " · " + p.current
                    },
                )
            }
        }
    }
}

@Composable
private fun VerdictHero(report: DiagnosticsReport) {
    val accent = report.verdict.accent()
    Card(colors = CardDefaults.cardColors(containerColor = report.verdict.container().copy(alpha = 0.55f))) {
        Column(Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                NamedIcon(
                    name = if (report.verdict.name == "CLEAN") "ic_verified" else "ic_shield_alert",
                    tint = accent,
                    modifier = Modifier.size(30.dp),
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        report.verdict.title,
                        style = MaterialTheme.typography.headlineLarge,
                        color = accent,
                    )
                    Text(report.verdict.summary, style = MaterialTheme.typography.bodyMedium)
                }
                Text(
                    report.totalScore.toString(),
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Bold,
                    color = accent,
                )
            }
            Spacer(Modifier.height(14.dp))
            ScoreBar(value = report.totalScore, color = accent, height = 10)
            Spacer(Modifier.height(10.dp))
            MonoText(
                "сработало " + report.hits.size + " из " + report.checksRun + " проверок · " +
                    report.probes.size + " проб · " +
                    String.format(Locale.US, "%.2f с", report.elapsedMs / 1000.0),
            )
            report.forcedBy?.let {
                Spacer(Modifier.height(6.dp))
                MonoText("вердикт форсирован критическим сигналом: " + it, color = accent)
            }
        }
    }
}

@Composable
private fun BucketsCard(report: DiagnosticsReport) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Text("Риск по категориям", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(12.dp))
            report.buckets.forEach { b ->
                val color = if (b.normalized >= 60) {
                    MaterialTheme.colorScheme.error
                } else if (b.normalized >= 25) {
                    dev.vroot.checker.ui.theme.SeverityMedium
                } else {
                    MaterialTheme.colorScheme.primary
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        b.bucket.title,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.width(88.dp),
                    )
                    ScoreBar(value = b.normalized, color = color, modifier = Modifier.weight(1f))
                    Spacer(Modifier.width(10.dp))
                    MonoText(b.normalized.toString().padStart(3) + "  •" + b.hits)
                }
                Spacer(Modifier.height(10.dp))
            }
        }
    }
}

@Composable
private fun ProbeBlock(p: ProbeReport) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
            NamedIcon(p.category.icon, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(8.dp))
            Text(p.displayName, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            MonoText(
                when {
                    p.timedOut -> "тайм-аут"
                    p.error != null -> "ошибка"
                    else -> p.elapsedMs.toString() + " мс"
                },
            )
        }
        p.error?.let { MonoText(it, color = MaterialTheme.colorScheme.error) }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            p.signals.sortedByDescending { it.score }.forEach { s -> SignalCard(signal = s) }
        }
        Spacer(Modifier.height(6.dp))
    }
}

@Composable
private fun DeviceCard(report: DiagnosticsReport) {
    val d = report.device
    Card {
        Column(Modifier.padding(16.dp)) {
            KeyValueRow("Производитель", d.manufacturer + " / " + d.brand)
            KeyValueRow("Модель", d.model + " (" + d.device + ")")
            KeyValueRow("Product", d.product)
            KeyValueRow("Hardware", d.hardware + " / " + d.board)
            KeyValueRow("Android", d.androidRelease + " (API " + d.sdkInt + ")")
            KeyValueRow("Build", d.buildType + " / " + d.buildTags)
            KeyValueRow("ABI", d.abis.joinToString(", "))
            KeyValueRow("Fingerprint", d.fingerprint)
            KeyValueRow("Ядро", d.kernel)
        }
    }
}

@Composable
private fun SectionTitle(title: String, trailing: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
        if (trailing.isNotEmpty()) MonoText(trailing)
    }
}
