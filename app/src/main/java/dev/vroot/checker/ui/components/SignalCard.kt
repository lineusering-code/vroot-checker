package dev.vroot.checker.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.unit.dp
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.ui.theme.accent

/**
 * Карточка одной проверки. Свёрнутая — только суть,
 * развёрнутая — «Почему / Метод / Улики», то есть полное обоснование детекта.
 */
@Composable
fun SignalCard(signal: Signal, modifier: Modifier = Modifier, initiallyExpanded: Boolean = false) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }
    val accent = signal.severity.accent()
    val rotation by animateFloatAsState(if (expanded) 180f else 0f, label = "chevron")

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (signal.triggered) {
                accent.copy(alpha = 0.07f)
            } else {
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
            },
        ),
    ) {
        Column(
            Modifier
                .clickable { expanded = !expanded }
                .padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                NamedIcon(
                    name = if (signal.triggered) "ic_error" else "ic_check",
                    tint = if (signal.triggered) accent else MaterialTheme.colorScheme.outline,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        text = signal.title,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    MonoText(signal.id)
                }
                Spacer(Modifier.width(8.dp))
                if (signal.triggered) SeverityChip(signal.severity)
                NamedIcon(
                    name = "ic_expand_more",
                    tint = MaterialTheme.colorScheme.outline,
                    modifier = Modifier
                        .size(22.dp)
                        .rotate(rotation),
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(top = 10.dp)) {
                    HorizontalDivider()
                    Spacer(Modifier.height(10.dp))

                    Text("Почему это важно", style = MaterialTheme.typography.labelSmall, color = accent)
                    Text(signal.why, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(10.dp))

                    KeyValueRow("Метод", signal.method)
                    KeyValueRow(
                        "Оценка",
                        signal.severity.label + " · вес " + signal.severity.weight +
                            " · уверенность " + signal.confidence + "% · вклад " + signal.score,
                    )
                    KeyValueRow("Категория", signal.category.title + " / " + signal.bucket.title)

                    if (signal.evidence.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Улики (" + signal.evidence.size + ")",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(4.dp))
                        signal.evidence.forEach { e -> KeyValueRow(e.key, e.value) }
                    }
                }
            }
        }
    }
}
