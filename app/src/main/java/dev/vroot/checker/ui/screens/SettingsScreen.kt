package dev.vroot.checker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.ui.ScanUiState

/**
 * Language and check selection.
 *
 * Toggling a check writes through to preferences immediately: an "apply"
 * button would only add a state that can disagree with what the next scan
 * actually runs.
 */
@Composable
fun SettingsScreen(
    state: ScanUiState,
    probes: List<Pair<String, String>>,
    onLang: (Lang) -> Unit,
    onProbeToggle: (String, Boolean) -> Unit,
    onEnableAll: () -> Unit,
    onDisableAll: () -> Unit,
) {
    val s = Tr.strings(state.lang)
    val enabled = probes.count { it.first !in state.disabledProbes }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        // ---------- language ----------
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(s.settingsLanguage, style = MaterialTheme.typography.titleMedium)
                Text(
                    s.settingsLanguageHint,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Lang.entries.forEach { lang ->
                        FilterChip(
                            selected = state.lang == lang,
                            onClick = { onLang(lang) },
                            label = { Text(lang.nativeName) },
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        // ---------- checks ----------
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(vertical = 16.dp)) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    Text(s.settingsChecks, style = MaterialTheme.typography.titleMedium)
                    Text(
                        s.settingsChecksHint,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        String.format(s.checksEnabledOf, enabled, probes.size),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Row {
                        TextButton(onClick = onEnableAll) { Text(s.enableAll) }
                        Spacer(Modifier.width(8.dp))
                        TextButton(onClick = onDisableAll) { Text(s.disableAll) }
                    }
                }

                HorizontalDivider(Modifier.padding(vertical = 8.dp))

                probes.forEach { (id, fallbackName) ->
                    val on = id !in state.disabledProbes
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                Tr.probe(state.lang, id, fallbackName),
                                style = MaterialTheme.typography.titleSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                if (on) id else id + " · " + s.checkDisabled,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(checked = on, onCheckedChange = { onProbeToggle(id, it) })
                    }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}
