package dev.vroot.checker.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import dev.vroot.checker.About
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.ui.components.KeyValueRow
import dev.vroot.checker.ui.components.MonoText
import dev.vroot.checker.ui.components.NamedIcon

/**
 * About: author, repository, license and what the engine actually covers.
 *
 * The scoring card states the real rules rather than a simplified version -
 * a diagnostics tool that hides its own maths is not much better than a
 * boolean.
 */
@Composable
fun AboutScreen(lang: Lang = Lang.DEFAULT, modifier: Modifier = Modifier) {
    val uri = LocalUriHandler.current
    val s = Tr.strings(lang)

    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card {
            Column(Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    NamedIcon(
                        "ic_launcher_foreground",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp),
                    )
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(About.APP_NAME, style = MaterialTheme.typography.headlineLarge)
                        Text(
                            "v" + About.VERSION + " \u00b7 " + s.aboutLicense + " " + About.LICENSE,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(s.tagline, style = MaterialTheme.typography.bodyMedium)
            }
        }

        Card {
            Column(Modifier.padding(vertical = 6.dp)) {
                LinkRow("ic_github", s.aboutGithub, About.REPO_NAME) { uri.openUri(About.REPO_URL) }
                HorizontalDivider()
                LinkRow("ic_person", s.aboutAuthor, About.AUTHOR) { uri.openUri(About.AUTHOR_URL) }
                HorizontalDivider()
                LinkRow("ic_bug", s.aboutIssues, "GitHub Issues") { uri.openUri(About.ISSUES_URL) }
                HorizontalDivider()
                LinkRow("ic_download", s.aboutReleases, "Releases") { uri.openUri(About.RELEASES_URL) }
            }
        }

        Card {
            Column(Modifier.padding(16.dp)) {
                Text(s.riskByCategory, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(10.dp))
                Category.entries.forEach { c ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(vertical = 4.dp),
                    ) {
                        NamedIcon(c.icon, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            Tr.category(lang, c),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                        MonoText(Tr.bucket(lang, c.bucket))
                    }
                }
            }
        }

        Card {
            Column(Modifier.padding(16.dp)) {
                Text(s.overallRisk, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                // Formulas are language-neutral on purpose: they are the same in
                // every locale and easier to verify against the engine source.
                KeyValueRow(s.weight, "severity \u00d7 confidence / 100")
                KeyValueRow(s.bucket, "100 \u00d7 (1 \u2212 e^(\u2212raw/70))")
                KeyValueRow(s.overallRisk, "max(bucket) + \u03a3 v\u1d62 / 2\u2071")
                KeyValueRow(s.verdict, "15 / 35 / 65 \u2192 SUSPICIOUS / COMPROMISED / HOSTILE")
                KeyValueRow(s.forcedUp, "2 \u00d7 CRITICAL (conf \u2265 90) or 1 \u00d7 CRITICAL + score \u2265 35")
            }
        }

        Text(
            About.exportFooter(lang),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline,
        )
    }
}

@Composable
private fun LinkRow(icon: String, title: String, subtitle: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        NamedIcon(icon, modifier = Modifier.size(22.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        NamedIcon("ic_open_in_new", modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.outline)
    }
}
