package dev.vroot.checker.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import dev.vroot.checker.R
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.ui.theme.MonoStyle
import dev.vroot.checker.ui.theme.accent

/**
 * Иконка по имени vector drawable — категории хранят имя иконки строкой,
 * чтобы добавление новой пробы не требовало правки UI.
 */
@Composable
fun NamedIcon(
    name: String,
    contentDescription: String? = null,
    modifier: Modifier = Modifier.size(20.dp),
    tint: Color = LocalContentColor.current,
) {
    val context = LocalContext.current
    val id = remember2(name) {
        context.resources.getIdentifier(name, "drawable", context.packageName)
    }
    Icon(
        painter = painterResource(id = if (id != 0) id else R.drawable.ic_info),
        contentDescription = contentDescription,
        modifier = modifier,
        tint = tint,
    )
}

@Composable
private fun <T> remember2(key: Any?, calc: () -> T): T = androidx.compose.runtime.remember(key) { calc() }

/** Горизонтальная шкала риска 0..100 с плавной анимацией. */
@Composable
fun ScoreBar(
    value: Int,
    color: Color,
    modifier: Modifier = Modifier,
    height: Int = 8,
) {
    val fraction by animateFloatAsState(
        targetValue = (value.coerceIn(0, 100)) / 100f,
        label = "score",
    )
    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(height.dp)
            .clip(RoundedCornerShape(height.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Box(
            Modifier
                .fillMaxHeight()
                .fillMaxWidth(fraction)
                .clip(RoundedCornerShape(height.dp))
                .background(color),
        )
    }
}

/** Компактный бейдж уровня опасности. */
@Composable
fun SeverityChip(severity: Severity, modifier: Modifier = Modifier) {
    val c = severity.accent()
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(c.copy(alpha = 0.14f))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(
            text = severity.label,
            style = MaterialTheme.typography.labelSmall,
            color = c,
        )
    }
}

/** Серая подпись-метка для технических значений. */
@Composable
fun MonoText(text: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurfaceVariant) {
    Text(text = text, style = MonoStyle, color = color, modifier = modifier)
}

/** Строка «ключ — значение» для улик и характеристик устройства. */
@Composable
fun KeyValueRow(key: String, value: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = key,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(120.dp),
        )
        Spacer(Modifier.width(8.dp))
        MonoText(text = value, modifier = Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
    }
}

/** Заглушка для пустых списков. */
@Composable
fun EmptyState(icon: String, title: String, subtitle: String, modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        androidx.compose.foundation.layout.Column(horizontalAlignment = Alignment.CenterHorizontally) {
            NamedIcon(
                name = icon,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.outline,
            )
            Spacer(Modifier.height(12.dp))
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

internal val CardPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp)
