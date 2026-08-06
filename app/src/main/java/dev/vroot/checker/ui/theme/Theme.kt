package dev.vroot.checker.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val LightScheme = lightColorScheme(
    primary = BlueSteel40,
    onPrimary = androidx.compose.ui.graphics.Color.White,
    primaryContainer = BlueSteel90,
    onPrimaryContainer = BlueSteel10,
    secondary = Slate30,
    background = androidx.compose.ui.graphics.Color(0xFFFBFCFE),
    surface = androidx.compose.ui.graphics.Color(0xFFFBFCFE),
)

private val DarkScheme = darkColorScheme(
    primary = BlueSteel80,
    onPrimary = BlueSteel20,
    primaryContainer = BlueSteel30,
    onPrimaryContainer = BlueSteel90,
    secondary = Slate90,
    background = Slate10,
    surface = Slate10,
    surfaceVariant = Slate20,
)

/**
 * Тема приложения. На Android 12+ берёт Material You из обоев пользователя,
 * на более старых — собственную палитру.
 */
@Composable
fun VrootTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val scheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        darkTheme -> DarkScheme
        else -> LightScheme
    }
    MaterialTheme(
        colorScheme = scheme,
        typography = VrootTypography,
        content = content,
    )
}
