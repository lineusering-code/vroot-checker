package dev.vroot.checker.ui

import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.vroot.checker.About
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.i18n.UiStrings
import dev.vroot.checker.report.Exporter
import dev.vroot.checker.ui.components.ExportSheet
import dev.vroot.checker.ui.components.NamedIcon
import dev.vroot.checker.ui.screens.AboutScreen
import dev.vroot.checker.ui.screens.DashboardScreen
import dev.vroot.checker.ui.screens.LogScreen
import dev.vroot.checker.ui.screens.SettingsScreen
import dev.vroot.checker.ui.theme.VrootTheme
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            VrootTheme {
                VrootApp()
            }
        }
    }
}

private enum class Tab(val icon: String) {
    DASHBOARD("ic_shield_alert"),
    LOG("ic_terminal"),
    SETTINGS("ic_tune"),
    ABOUT("ic_info");

    fun title(s: UiStrings): String = when (this) {
        DASHBOARD -> s.navDashboard
        LOG -> s.navLog
        SETTINGS -> s.navSettings
        ABOUT -> s.navAbout
    }
}

@Composable
fun VrootApp(vm: ScanViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val base = LocalContext.current

    // The whole tree is composed against a configuration built from the chosen
    // language rather than the system locale. That way existing stringResource
    // lookups follow the in-app picker without every screen having to be
    // rewritten, and the choice survives a device locale that we do not ship.
    val localized = remember(state.lang, base) {
        val cfg = Configuration(base.resources.configuration)
        cfg.setLocale(Locale(state.lang.code))
        base.createConfigurationContext(cfg)
    }

    CompositionLocalProvider(
        LocalContext provides localized,
        LocalConfiguration provides localized.resources.configuration,
    ) {
        VrootShell(vm = vm, state = state)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VrootShell(vm: ScanViewModel, state: ScanUiState) {
    val context = LocalContext.current
    val s = Tr.strings(state.lang)
    val snackbar = remember { SnackbarHostState() }
    var tab by remember { mutableStateOf(Tab.DASHBOARD) }
    var showExport by remember { mutableStateOf(false) }

    // The first scan starts on its own - nothing to tap to see a result.
    LaunchedEffect(Unit) {
        if (!state.hasReport && !state.scanning) vm.scan()
    }

    LaunchedEffect(state.toast) {
        state.toast?.let {
            snackbar.showSnackbar(it)
            vm.consumeToast()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(About.APP_NAME, style = MaterialTheme.typography.titleLarge)
                        Text(
                            tab.title(s),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { NamedIcon(t.icon, modifier = Modifier.size(22.dp)) },
                        label = { Text(t.title(s)) },
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (tab) {
                Tab.DASHBOARD -> DashboardScreen(
                    state = state,
                    onScan = { vm.scan() },
                    onCancel = { vm.cancel() },
                    onExport = { showExport = true },
                )

                Tab.LOG -> LogScreen(
                    state = state,
                    onToggleLevel = vm::toggleLogLevel,
                    onQuery = vm::setLogQuery,
                    onCopyLog = {
                        state.report?.let { vm.onExport(Exporter.copyLog(context, it, state.lang)) }
                    },
                )

                Tab.SETTINGS -> SettingsScreen(
                    state = state,
                    probes = vm.allProbes,
                    onLang = vm::setLang,
                    onProbeToggle = vm::setProbeEnabled,
                    onEnableAll = vm::enableAllProbes,
                    onDisableAll = vm::disableAllProbes,
                )

                Tab.ABOUT -> AboutScreen()
            }
        }
    }

    val report = state.report
    if (showExport && report != null) {
        ExportSheet(
            report = report,
            lang = state.lang,
            onResult = vm::onExport,
            onDismiss = { showExport = false },
        )
    }
}
