package dev.vroot.checker.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vroot.checker.core.DetectorEngine
import dev.vroot.checker.core.EngineConfig
import dev.vroot.checker.core.ScanProgress
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.LogLevel
import dev.vroot.checker.core.model.LogLine
import dev.vroot.checker.report.ExportResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ScanUiState(
    val scanning: Boolean = false,
    val progress: ScanProgress? = null,
    val report: DiagnosticsReport? = null,
    val error: String? = null,
    /** Фильтры экрана лога. */
    val logLevels: Set<LogLevel> = LogLevel.entries.toSet(),
    val logQuery: String = "",
    /** Сообщение для snackbar после экспорта. */
    val toast: String? = null,
) {
    val hasReport: Boolean get() = report != null

    val filteredLog: List<LogLine>
        get() {
            val all = report?.log ?: emptyList()
            val q = logQuery.trim()
            return all.filter { line ->
                line.level in logLevels &&
                    (
                        q.isEmpty() ||
                            line.message.contains(q, ignoreCase = true) ||
                            line.tag.contains(q, ignoreCase = true) ||
                            (line.detail?.contains(q, ignoreCase = true) == true)
                        )
            }
        }
}

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    private var job: Job? = null

    fun scan(config: EngineConfig = EngineConfig()) {
        if (_state.value.scanning) return
        job = viewModelScope.launch {
            _state.update { it.copy(scanning = true, error = null, progress = null, report = null) }
            runCatching {
                DetectorEngine(getApplication(), config).scan { p ->
                    _state.update { it.copy(progress = p) }
                }
            }.onSuccess { report ->
                _state.update { it.copy(scanning = false, report = report, progress = null) }
            }.onFailure { t ->
                _state.update {
                    it.copy(
                        scanning = false,
                        progress = null,
                        error = t.javaClass.simpleName + ": " + (t.message ?: "неизвестная ошибка"),
                    )
                }
            }
        }
    }

    fun cancel() {
        job?.cancel()
        _state.update { it.copy(scanning = false, progress = null) }
    }

    fun toggleLogLevel(level: LogLevel) = _state.update { s ->
        val next = if (level in s.logLevels) s.logLevels - level else s.logLevels + level
        s.copy(logLevels = if (next.isEmpty()) LogLevel.entries.toSet() else next)
    }

    fun setLogQuery(q: String) = _state.update { it.copy(logQuery = q) }

    fun onExport(result: ExportResult) = _state.update { it.copy(toast = result.message) }

    fun consumeToast() = _state.update { it.copy(toast = null) }
}
