package com.renwixx.trueadblocker.ui

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.renwixx.trueadblocker.BlockerApp
import com.renwixx.trueadblocker.data.AggregatedLog
import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.AppTrafficRow
import com.renwixx.trueadblocker.data.BackupInspection
import com.renwixx.trueadblocker.data.BackupSections
import com.renwixx.trueadblocker.data.BlocklistSource
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.HourlyBucket
import com.renwixx.trueadblocker.data.HttpsDomainGroup
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.data.RawLog
import com.renwixx.trueadblocker.data.TrackerParamStat
import com.renwixx.trueadblocker.data.escapeSqlLike
import com.renwixx.trueadblocker.engine.GitHubBlocklistExplorer
import com.renwixx.trueadblocker.engine.GitHubRawListCandidate
import com.renwixx.trueadblocker.engine.GitHubRepoItem
import com.renwixx.trueadblocker.net.AdBlockVpnService
import com.renwixx.trueadblocker.net.UpstreamProxy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

const val ACTIVITY_MODE_GROUPED = 0
const val ACTIVITY_MODE_HTTPS_URLS = 1
const val ACTIVITY_MODE_LIVE_RAW = 2

data class ActivityFilter(
	val query: String = "",
	val blockFilter: Int = -1,
	val isTopSort: Boolean = false,
	val viewMode: Int = ACTIVITY_MODE_GROUPED,
	val isHttpsLiveStream: Boolean = false,
	val appPkgFilter: String = "",
	val isShortenUrls: Boolean = true,
	val isGroupHttpsByDomain: Boolean = false,
	val selectedHttpsDomain: String = "",
	val responseTypeFilter: String = "",
	val customFileExt: String = "",
)

data class RuleFilter(
	val tabIndex: Int = 0,
	val query: String = "",
)

data class InstalledAppItem(
	val packageName: String,
	val label: String,
	val isSystem: Boolean,
)

@OptIn(ExperimentalCoroutinesApi::class)
class MainViewModel(application: Application) : AndroidViewModel(application) {
	private val _app = application as BlockerApp
	private val _db = _app.db
	private val _labelSp = _app.getSharedPreferences("trueblock_pkg_labels", Context.MODE_PRIVATE)
	val prefs = _app.prefs
	val engine = _app.engine
	val ca = _app.ca

	val config: StateFlow<AppConfig> = prefs.state
	val vpnState = AdBlockVpnService.runtime
	val engineStats = engine.stats
	val rulesRevision = engine.revision
	val caStatus = ca.status

	val totalRequests: StateFlow<Long> = _db.trafficDao().observeTotalRequests()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

	val totalBlocked: StateFlow<Long> = _db.trafficDao().observeTotalBlocked()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

	val totalAllowed: StateFlow<Long> = _db.trafficDao().observeTotalAllowed()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

	val totalCnameUncloaked: StateFlow<Long> = _db.trafficDao().observeTotalCnameUncloaked()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

	val totalTrackerParamsRemoved: StateFlow<Long> = _db.trackerParamDao().observeTotalRemoved()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

	val topTrackerParams: StateFlow<List<TrackerParamStat>> = _db.trackerParamDao().observeTopParams()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

	val blocklists: StateFlow<List<BlocklistSource>> = _db.blocklistDao().observeAll()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

	val loggedApps: StateFlow<List<String>> = _db.trafficDao().observeLoggedAppPackages()
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

	private val _activityFilter = MutableStateFlow(ActivityFilter())
	val activityFilter: StateFlow<ActivityFilter> = _activityFilter.asStateFlow()

	private val _ruleFilter = MutableStateFlow(RuleFilter())
	val ruleFilter: StateFlow<RuleFilter> = _ruleFilter.asStateFlow()

	private val _installedApps = MutableStateFlow<List<InstalledAppItem>>(emptyList())
	val installedApps: StateFlow<List<InstalledAppItem>> = _installedApps.asStateFlow()

	private val _installedPkgSet = MutableStateFlow<Set<String>>(emptySet())
	val installedPkgSet: StateFlow<Set<String>> = _installedPkgSet.asStateFlow()

	private val _isAppsLoading = MutableStateFlow(false)
	val isAppsLoading: StateFlow<Boolean> = _isAppsLoading.asStateFlow()

	private val _hourlyBuckets = MutableStateFlow<List<HourlyBucket>>(emptyList())
	val hourlyBuckets: StateFlow<List<HourlyBucket>> = _hourlyBuckets.asStateFlow()

	private val _topAppsBreakdown = MutableStateFlow<List<AppTrafficRow>>(emptyList())
	val topAppsBreakdown: StateFlow<List<AppTrafficRow>> = _topAppsBreakdown.asStateFlow()

	private val _testingProxyId = MutableStateFlow("")
	val testingProxyId: StateFlow<String> = _testingProxyId.asStateFlow()

	private val _githubRepos = MutableStateFlow<List<GitHubRepoItem>>(emptyList())
	val githubRepos: StateFlow<List<GitHubRepoItem>> = _githubRepos.asStateFlow()

	private val _isGithubLoading = MutableStateFlow(false)
	val isGithubLoading: StateFlow<Boolean> = _isGithubLoading.asStateFlow()

	private val _repoFiles = MutableStateFlow<List<GitHubRawListCandidate>>(emptyList())
	val repoFiles: StateFlow<List<GitHubRawListCandidate>> = _repoFiles.asStateFlow()

	private val _isRepoFilesLoading = MutableStateFlow(false)
	val isRepoFilesLoading: StateFlow<Boolean> = _isRepoFilesLoading.asStateFlow()

	private val _stagedImport = MutableStateFlow<Pair<String, BackupInspection>?>(null)
	val stagedImport: StateFlow<Pair<String, BackupInspection>?> = _stagedImport.asStateFlow()

	private val _toastChannel = Channel<String>(Channel.BUFFERED)
	val toastEvents: Flow<String> = _toastChannel.receiveAsFlow()

	private val _labelRevision = MutableStateFlow(0)
	val labelRevision: StateFlow<Int> = _labelRevision.asStateFlow()

	private val _iconCache = LruCache<String, ImageBitmap>(400)
	private val _iconCacheDir = File(_app.cacheDir, "app_icons").apply { mkdirs() }
	private val _fastLabels = ConcurrentHashMap<String, String>(128)
	private val _pendingLookups: MutableSet<String> = Collections.synchronizedSet(HashSet())

	private val _syncQueue = ConcurrentLinkedQueue<suspend () -> Unit>()
	private var _syncWorkerJob: Job? = null

	private val _pagingCfg = PagingConfig(
		pageSize = 50,
		prefetchDistance = 25,
		initialLoadSize = 60,
		enablePlaceholders = false,
	)

	init {
		for ((k, v) in _labelSp.all) {
			if (v is String)
				_fastLabels[k] = v
		}
		loadInstalledAppsIfNeeded()
	}

	val pagedAggregated: Flow<PagingData<AggregatedLog>> = _activityFilter
		.flatMapLatest { f ->
			val routeMode = if (f.viewMode == ACTIVITY_MODE_HTTPS_URLS) 1 else 0
			val safeQuery = escapeSqlLike(f.query.trim())
			val typeF = if (f.viewMode == ACTIVITY_MODE_HTTPS_URLS) f.responseTypeFilter else ""
			val extF = if (typeF == "file") escapeSqlLike(f.customFileExt.trim().lowercase().removePrefix(".")) else ""
			val hostF = if (f.viewMode == ACTIVITY_MODE_HTTPS_URLS && f.isGroupHttpsByDomain) f.selectedHttpsDomain else ""
			Pager(_pagingCfg) {
				if (f.isTopSort) {
					_db.trafficDao().pageTop(safeQuery, f.blockFilter, routeMode, f.appPkgFilter, typeF, extF, hostF)
				} else {
					_db.trafficDao().pageRecent(safeQuery, f.blockFilter, routeMode, f.appPkgFilter, typeF, extF, hostF)
				}
			}.flow
		}
		.cachedIn(viewModelScope)

	val pagedHttpsDomains: Flow<PagingData<HttpsDomainGroup>> = _activityFilter
		.flatMapLatest { f ->
			val safeQuery = escapeSqlLike(f.query.trim())
			val extF = if (f.responseTypeFilter == "file") escapeSqlLike(f.customFileExt.trim().lowercase().removePrefix(".")) else ""
			Pager(_pagingCfg) {
				_db.trafficDao().pageHttpsDomains(
					q = safeQuery,
					blockFilter = f.blockFilter,
					appPkg = f.appPkgFilter,
					typeFilter = f.responseTypeFilter,
					customExt = extF,
					isTopSort = if (f.isTopSort) 1 else 0,
				)
			}.flow
		}
		.cachedIn(viewModelScope)

	val pagedRaw: Flow<PagingData<RawLog>> = _activityFilter
		.flatMapLatest { f ->
			val routesFlag = if (f.viewMode == ACTIVITY_MODE_HTTPS_URLS) 1 else 0
			val safeQuery = escapeSqlLike(f.query.trim())
			val typeF = if (f.viewMode == ACTIVITY_MODE_HTTPS_URLS) f.responseTypeFilter else ""
			val extF = if (typeF == "file") escapeSqlLike(f.customFileExt.trim().lowercase().removePrefix(".")) else ""
			Pager(_pagingCfg) {
				_db.trafficDao().pageRaw(safeQuery, f.blockFilter, routesFlag, f.appPkgFilter, typeF, extF)
			}.flow
		}
		.cachedIn(viewModelScope)

	val pagedCustomRules: Flow<PagingData<CustomRule>> = _ruleFilter
		.flatMapLatest { rf ->
			val safeQuery = escapeSqlLike(rf.query.trim())
			Pager(_pagingCfg) {
				when (rf.tabIndex) {
					1 -> _db.ruleDao().pageRules(isAllow = false, isRoutesOnly = 0, q = safeQuery)
					2 -> _db.ruleDao().pageRules(isAllow = true, isRoutesOnly = 0, q = safeQuery)
					3 -> _db.ruleDao().pageRouteRules(q = safeQuery)
					else -> _db.ruleDao().pageAllRules(q = safeQuery)
				}
			}.flow
		}
		.cachedIn(viewModelScope)

	val customRulesSummary: StateFlow<Pair<Int, Int>> = _db.ruleDao().observeEnabled()
		.combine(engineStats) { rules, _ ->
			val blockedCount = rules.count { !it.isAllow }
			val allowedCount = rules.count { it.isAllow }
			blockedCount to allowedCount
		}
		.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0 to 0)

	fun postMessage(msg: String) {
		if (msg.isNotEmpty())
			_toastChannel.trySend(msg)
	}

	fun updateActivityFilter(transform: (ActivityFilter) -> ActivityFilter) {
		_activityFilter.value = transform(_activityFilter.value)
	}

	fun updateRuleFilter(transform: (RuleFilter) -> RuleFilter) {
		_ruleFilter.value = transform(_ruleFilter.value)
	}

	fun evaluateLive(target: String, isRoute: Boolean) = engine.evaluateTargetLive(target, isRoute)

	fun matchCustomFast(target: String, isRoute: Boolean) = engine.matchCustomOnly(target, isRoute)

	fun snoozeProtection(minutes: Int) {
		AdBlockVpnService.snooze(_app, minutes)
		postMessage("Protection snoozed for ${minutes}m")
	}

	fun resumeProtection() {
		AdBlockVpnService.resume(_app)
		postMessage("Protection resumed")
	}

	fun refreshAnalytics() {
		viewModelScope.launch(Dispatchers.IO) {
			val since = System.currentTimeMillis() - 24L * 3_600_000L
			_hourlyBuckets.value = _db.trafficDao().getHourlyActivity(since)
			_topAppsBreakdown.value = _db.trafficDao().getTopAppsBreakdown(30)
		}
	}

	fun clearTrackerParamStats() {
		viewModelScope.launch(Dispatchers.IO) {
			_db.trackerParamDao().clearAll()
			postMessage("Tracker parameter stats cleared")
		}
	}

	fun saveCustomRule(rule: CustomRule) {
		viewModelScope.launch(Dispatchers.IO) {
			_db.ruleDao().upsert(rule)
			engine.reloadCustomRulesOnly()
			postMessage(if (rule.isAllow) "Saved Allowed rule" else "Saved Blocked rule")
		}
	}

	fun quickToggleDomainRule(domainOrRoute: String, isMakeBlocked: Boolean) {
		viewModelScope.launch(Dispatchers.IO) {
			val clean = domainOrRoute.trim()
			val slashIdx = clean.indexOf('/')
			val isRoute = slashIdx >= 0
			val isLikelyTruncatedRoute = isRoute && (clean.length - slashIdx) >= 320
			val effectivePattern = if (isLikelyTruncatedRoute && !clean.endsWith('*')) "$clean*" else clean
			val effectiveMode = if (isLikelyTruncatedRoute) MODE_WILDCARD else MODE_EXACT

			_db.ruleDao().deleteByPattern(effectivePattern, !isMakeBlocked)
			_db.ruleDao().upsert(
				CustomRule(
					pattern = effectivePattern,
					matchMode = effectiveMode,
					isAllow = !isMakeBlocked,
					isRoute = isRoute,
					isEnabled = true,
				)
			)
			engine.reloadCustomRulesOnly()
			postMessage(if (isMakeBlocked) "Blocked: $effectivePattern" else "Allowed: $effectivePattern")
		}
	}

	fun toggleCustomRuleEnabled(rule: CustomRule) {
		viewModelScope.launch(Dispatchers.IO) {
			_db.ruleDao().setEnabled(rule.id, !rule.isEnabled)
			engine.reloadCustomRulesOnly()
		}
	}

	fun deleteCustomRule(id: Long) {
		viewModelScope.launch(Dispatchers.IO) {
			_db.ruleDao().deleteById(id)
			engine.reloadCustomRulesOnly()
		}
	}

	fun clearTrafficLogs() {
		viewModelScope.launch(Dispatchers.IO) {
			_app.traffic.clearAll()
			refreshAnalytics()
			postMessage("Traffic history cleared")
		}
	}

	@Synchronized
	private fun enqueueSyncTask(task: suspend () -> Unit) {
		_syncQueue.add(task)
		if (_syncWorkerJob?.isActive == true)
			return

		engine.resetCancelFlag()
		_syncWorkerJob = viewModelScope.launch(Dispatchers.IO) {
			while (true) {
				if (engine.isCancelRequested) {
					_syncQueue.clear()
					break
				}
				val next = _syncQueue.poll() ?: break
				try {
					next()
				} catch (_: CancellationException) {
					_syncQueue.clear()
					break
				}
			}
		}
	}

	@Synchronized
	fun cancelSync() {
		_syncQueue.clear()
		engine.cancelActiveSync()
		_syncWorkerJob?.cancel()
		_syncWorkerJob = null
		postMessage("Sync stopped — previous blocklists kept")
	}

	fun toggleBlocklist(src: BlocklistSource) {
		val nextEnabled = !src.isEnabled
		if (!nextEnabled) {
			viewModelScope.launch(Dispatchers.IO) {
				_db.blocklistDao().setEnabled(src.id, false)
				engine.reloadBlocklists()
			}
			return
		}

		viewModelScope.launch(Dispatchers.IO) {
			_db.blocklistDao().setEnabled(src.id, true)
		}
		enqueueSyncTask {
			val res = engine.syncBlocklist(src.copy(isEnabled = true))
			if (res.isFailure && res.exceptionOrNull() !is CancellationException)
				postMessage("Sync error (${src.title}): ${res.exceptionOrNull()?.message}")
		}
	}

	fun refreshSingleBlocklist(src: BlocklistSource) {
		enqueueSyncTask {
			val res = engine.syncBlocklist(src)
			if (res.isSuccess)
				postMessage("${src.title} updated")
			else if (res.exceptionOrNull() !is CancellationException)
				postMessage("Update failed: ${res.exceptionOrNull()?.message}")
		}
	}

	fun refreshAllBlocklists() {
		enqueueSyncTask {
			val isCompleted = engine.syncAllEnabled(isForce = true)
			if (isCompleted) {
				prefs.update { it.copy(lastAutoSyncMs = System.currentTimeMillis()) }
				postMessage("Enabled blocklists updated")
			}
		}
	}

	fun addCustomUrlBlocklist(title: String, url: String) {
		val cleanUrl = url.trim()
		val digest = MessageDigest.getInstance("SHA-256").digest(cleanUrl.toByteArray(Charsets.UTF_8))
		val hexId = digest.take(8).joinToString("") { "%02x".format(it) }
		val id = "custom_$hexId"
		val src = BlocklistSource(
			id = id,
			title = title.trim().ifEmpty { cleanUrl.substringAfterLast('/') },
			url = cleanUrl,
			category = "Custom URL",
			desc = cleanUrl,
			isHighlight = false,
			isEnabled = true,
		)
		viewModelScope.launch(Dispatchers.IO) {
			_db.blocklistDao().upsert(src)
		}
		enqueueSyncTask {
			val res = engine.syncBlocklist(src)
			if (res.isSuccess)
				postMessage("Added & synced ${src.title}")
			else if (res.exceptionOrNull() !is CancellationException)
				postMessage("Download failed: ${res.exceptionOrNull()?.message}")
		}
	}

	fun deleteCustomBlocklist(src: BlocklistSource) {
		viewModelScope.launch(Dispatchers.IO) {
			_db.blocklistDao().deleteById(src.id)
			engine.deleteCachedList(src.id)
			engine.reloadBlocklists()
		}
	}

	fun importLocalBlocklistContent(fileName: String, content: String) {
		viewModelScope.launch(Dispatchers.IO) {
			runCatching {
				val id = "local_${System.currentTimeMillis()}"
				engine.importLocalListFile(id, fileName.ifBlank { "Local Filter" }, content)
				postMessage("Imported filter list: $fileName")
			}.onFailure { e ->
				postMessage("Import failed: ${e.message}")
			}
		}
	}

	fun importLocalBlocklistStream(fileName: String, openStream: () -> InputStream?) {
		viewModelScope.launch(Dispatchers.IO) {
			runCatching {
				val stream = openStream() ?: throw IllegalStateException("Cannot read selected file")
				val id = "local_${System.currentTimeMillis()}"
				stream.use { inp ->
					engine.importLocalListStream(id, fileName.ifBlank { "Local Filter" }, inp)
				}
				postMessage("Imported filter list: $fileName")
			}.onFailure { e ->
				postMessage("Import failed: ${e.message}")
			}
		}
	}

	fun searchGitHubLists(query: String) {
		if (_isGithubLoading.value)
			return
		_isGithubLoading.value = true
		viewModelScope.launch {
			val res = GitHubBlocklistExplorer.searchRepos(query)
			res.onSuccess { _githubRepos.value = it }
				.onFailure { postMessage("GitHub search failed: ${it.message}") }
			_isGithubLoading.value = false
		}
	}

	fun inspectGitHubRepoFiles(repo: GitHubRepoItem) {
		_isRepoFilesLoading.value = true
		_repoFiles.value = emptyList()
		viewModelScope.launch {
			val res = GitHubBlocklistExplorer.listFilterFilesInRepo(repo)
			res.onSuccess { _repoFiles.value = it }
				.onFailure { postMessage("Failed to load repo tree: ${it.message}") }
			_isRepoFilesLoading.value = false
		}
	}

	fun clearInspectedRepoFiles() {
		_repoFiles.value = emptyList()
	}

	fun generateCa() {
		viewModelScope.launch(Dispatchers.Default) {
			ca.generateOrRegenerateCa()
			postMessage("Root CA generated — save & install .crt in Android Settings")
		}
	}

	fun appLabelFast(pkg: String): String {
		if (pkg.isEmpty() || pkg == "System DNS")
			return pkg
		_fastLabels[pkg]?.let { return it }

		if (_pendingLookups.add(pkg)) {
			viewModelScope.launch(Dispatchers.IO) {
				val pm = _app.packageManager
				val label = runCatching {
					val ai = pm.getApplicationInfo(pkg, 0)
					pm.getApplicationLabel(ai).toString()
				}.getOrDefault(pkg)
				val formatted = if (label == pkg) pkg else "$label ($pkg)"
				_fastLabels[pkg] = formatted
				_labelSp.edit().putString(pkg, formatted).apply()
				_pendingLookups.remove(pkg)
				_labelRevision.value = _labelRevision.value + 1
			}
		}

		return pkg
	}

	fun loadInstalledAppsIfNeeded() {
		if (_installedApps.value.isNotEmpty() || _isAppsLoading.value)
			return

		_isAppsLoading.value = true
		viewModelScope.launch(Dispatchers.IO) {
			val pm = _app.packageManager
			val pkgs = pm.getInstalledApplications(PackageManager.GET_META_DATA)
			val ownPkg = _app.packageName
			val list = ArrayList<InstalledAppItem>(pkgs.size)
			val pkgSet = HashSet<String>(pkgs.size)
			val spEditor = _labelSp.edit()

			for (ai in pkgs) {
				if (ai.packageName == ownPkg)
					continue
				pkgSet.add(ai.packageName)
				val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(ai.packageName)
				val formatted = if (label == ai.packageName) label else "$label (${ai.packageName})"
				_fastLabels[ai.packageName] = formatted
				spEditor.putString(ai.packageName, formatted)
				val isSys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
					(ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
				list.add(
					InstalledAppItem(
						packageName = ai.packageName,
						label = label,
						isSystem = isSys,
					)
				)
			}
			spEditor.apply()

			list.sortBy { it.label.lowercase() }
			_installedPkgSet.value = pkgSet
			_installedApps.value = list
			_labelRevision.value = _labelRevision.value + 1
			_isAppsLoading.value = false

			for (item in list) {
				if (!item.isSystem && _iconCache.get(item.packageName) == null)
					loadAndCacheIconSync(item.packageName)
			}
		}
	}

	fun getCachedAppIcon(packageName: String): ImageBitmap? = _iconCache.get(packageName)

	suspend fun getAppIcon(packageName: String): ImageBitmap? {
		_iconCache.get(packageName)?.let { return it }

		return withContext(Dispatchers.IO) {
			loadAndCacheIconSync(packageName)
		}
	}

	private fun loadAndCacheIconSync(packageName: String): ImageBitmap? {
		_iconCache.get(packageName)?.let { return it }
		if (packageName.isEmpty() || packageName == "System DNS")
			return null

		val safeName = packageName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
		val diskFile = File(_iconCacheDir, "$safeName.png")
		if (diskFile.exists()) {
			val decoded = runCatching { BitmapFactory.decodeFile(diskFile.absolutePath)?.asImageBitmap() }.getOrNull()
			if (decoded != null) {
				_iconCache.put(packageName, decoded)
				return decoded
			}
		}

		return runCatching {
			val d = _app.packageManager.getApplicationIcon(packageName)
			val w = d.intrinsicWidth.coerceIn(48, 96)
			val h = d.intrinsicHeight.coerceIn(48, 96)
			val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
			val canvas = Canvas(bmp)
			d.setBounds(0, 0, w, h)
			d.draw(canvas)
			runCatching {
				FileOutputStream(diskFile).use { fos ->
					bmp.compress(Bitmap.CompressFormat.PNG, 90, fos)
				}
			}
			bmp.asImageBitmap().also { _iconCache.put(packageName, it) }
		}.getOrNull()
	}

	fun toggleAppBypass(pkg: String) {
		var isAdded = false
		prefs.update { cur ->
			val next = cur.bypassedApps.toMutableSet()
			isAdded = next.add(pkg)
			if (!isAdded)
				next.remove(pkg)
			cur.copy(bypassedApps = next)
		}
		if (isAdded) {
			viewModelScope.launch(Dispatchers.IO) {
				runCatching { _db.trafficDao().deleteAllByApp(pkg) }
			}
		}
	}

	fun toggleAppHttpsInspect(pkg: String) {
		prefs.update { cur ->
			val next = cur.httpsInspectedApps.toMutableSet()
			if (!next.add(pkg))
				next.remove(pkg)
			cur.copy(httpsInspectedApps = next)
		}
	}

	fun toggleAppFirewallWifi(pkg: String) {
		prefs.update { cur ->
			val next = cur.firewallWifiApps.toMutableSet()
			if (!next.add(pkg))
				next.remove(pkg)
			cur.copy(firewallWifiApps = next)
		}
	}

	fun toggleAppFirewallMobile(pkg: String) {
		prefs.update { cur ->
			val next = cur.firewallMobileApps.toMutableSet()
			if (!next.add(pkg))
				next.remove(pkg)
			cur.copy(firewallMobileApps = next)
		}
	}

	fun toggleAppFirewallBoth(pkg: String) {
		prefs.update { cur ->
			val isCurrentlyBlocked = cur.firewallWifiApps.contains(pkg) || cur.firewallMobileApps.contains(pkg)
			val nextWifi = cur.firewallWifiApps.toMutableSet()
			val nextMob = cur.firewallMobileApps.toMutableSet()
			if (isCurrentlyBlocked) {
				nextWifi.remove(pkg)
				nextMob.remove(pkg)
			} else {
				nextWifi.add(pkg)
				nextMob.add(pkg)
			}
			cur.copy(firewallWifiApps = nextWifi, firewallMobileApps = nextMob)
		}
	}

	fun saveProxyProfile(profile: ProxyProfile) {
		prefs.update { cur ->
			val mutable = cur.proxies.toMutableList()
			val idx = mutable.indexOfFirst { it.id == profile.id }
			if (idx >= 0)
				mutable[idx] = profile
			else
				mutable.add(profile)
			cur.copy(proxies = mutable)
		}
		postMessage("Saved proxy: ${profile.name}")
	}

	fun deleteProxyProfile(id: String) {
		prefs.update { cur ->
			cur.copy(proxies = cur.proxies.filterNot { it.id == id })
		}
		postMessage("Proxy removed")
	}

	fun toggleProxyProfileEnabled(id: String) {
		prefs.update { cur ->
			val updated = cur.proxies.map { p ->
				if (p.id == id) p.copy(isEnabled = !p.isEnabled) else p
			}
			cur.copy(proxies = updated)
		}
	}

	fun toggleAppInPrimaryProxy(pkg: String): Boolean {
		val curProxies = prefs.state.value.proxies
		if (curProxies.isEmpty())
			return false

		val target = curProxies.firstOrNull { it.isEnabled && !it.isAllApps }
			?: curProxies.firstOrNull { !it.isAllApps }
			?: curProxies.first()

		val nextPkgs = target.appPackages.toMutableSet()
		val isAdded = nextPkgs.add(pkg)
		if (!isAdded)
			nextPkgs.remove(pkg)

		val updatedTarget = target.copy(isAllApps = false, appPackages = nextPkgs)
		prefs.update { cur ->
			cur.copy(proxies = cur.proxies.map { if (it.id == target.id) updatedTarget else it })
		}
		postMessage(if (isAdded) "Routed via ${target.name}" else "Removed from ${target.name}")

		return true
	}

	fun testProxyProfile(profile: ProxyProfile) {
		if (_testingProxyId.value.isNotEmpty())
			return

		_testingProxyId.value = profile.id
		viewModelScope.launch(Dispatchers.IO) {
			val protector: ((java.net.Socket) -> Boolean)? = AdBlockVpnService.instance?.let { svc ->
				{ sock -> svc.protect(sock) }
			}
			val res = UpstreamProxy.testProxyLatency(profile, protector)
			res.onSuccess { ms ->
				postMessage("${profile.name}: handshake OK (${ms} ms)")
			}.onFailure { e ->
				postMessage("${profile.name} failed: ${e.message ?: "Unreachable"}")
			}
			_testingProxyId.value = ""
		}
	}

	fun resetEngineTuning() {
		prefs.resetEngineTuningToDefaults()
		postMessage("Engine parameters restored to defaults")
	}

	suspend fun buildBackupJson(sections: BackupSections = BackupSections()): String {
		return withContext(Dispatchers.IO) {
			prefs.exportJson(_db, sections)
		}
	}

	fun stageBackupImport(text: String) {
		viewModelScope.launch(Dispatchers.IO) {
			runCatching {
				val info = prefs.inspectBackupContent(text)
				if (info.isPlainTextRules) {
					val rulesOnly = BackupSections(
						isGeneralConfig = false,
						isDnsAndNetworks = false,
						isAppsAndProxies = false,
						isCustomRules = true,
						isBlocklists = false,
					)
					prefs.importJson(text, _db, rulesOnly)
					engine.reloadCustomRulesOnly()
					postMessage("Imported ${info.customRulesCount} custom rule(s)")
				} else {
					_stagedImport.value = text to info
				}
			}.onFailure {
				postMessage("Import error: ${it.message}")
			}
		}
	}

	fun confirmStagedImport(sections: BackupSections) {
		val staged = _stagedImport.value ?: return
		_stagedImport.value = null
		if (!sections.hasAnySelected)
			return

		viewModelScope.launch(Dispatchers.IO) {
			runCatching {
				prefs.importJson(staged.first, _db, sections)
				engine.reloadFromDiskAndDb()
				postMessage("Selected backup sections imported")
				if (sections.isBlocklists)
					refreshAllBlocklists()
			}.onFailure {
				postMessage("Import error: ${it.message}")
			}
		}
	}

	fun dismissStagedImport() {
		_stagedImport.value = null
	}
}
