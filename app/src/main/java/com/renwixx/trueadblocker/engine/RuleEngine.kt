package com.renwixx.trueadblocker.engine

import android.content.Context
import com.renwixx.trueadblocker.BuildConfig
import com.renwixx.trueadblocker.data.AppDatabase
import com.renwixx.trueadblocker.data.BlocklistSource
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import com.renwixx.trueadblocker.data.sanitizeBlocklistId
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.IDN
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.TimeUnit

data class MatchVerdict(
	val isBlocked: Boolean,
	val matchedRule: String,
	val ruleSource: String = "",
) {
	fun summaryText(): String {
		if (ruleSource.isEmpty())
			return matchedRule
		if (matchedRule.isEmpty())
			return ruleSource

		return "$ruleSource • $matchedRule"
	}

	companion object {
		val ALLOWED_DEFAULT = MatchVerdict(false, "", "")
	}
}

class CompiledCustomRule(
	val raw: CustomRule,
	val normPattern: String,
	val isSchemeIncluded: Boolean,
	val compiledRegex: Regex?,
)

class FastRouteRule(
	val pattern: String,
	val isHostAnchored: Boolean,
	val isWebSocketOnly: Boolean,
	val sourceTitle: String,
	val displayRule: String,
	val typeMask: Int = 0,
	val partyMode: Int = 0,
) {
	fun matchesContext(isWebSocket: Boolean, reqTypeMask: Int, isThirdParty: Boolean?): Boolean {
		if (isWebSocketOnly && !isWebSocket)
			return false
		if (partyMode == PARTY_THIRD_ONLY && isThirdParty != true)
			return false
		if (partyMode == PARTY_FIRST_ONLY && isThirdParty != false)
			return false
		if (typeMask != 0) {
			val effectiveReqMask = if (isWebSocket) (reqTypeMask or RuleEngine.RES_WEBSOCKET) else reqTypeMask
			if ((effectiveReqMask and typeMask) == 0)
				return false
		}

		return true
	}

	companion object {
		const val PARTY_ANY = 0
		const val PARTY_THIRD_ONLY = 1
		const val PARTY_FIRST_ONLY = 2
	}
}

class CustomSnapshot(
	val allowExactDomains: Set<String> = emptySet(),
	val allowZones: Set<String> = emptySet(),
	val blockExactDomains: Set<String> = emptySet(),
	val blockZones: Set<String> = emptySet(),
	val allowComplex: List<CompiledCustomRule> = emptyList(),
	val blockComplex: List<CompiledCustomRule> = emptyList(),
	val domainCount: Int = 0,
	val routeCount: Int = 0,
)

class BlocklistSnapshot(
	val allowExact: Map<String, String> = emptyMap(),
	val allowZones: Map<String, String> = emptyMap(),
	val blockExact: Map<String, String> = emptyMap(),
	val blockZones: Map<String, String> = emptyMap(),
	val hostRouteAllows: Map<String, List<FastRouteRule>> = emptyMap(),
	val hostRouteBlocks: Map<String, List<FastRouteRule>> = emptyMap(),
	val tokenRouteAllows: Map<String, List<FastRouteRule>> = emptyMap(),
	val tokenRouteBlocks: Map<String, List<FastRouteRule>> = emptyMap(),
	val fallbackRouteBlocks: List<FastRouteRule> = emptyList(),
	val genericCosmeticSelectors: List<String> = emptyList(),
	val domainCosmeticMap: Map<String, List<String>> = emptyMap(),
	val domainCosmeticExceptions: Map<String, Set<String>> = emptyMap(),
	val removeParams: Set<String> = emptySet(),
	val domainCount: Int = 0,
	val routeCount: Int = 0,
	val cosmeticCount: Int = 0,
) {
	@Volatile
	var cachedGenericCss: Pair<Int, String> = 0 to ""
}

data class EngineStats(
	val totalDomainRules: Int = 0,
	val totalRouteRules: Int = 0,
	val totalCosmeticRules: Int = 0,
	val totalRemoveParamRules: Int = 0,
	val isSyncing: Boolean = false,
	val syncingListId: String = "",
)

class RuleEngine(
	private val _ctx: Context,
	private val _db: AppDatabase,
	private val _http: OkHttpClient = OkHttpClient.Builder()
		.connectTimeout(20, TimeUnit.SECONDS)
		.readTimeout(45, TimeUnit.SECONDS)
		.followRedirects(true)
		.build(),
) {
	@Volatile
	private var _customSnap = CustomSnapshot()

	@Volatile
	private var _listSnap = BlocklistSnapshot()

	@Volatile
	private var _activeCall: Call? = null

	@Volatile
	private var _isCancelRequested = false

	private val _listMutex = Mutex()
	private val _customMutex = Mutex()
	private val _syncOpMutex = Mutex()

	private val _stats = MutableStateFlow(EngineStats())
	val stats: StateFlow<EngineStats> = _stats.asStateFlow()

	private val _revision = MutableStateFlow(0L)
	val revision: StateFlow<Long> = _revision.asStateFlow()

	private val _cacheDir = File(_ctx.filesDir, "blocklists").apply { mkdirs() }
	private val _binCacheFile = File(_cacheDir, "compiled_lists_v3.bin")

	fun listRemoveParams(): Set<String> = _listSnap.removeParams

	fun cosmeticCssForHost(rawHost: String, maxGeneric: Int, customCss: String): String {
		val host = normalizeHost(rawHost)
		val ls = _listSnap
		val cap = maxGeneric.coerceIn(0, MAX_GENERIC_COSMETICS)

		val excluded = HashSet<String>()
		if (host.isNotEmpty() && ls.domainCosmeticExceptions.isNotEmpty()) {
			ls.domainCosmeticExceptions[host]?.let { excluded.addAll(it) }
			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				val parent = host.substring(dot + 1)
				ls.domainCosmeticExceptions[parent]?.let { excluded.addAll(it) }
				dot = host.indexOf('.', dot + 1)
			}
		}

		val genericCss = if (cap > 0 && ls.genericCosmeticSelectors.isNotEmpty()) {
			val slice = ls.genericCosmeticSelectors.take(cap)
			if (excluded.isEmpty()) {
				val cur = ls.cachedGenericCss
				if (cur.first == cap && cur.second.isNotEmpty()) {
					cur.second
				} else {
					val built = "${slice.joinToString(",")}{display:none!important}"
					ls.cachedGenericCss = cap to built
					built
				}
			} else {
				val filtered = slice.filterNot { excluded.contains(it) }
				if (filtered.isEmpty()) "" else "${filtered.joinToString(",")}{display:none!important}"
			}
		} else {
			""
		}

		val domainSelectors = ArrayList<String>(16)
		if (host.isNotEmpty() && ls.domainCosmeticMap.isNotEmpty()) {
			ls.domainCosmeticMap[host]?.let { sels ->
				for (s in sels) {
					if (!excluded.contains(s))
						domainSelectors.add(s)
				}
			}
			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				val parent = host.substring(dot + 1)
				ls.domainCosmeticMap[parent]?.let { sels ->
					for (s in sels) {
						if (!excluded.contains(s))
							domainSelectors.add(s)
					}
				}
				dot = host.indexOf('.', dot + 1)
			}
		}

		val domainCss = if (domainSelectors.isNotEmpty()) {
			"${domainSelectors.distinct().joinToString(",")}{display:none!important}"
		} else {
			""
		}

		val extra = customCss.trim()
		if (genericCss.isEmpty() && domainCss.isEmpty() && extra.isEmpty())
			return ""

		return buildString(genericCss.length + domainCss.length + extra.length + 4) {
			append(genericCss)
			append(domainCss)
			if (extra.isNotEmpty())
				append(extra)
		}
	}

	fun cancelActiveSync() {
		_isCancelRequested = true
		_activeCall?.cancel()
		_activeCall = null
		_stats.value = _stats.value.copy(isSyncing = false, syncingListId = "")
	}

	fun resetCancelFlag() {
		_isCancelRequested = false
	}

	val isCancelRequested: Boolean
		get() = _isCancelRequested

	fun matchDns(rawHost: String): MatchVerdict {
		val host = normalizeHost(rawHost)
		if (host.isEmpty())
			return MatchVerdict.ALLOWED_DEFAULT

		val cs = _customSnap
		if (cs.allowExactDomains.contains(host))
			return MatchVerdict(false, "@@$host", "Custom Rule (Allowed • Exact)")
		val customAllowZone = matchesZoneSet(host, cs.allowZones)
		if (customAllowZone != null)
			return MatchVerdict(false, "@@*.$customAllowZone", "Custom Rule (Allowed • Wildcard)")
		for (r in cs.allowComplex) {
			if (!r.raw.isRoute && matchesCustomDomain(host, r))
				return MatchVerdict(false, "@@${r.raw.pattern}", formatCustomSource(r.raw))
		}

		if (cs.blockExactDomains.contains(host))
			return MatchVerdict(true, host, "Custom Rule (Blocked • Exact)")
		val customZone = matchesZoneSet(host, cs.blockZones)
		if (customZone != null)
			return MatchVerdict(true, "*.$customZone", "Custom Rule (Blocked • Wildcard)")
		for (r in cs.blockComplex) {
			if (!r.raw.isRoute && matchesCustomDomain(host, r))
				return MatchVerdict(true, r.raw.pattern, formatCustomSource(r.raw))
		}

		val ls = _listSnap
		ls.allowExact[host]?.let { src ->
			return MatchVerdict(false, "@@$host", src)
		}
		matchesZoneMap(host, ls.allowZones)?.let { (zone, src) ->
			return MatchVerdict(false, "@@||$zone^", src)
		}

		ls.blockExact[host]?.let { src ->
			return MatchVerdict(true, host, src)
		}
		matchesZoneMap(host, ls.blockZones)?.let { (zone, src) ->
			return MatchVerdict(true, "||$zone^", src)
		}

		return MatchVerdict.ALLOWED_DEFAULT
	}

	fun matchUrl(
		fullUrl: String,
		rawHost: String,
		pathAndQuery: String,
		isWebSocket: Boolean,
		reqTypeMask: Int = 0,
		isThirdParty: Boolean? = null,
	): MatchVerdict {
		val host = normalizeHost(rawHost)
		if (host.isEmpty())
			return MatchVerdict.ALLOWED_DEFAULT

		val path = if (pathAndQuery.isEmpty()) "/" else if (pathAndQuery.startsWith('/')) pathAndQuery else "/$pathAndQuery"
		val hostWithPath = "$host$path"

		val cs = _customSnap
		if (cs.allowExactDomains.contains(host))
			return MatchVerdict(false, "@@$host", "Custom Rule (Allowed • Exact)")
		val caz = matchesZoneSet(host, cs.allowZones)
		if (caz != null)
			return MatchVerdict(false, "@@*.$caz", "Custom Rule (Allowed • Wildcard)")
		for (r in cs.allowComplex) {
			if (matchesCustomFull(fullUrl, host, hostWithPath, r))
				return MatchVerdict(false, "@@${r.raw.pattern}", formatCustomSource(r.raw))
		}

		if (cs.blockExactDomains.contains(host))
			return MatchVerdict(true, host, "Custom Rule (Blocked • Exact)")
		val cz = matchesZoneSet(host, cs.blockZones)
		if (cz != null)
			return MatchVerdict(true, "*.$cz", "Custom Rule (Blocked • Wildcard)")
		for (r in cs.blockComplex) {
			if (matchesCustomFull(fullUrl, host, hostWithPath, r))
				return MatchVerdict(true, r.raw.pattern, formatCustomSource(r.raw))
		}

		val ls = _listSnap
		ls.allowExact[host]?.let { src ->
			return MatchVerdict(false, "@@$host", src)
		}
		matchesZoneMap(host, ls.allowZones)?.let { (zone, src) ->
			return MatchVerdict(false, "@@||$zone^", src)
		}
		matchesHostRouteMap(host, hostWithPath, isWebSocket, reqTypeMask, isThirdParty, ls.hostRouteAllows)?.let { r ->
			return MatchVerdict(false, "@@${r.displayRule}", r.sourceTitle)
		}
		matchesTokenRoutes(fullUrl, hostWithPath, isWebSocket, reqTypeMask, isThirdParty, ls.tokenRouteAllows)?.let { r ->
			return MatchVerdict(false, "@@${r.displayRule}", r.sourceTitle)
		}

		ls.blockExact[host]?.let { src ->
			return MatchVerdict(true, host, src)
		}
		matchesZoneMap(host, ls.blockZones)?.let { (zone, src) ->
			return MatchVerdict(true, "||$zone^", src)
		}

		val hostRouteHit = matchesHostRouteMap(host, hostWithPath, isWebSocket, reqTypeMask, isThirdParty, ls.hostRouteBlocks)
		if (hostRouteHit != null)
			return MatchVerdict(true, hostRouteHit.displayRule, hostRouteHit.sourceTitle)

		val tokenHit = matchesTokenRoutes(fullUrl, hostWithPath, isWebSocket, reqTypeMask, isThirdParty, ls.tokenRouteBlocks)
		if (tokenHit != null)
			return MatchVerdict(true, tokenHit.displayRule, tokenHit.sourceTitle)

		for (fb in ls.fallbackRouteBlocks) {
			if (!fb.matchesContext(isWebSocket, reqTypeMask, isThirdParty))
				continue
			val target = if (fb.isHostAnchored) hostWithPath else fullUrl
			if (adblockWildcardMatch(target, fb.pattern))
				return MatchVerdict(true, fb.displayRule, fb.sourceTitle)
		}

		return MatchVerdict.ALLOWED_DEFAULT
	}

	fun matchCustomOnly(target: String, isRoute: Boolean): MatchVerdict? {
		val cs = _customSnap
		if (
			cs.allowExactDomains.isEmpty() &&
			cs.allowZones.isEmpty() &&
			cs.blockExactDomains.isEmpty() &&
			cs.blockZones.isEmpty() &&
			cs.allowComplex.isEmpty() &&
			cs.blockComplex.isEmpty()
		) {
			return null
		}

		val slash = target.indexOf('/')
		val rawHost = if (slash >= 0) target.substring(0, slash) else target
		val host = normalizeHost(rawHost)
		if (host.isEmpty())
			return null

		if (cs.allowExactDomains.contains(host))
			return MatchVerdict(false, "@@$host", "Custom Rule (Allowed • Exact)")
		val az = matchesZoneSet(host, cs.allowZones)
		if (az != null)
			return MatchVerdict(false, "@@*.$az", "Custom Rule (Allowed • Wildcard)")

		val hasPath = isRoute || slash >= 0
		val path = if (slash >= 0) target.substring(slash) else "/"
		val hostWithPath = "$host$path"
		val fullUrl = "https://$hostWithPath"

		for (r in cs.allowComplex) {
			val hit = if (hasPath) matchesCustomFull(fullUrl, host, hostWithPath, r) else (!r.raw.isRoute && matchesCustomDomain(host, r))
			if (hit)
				return MatchVerdict(false, "@@${r.raw.pattern}", formatCustomSource(r.raw))
		}

		if (cs.blockExactDomains.contains(host))
			return MatchVerdict(true, host, "Custom Rule (Blocked • Exact)")
		val bz = matchesZoneSet(host, cs.blockZones)
		if (bz != null)
			return MatchVerdict(true, "*.$bz", "Custom Rule (Blocked • Wildcard)")

		for (r in cs.blockComplex) {
			val hit = if (hasPath) matchesCustomFull(fullUrl, host, hostWithPath, r) else (!r.raw.isRoute && matchesCustomDomain(host, r))
			if (hit)
				return MatchVerdict(true, r.raw.pattern, formatCustomSource(r.raw))
		}

		return null
	}

	fun evaluateTargetLive(target: String, isRoute: Boolean): MatchVerdict {
		if (isRoute || target.contains('/')) {
			val slash = target.indexOf('/')
			val host = if (slash > 0) target.substring(0, slash) else target
			val path = if (slash > 0) target.substring(slash) else "/"
			return matchUrl("https://$target", host, path, isWebSocket = false, reqTypeMask = RES_ALL_MASK, isThirdParty = true)
		}

		return matchDns(target)
	}

	private fun safeCacheFile(id: String, ext: String = "txt"): File? {
		val cleanId = sanitizeBlocklistId(id)
		if (cleanId.isEmpty())
			return null
		val f = File(_cacheDir, "$cleanId.$ext")
		val ok = runCatching { f.canonicalFile.parentFile == _cacheDir.canonicalFile }.getOrDefault(false)

		return if (ok) f else null
	}

	suspend fun areAllEnabledCached(): Boolean = withContext(Dispatchers.IO) {
		val enabled = _db.blocklistDao().getEnabled()
		enabled.all { src ->
			val f = safeCacheFile(src.id)
			f != null && f.exists() && f.length() > 0L
		}
	}

	suspend fun ensureCatalogSeeded() {
		withContext(Dispatchers.IO) {
			File(_cacheDir, "compiled_lists_v1.bin").delete()
			File(_cacheDir, "compiled_lists_v2.bin").delete()
			_db.blocklistDao().deleteByIds(REMOVED_BLOCKLIST_IDS)
			for (oldId in REMOVED_BLOCKLIST_IDS)
				safeCacheFile(oldId)?.delete()
			_db.blocklistDao().insertIgnore(BUILTIN_BLOCKLISTS)
		}
	}

	suspend fun reloadCustomRulesOnly() {
		_customMutex.withLock {
			withContext(Dispatchers.Default) {
				val customRules = _db.ruleDao().getEnabled()
				val built = buildCustomSnapshot(customRules)
				_customSnap = built
				publishTotals()
			}
		}
	}

	suspend fun reloadBlocklists() {
		_listMutex.withLock {
			withContext(Dispatchers.IO) {
				val enabledLists = _db.blocklistDao().getEnabled()
				val fp = computeListFingerprint(enabledLists)
				val cached = loadBinarySnapshotIfValid(fp)
				if (cached != null) {
					_listSnap = cached
					publishTotals()
					return@withContext
				}

				val built = withContext(Dispatchers.Default) {
					buildBlocklistSnapshot(enabledLists)
				}
				_listSnap = built
				publishTotals()
				saveBinarySnapshot(fp, built)
			}
		}
	}

	suspend fun reloadFromDiskAndDb() {
		reloadCustomRulesOnly()
		reloadBlocklists()
	}

	private fun publishTotals() {
		val cs = _customSnap
		val ls = _listSnap
		_stats.value = _stats.value.copy(
			totalDomainRules = cs.domainCount + ls.domainCount,
			totalRouteRules = cs.routeCount + ls.routeCount,
			totalCosmeticRules = ls.cosmeticCount,
			totalRemoveParamRules = ls.removeParams.size,
		)
		_revision.value = _revision.value + 1L
	}

	suspend fun syncBlocklist(src: BlocklistSource, isReloadAfter: Boolean = true): Result<Pair<Int, Int>> {
		return _syncOpMutex.withLock {
			syncBlocklistUnlocked(src, isReloadAfter)
		}
	}

	private suspend fun syncBlocklistUnlocked(src: BlocklistSource, isReloadAfter: Boolean): Result<Pair<Int, Int>> = withContext(Dispatchers.IO) {
		if (_isCancelRequested)
			return@withContext Result.failure(CancellationException("Sync stopped"))

		val tmpFile = safeCacheFile(src.id, "tmp") ?: return@withContext Result.failure(IllegalArgumentException("Invalid blocklist ID"))
		val dstFile = safeCacheFile(src.id, "txt") ?: return@withContext Result.failure(IllegalArgumentException("Invalid blocklist ID"))

		_stats.value = _stats.value.copy(isSyncing = true, syncingListId = src.id)

		try {
			if (src.url.startsWith("file://")) {
				val local = File(src.url.removePrefix("file://"))
				val isInsideCache = runCatching {
					local.canonicalPath.startsWith(_cacheDir.canonicalPath + File.separator)
				}.getOrDefault(false)
				if (!isInsideCache || !local.exists())
					throw IllegalStateException("Local list file missing")
				if (local.canonicalFile != dstFile.canonicalFile)
					local.copyTo(tmpFile, overwrite = true)
				else
					dstFile.copyTo(tmpFile, overwrite = true)
			} else {
				val req = Request.Builder()
					.url(src.url)
					.header("User-Agent", "TrueBlock/${BuildConfig.VERSION_NAME}")
					.build()
				val call = _http.newCall(req)
				_activeCall = call
				call.execute().use { resp ->
					if (!resp.isSuccessful)
						throw IllegalStateException("HTTP ${resp.code}")
					val body = resp.body ?: throw IllegalStateException("Empty body")
					val declaredLen = body.contentLength()
					if (declaredLen > MAX_BLOCKLIST_BYTES)
						throw IllegalStateException("List exceeds 150 MB limit")

					body.byteStream().use { input ->
						tmpFile.outputStream().buffered(32 * 1024).use { output ->
							val buf = ByteArray(32 * 1024)
							var written = 0L
							while (true) {
								if (_isCancelRequested || call.isCanceled())
									throw CancellationException("Sync stopped")
								val n = input.read(buf)
								if (n < 0)
									break
								written += n
								if (written > MAX_BLOCKLIST_BYTES)
									throw IllegalStateException("List exceeds 150 MB limit")
								output.write(buf, 0, n)
							}
						}
					}
				}
			}

			if (_isCancelRequested)
				throw CancellationException("Sync stopped")

			val counts = countRulesInFile(tmpFile)
			if (_isCancelRequested)
				throw CancellationException("Sync stopped")

			replaceFileAtomically(tmpFile, dstFile)

			val now = System.currentTimeMillis()
			_db.blocklistDao().updateStats(src.id, counts.first, counts.second, now, "")
			if (isReloadAfter && !_isCancelRequested)
				reloadBlocklists()

			Result.success(counts)
		} catch (ce: CancellationException) {
			tmpFile.delete()
			Result.failure(ce)
		} catch (e: Throwable) {
			tmpFile.delete()
			if (_isCancelRequested || _activeCall?.isCanceled() == true) {
				Result.failure(CancellationException("Sync stopped"))
			} else {
				val msg = e.message ?: "Download failed"
				_db.blocklistDao().updateStats(src.id, src.ruleCount, src.routeRuleCount, src.lastUpdated, msg)
				Result.failure(e)
			}
		} finally {
			_activeCall = null
			if (!_isCancelRequested)
				_stats.value = _stats.value.copy(isSyncing = false, syncingListId = "")
		}
	}

	suspend fun syncAllEnabled(isForce: Boolean = false): Boolean {
		return _syncOpMutex.withLock {
			_isCancelRequested = false
			val enabled = withContext(Dispatchers.IO) { _db.blocklistDao().getEnabled() }
			var isAnyUpdated = false

			try {
				for (src in enabled) {
					if (_isCancelRequested)
						break
					val cacheFile = safeCacheFile(src.id)
					if (cacheFile == null)
						continue
					if (isForce || !cacheFile.exists() || cacheFile.length() == 0L) {
						val res = syncBlocklistUnlocked(src, isReloadAfter = false)
						if (res.isSuccess)
							isAnyUpdated = true
						if (_isCancelRequested)
							break
					}
				}
				if (isAnyUpdated && !_isCancelRequested)
					reloadBlocklists()
			} finally {
				_stats.value = _stats.value.copy(isSyncing = false, syncingListId = "")
			}

			!_isCancelRequested
		}
	}

	suspend fun importLocalListFile(id: String, title: String, content: String) {
		importLocalListStream(id, title, content.byteInputStream(Charsets.UTF_8))
	}

	suspend fun importLocalListStream(id: String, title: String, input: InputStream) {
		val safeId = sanitizeBlocklistId(id).ifEmpty { "local_${System.currentTimeMillis()}" }
		withContext(Dispatchers.IO) {
			val dstFile = safeCacheFile(safeId) ?: throw IllegalArgumentException("Invalid local list ID")
			val tmpFile = safeCacheFile(safeId, "tmp") ?: throw IllegalArgumentException("Invalid local list ID")
			try {
				tmpFile.outputStream().buffered(32 * 1024).use { out ->
					val buf = ByteArray(32 * 1024)
					var total = 0L
					while (true) {
						val n = input.read(buf)
						if (n < 0)
							break
						total += n
						if (total > MAX_BLOCKLIST_BYTES)
							throw IllegalStateException("File exceeds 150 MB limit")
						out.write(buf, 0, n)
					}
				}
				replaceFileAtomically(tmpFile, dstFile)
			} catch (e: Throwable) {
				tmpFile.delete()
				throw e
			}
			val counts = countRulesInFile(dstFile)
			val src = BlocklistSource(
				id = safeId,
				title = title,
				url = "file://${dstFile.absolutePath}",
				category = "Custom",
				desc = "Imported local filter file",
				isHighlight = false,
				isEnabled = true,
				ruleCount = counts.first,
				routeRuleCount = counts.second,
				lastUpdated = System.currentTimeMillis(),
			)
			_db.blocklistDao().upsert(src)
		}
		reloadBlocklists()
	}

	fun deleteCachedList(id: String) {
		safeCacheFile(id)?.delete()
	}

	private fun replaceFileAtomically(tmp: File, dst: File) {
		val moved = runCatching {
			Files.move(tmp.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING)
			true
		}.getOrDefault(false)
		if (!moved) {
			if (dst.exists())
				dst.delete()
			tmp.renameTo(dst)
		}
	}

	private fun computeListFingerprint(enabledLists: List<BlocklistSource>): String {
		if (enabledLists.isEmpty())
			return "empty"

		return enabledLists
			.sortedBy { it.id }
			.joinToString("|") { src ->
				val f = safeCacheFile(src.id)
				val len = f?.length() ?: 0L
				val mod = f?.lastModified() ?: 0L
				"${src.id}:${src.title}:${len}_$mod"
			}
	}

	private fun saveBinarySnapshot(fp: String, snap: BlocklistSnapshot) {
		val tmp = File(_cacheDir, "compiled_lists_v3.tmp")
		runCatching {
			val poolList = ArrayList<String>(64)
			val poolIdx = HashMap<String, Int>(64)
			fun idxOf(s: String): Int {
				return poolIdx.getOrPut(s) {
					poolList.add(s)
					poolList.size - 1
				}
			}

			for (v in snap.allowExact.values) idxOf(v)
			for (v in snap.allowZones.values) idxOf(v)
			for (v in snap.blockExact.values) idxOf(v)
			for (v in snap.blockZones.values) idxOf(v)
			for (list in snap.hostRouteAllows.values) for (r in list) idxOf(r.sourceTitle)
			for (list in snap.hostRouteBlocks.values) for (r in list) idxOf(r.sourceTitle)
			for (list in snap.tokenRouteAllows.values) for (r in list) idxOf(r.sourceTitle)
			for (list in snap.tokenRouteBlocks.values) for (r in list) idxOf(r.sourceTitle)
			for (r in snap.fallbackRouteBlocks) idxOf(r.sourceTitle)

			DataOutputStream(BufferedOutputStream(tmp.outputStream(), 64 * 1024)).use { out ->
				out.writeInt(BIN_MAGIC)
				out.writeInt(BIN_VERSION)
				writeLongString(out, fp)

				out.writeInt(poolList.size)
				for (s in poolList)
					out.writeUTF(s)

				fun writeDomainMap(m: Map<String, String>) {
					out.writeInt(m.size)
					for ((k, v) in m) {
						out.writeUTF(k)
						out.writeInt(poolIdx[v] ?: 0)
					}
				}

				fun writeRouteList(list: List<FastRouteRule>) {
					out.writeInt(list.size)
					for (r in list) {
						out.writeUTF(r.pattern)
						out.writeBoolean(r.isHostAnchored)
						out.writeBoolean(r.isWebSocketOnly)
						out.writeInt(poolIdx[r.sourceTitle] ?: 0)
						out.writeUTF(r.displayRule)
						out.writeInt(r.typeMask)
						out.writeByte(r.partyMode)
					}
				}

				fun writeRouteMap(m: Map<String, List<FastRouteRule>>) {
					out.writeInt(m.size)
					for ((k, list) in m) {
						out.writeUTF(k)
						writeRouteList(list)
					}
				}

				writeDomainMap(snap.allowExact)
				writeDomainMap(snap.allowZones)
				writeDomainMap(snap.blockExact)
				writeDomainMap(snap.blockZones)
				writeRouteMap(snap.hostRouteAllows)
				writeRouteMap(snap.hostRouteBlocks)
				writeRouteMap(snap.tokenRouteAllows)
				writeRouteMap(snap.tokenRouteBlocks)
				writeRouteList(snap.fallbackRouteBlocks)

				out.writeInt(snap.genericCosmeticSelectors.size)
				for (sel in snap.genericCosmeticSelectors)
					out.writeUTF(sel)

				out.writeInt(snap.domainCosmeticMap.size)
				for ((dom, sels) in snap.domainCosmeticMap) {
					out.writeUTF(dom)
					out.writeInt(sels.size)
					for (sel in sels)
						out.writeUTF(sel)
				}

				out.writeInt(snap.domainCosmeticExceptions.size)
				for ((dom, sels) in snap.domainCosmeticExceptions) {
					out.writeUTF(dom)
					out.writeInt(sels.size)
					for (sel in sels)
						out.writeUTF(sel)
				}

				out.writeInt(snap.removeParams.size)
				for (rp in snap.removeParams)
					out.writeUTF(rp)

				out.writeInt(snap.domainCount)
				out.writeInt(snap.routeCount)
				out.writeInt(snap.cosmeticCount)
			}

			replaceFileAtomically(tmp, _binCacheFile)
		}.onFailure {
			tmp.delete()
		}
	}

	private fun loadBinarySnapshotIfValid(expectedFp: String): BlocklistSnapshot? {
		if (!_binCacheFile.exists())
			return null

		return runCatching {
			DataInputStream(BufferedInputStream(_binCacheFile.inputStream(), 64 * 1024)).use { inp ->
				if (inp.readInt() != BIN_MAGIC)
					return null
				if (inp.readInt() != BIN_VERSION)
					return null
				if (readLongString(inp) != expectedFp)
					return null

				val poolSize = inp.readInt()
				val pool = Array(poolSize) { inp.readUTF() }

				fun readDomainMap(): Map<String, String> {
					val sz = inp.readInt()
					if (sz == 0)
						return emptyMap()
					val map = HashMap<String, String>((sz * 4 / 3) + 4)
					repeat(sz) {
						val k = inp.readUTF()
						val idx = inp.readInt()
						map[k] = pool.getOrElse(idx) { "" }
					}
					return map
				}

				fun readRouteList(): List<FastRouteRule> {
					val sz = inp.readInt()
					if (sz == 0)
						return emptyList()
					val list = ArrayList<FastRouteRule>(sz)
					repeat(sz) {
						val pat = inp.readUTF()
						val isHost = inp.readBoolean()
						val isWs = inp.readBoolean()
						val srcIdx = inp.readInt()
						val disp = inp.readUTF()
						val tMask = inp.readInt()
						val pMode = inp.readByte().toInt()
						list.add(FastRouteRule(pat, isHost, isWs, pool.getOrElse(srcIdx) { "" }, disp, tMask, pMode))
					}
					return list
				}

				fun readRouteMap(): Map<String, List<FastRouteRule>> {
					val sz = inp.readInt()
					if (sz == 0)
						return emptyMap()
					val map = HashMap<String, List<FastRouteRule>>((sz * 4 / 3) + 4)
					repeat(sz) {
						val k = inp.readUTF()
						map[k] = readRouteList()
					}
					return map
				}

				val allowExact = readDomainMap()
				val allowZones = readDomainMap()
				val blockExact = readDomainMap()
				val blockZones = readDomainMap()
				val hostRouteAllows = readRouteMap()
				val hostRouteBlocks = readRouteMap()
				val tokenRouteAllows = readRouteMap()
				val tokenRouteBlocks = readRouteMap()
				val fallbackRoutes = readRouteList()

				val genCosSz = inp.readInt()
				val genCos = if (genCosSz == 0) emptyList() else List(genCosSz) { inp.readUTF() }

				val domCosSz = inp.readInt()
				val domCos = if (domCosSz == 0) {
					emptyMap()
				} else {
					val map = HashMap<String, List<String>>((domCosSz * 4 / 3) + 4)
					repeat(domCosSz) {
						val dom = inp.readUTF()
						val cnt = inp.readInt()
						map[dom] = List(cnt) { inp.readUTF() }
					}
					map
				}

				val domExSz = inp.readInt()
				val domEx = if (domExSz == 0) {
					emptyMap()
				} else {
					val map = HashMap<String, Set<String>>((domExSz * 4 / 3) + 4)
					repeat(domExSz) {
						val dom = inp.readUTF()
						val cnt = inp.readInt()
						val set = HashSet<String>((cnt * 4 / 3) + 2)
						repeat(cnt) { set.add(inp.readUTF()) }
						map[dom] = set
					}
					map
				}

				val rpSz = inp.readInt()
				val rps = if (rpSz == 0) {
					emptySet()
				} else {
					val set = HashSet<String>((rpSz * 4 / 3) + 4)
					repeat(rpSz) { set.add(inp.readUTF()) }
					set
				}

				val domCnt = inp.readInt()
				val rtCnt = inp.readInt()
				val cosCnt = inp.readInt()

				BlocklistSnapshot(
					allowExact = allowExact,
					allowZones = allowZones,
					blockExact = blockExact,
					blockZones = blockZones,
					hostRouteAllows = hostRouteAllows,
					hostRouteBlocks = hostRouteBlocks,
					tokenRouteAllows = tokenRouteAllows,
					tokenRouteBlocks = tokenRouteBlocks,
					fallbackRouteBlocks = fallbackRoutes,
					genericCosmeticSelectors = genCos,
					domainCosmeticMap = domCos,
					domainCosmeticExceptions = domEx,
					removeParams = rps,
					domainCount = domCnt,
					routeCount = rtCnt,
					cosmeticCount = cosCnt,
				)
			}
		}.getOrNull()
	}

	private fun writeLongString(out: DataOutputStream, s: String) {
		val bytes = s.toByteArray(Charsets.UTF_8)
		out.writeInt(bytes.size)
		out.write(bytes)
	}

	private fun readLongString(inp: DataInputStream): String {
		val len = inp.readInt()
		if (len <= 0)
			return ""
		if (len > 4 * 1024 * 1024)
			throw IllegalStateException("Corrupt header length")
		val bytes = ByteArray(len)
		inp.readFully(bytes)

		return String(bytes, Charsets.UTF_8)
	}

	private fun countRulesInFile(file: File): Pair<Int, Int> {
		val allowExact = HashMap<String, String>(256)
		val allowZones = HashMap<String, String>(512)
		val blockExact = HashMap<String, String>(4096)
		val blockZones = HashMap<String, String>(8192)
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>(128)
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>(512)
		val tokAllows = HashMap<String, MutableList<FastRouteRule>>(128)
		val tokBlocks = HashMap<String, MutableList<FastRouteRule>>(512)
		val fallback = ArrayList<FastRouteRule>(32)
		val seenRoutes = HashSet<String>(1024)
		val pool = HashMap<String, String>(8)

		BufferedReader(InputStreamReader(file.inputStream(), Charsets.UTF_8), 32 * 1024).use { reader ->
			while (true) {
				val line = reader.readLine() ?: break
				parseLineIntoSets(
					rawLine = line,
					listTitle = "src",
					allowExact = allowExact,
					allowZones = allowZones,
					blockExact = blockExact,
					blockZones = blockZones,
					hostRouteAllows = hostAllows,
					hostRouteBlocks = hostBlocks,
					tokenRouteAllows = tokAllows,
					tokenRouteBlocks = tokBlocks,
					fallbackRouteBlocks = fallback,
					seenRouteKeys = seenRoutes,
					sourcePool = pool,
				)
			}
		}

		val domainCount = allowExact.size + allowZones.size + blockExact.size + blockZones.size
		val routeCount = hostAllows.values.sumOf { it.size } +
			hostBlocks.values.sumOf { it.size } +
			tokAllows.values.sumOf { it.size } +
			tokBlocks.values.sumOf { it.size } +
			fallback.size

		return domainCount to routeCount
	}

	private fun buildCustomSnapshot(customRules: List<CustomRule>): CustomSnapshot {
		val allowExact = HashSet<String>()
		val allowZones = HashSet<String>()
		val blockExact = HashSet<String>()
		val blockZones = HashSet<String>()
		val allowComplex = ArrayList<CompiledCustomRule>()
		val blockComplex = ArrayList<CompiledCustomRule>()

		for (r in customRules) {
			val compiled = compileCustomRule(r) ?: continue
			if (!r.isRoute && r.matchMode == MODE_EXACT && !compiled.isSchemeIncluded) {
				if (r.isAllow)
					allowExact.add(compiled.normPattern)
				else
					blockExact.add(compiled.normPattern)
			} else if (
				!r.isRoute &&
				r.matchMode == MODE_WILDCARD &&
				compiled.normPattern.startsWith("*.") &&
				compiled.normPattern.indexOf('*', 2) == -1 &&
				!compiled.normPattern.contains('?')
			) {
				val zone = compiled.normPattern.substring(2)
				if (r.isAllow)
					allowZones.add(zone)
				else
					blockZones.add(zone)
			} else {
				if (r.isAllow)
					allowComplex.add(compiled)
				else
					blockComplex.add(compiled)
			}
		}

		val domCnt = allowExact.size + allowZones.size + blockExact.size + blockZones.size +
			allowComplex.count { !it.raw.isRoute } + blockComplex.count { !it.raw.isRoute }
		val rtCnt = allowComplex.count { it.raw.isRoute } + blockComplex.count { it.raw.isRoute }

		return CustomSnapshot(
			allowExactDomains = allowExact,
			allowZones = allowZones,
			blockExactDomains = blockExact,
			blockZones = blockZones,
			allowComplex = allowComplex,
			blockComplex = blockComplex,
			domainCount = domCnt,
			routeCount = rtCnt,
		)
	}

	private fun buildBlocklistSnapshot(enabledLists: List<BlocklistSource>): BlocklistSnapshot {
		val listAllowExact = HashMap<String, String>(4096)
		val listAllowZones = HashMap<String, String>(8192)
		val listBlockExact = HashMap<String, String>(131072)
		val listBlockZones = HashMap<String, String>(262144)
		val hostRouteAllows = HashMap<String, MutableList<FastRouteRule>>(1024)
		val hostRouteBlocks = HashMap<String, MutableList<FastRouteRule>>(8192)
		val tokenRouteAllows = HashMap<String, MutableList<FastRouteRule>>(1024)
		val tokenRouteBlocks = HashMap<String, MutableList<FastRouteRule>>(16384)
		val fallbackRouteBlocks = ArrayList<FastRouteRule>(256)
		val genericCosmetics = LinkedHashSet<String>(2048)
		val domainCosmetics = HashMap<String, MutableList<String>>(4096)
		val domainCosmeticExceptions = HashMap<String, MutableSet<String>>(512)
		val removeParams = HashSet<String>(128)
		val seenRouteKeys = HashSet<String>(32768)
		val sourcePool = HashMap<String, String>(256)

		for (src in enabledLists) {
			val f = safeCacheFile(src.id)
			if (f == null || !f.exists())
				continue

			val titleInterned = sourcePool.getOrPut(src.title) { src.title }

			runCatching {
				BufferedReader(InputStreamReader(f.inputStream(), Charsets.UTF_8), 64 * 1024).use { reader ->
					while (true) {
						val rawLine = reader.readLine() ?: break
						parseLineIntoSets(
							rawLine = rawLine,
							listTitle = titleInterned,
							allowExact = listAllowExact,
							allowZones = listAllowZones,
							blockExact = listBlockExact,
							blockZones = listBlockZones,
							hostRouteAllows = hostRouteAllows,
							hostRouteBlocks = hostRouteBlocks,
							tokenRouteAllows = tokenRouteAllows,
							tokenRouteBlocks = tokenRouteBlocks,
							fallbackRouteBlocks = fallbackRouteBlocks,
							seenRouteKeys = seenRouteKeys,
							sourcePool = sourcePool,
							genericCosmetics = genericCosmetics,
							domainCosmetics = domainCosmetics,
							domainCosmeticExceptions = domainCosmeticExceptions,
							removeParams = removeParams,
						)
					}
				}
			}
		}

		compactRuleSets(
			allowExact = listAllowExact,
			allowZones = listAllowZones,
			blockExact = listBlockExact,
			blockZones = listBlockZones,
			hostRouteBlocks = hostRouteBlocks,
			sourcePool = sourcePool,
		)

		val routeTotal = hostRouteAllows.values.sumOf { it.size } +
			hostRouteBlocks.values.sumOf { it.size } +
			tokenRouteAllows.values.sumOf { it.size } +
			tokenRouteBlocks.values.sumOf { it.size } +
			fallbackRouteBlocks.size

		val domainTotal = listAllowExact.size + listAllowZones.size + listBlockExact.size + listBlockZones.size
		val cosmeticTotal = genericCosmetics.size + domainCosmetics.values.sumOf { it.size }

		return BlocklistSnapshot(
			allowExact = listAllowExact,
			allowZones = listAllowZones,
			blockExact = listBlockExact,
			blockZones = listBlockZones,
			hostRouteAllows = hostRouteAllows,
			hostRouteBlocks = hostRouteBlocks,
			tokenRouteAllows = tokenRouteAllows,
			tokenRouteBlocks = tokenRouteBlocks,
			fallbackRouteBlocks = fallbackRouteBlocks,
			genericCosmeticSelectors = genericCosmetics.toList(),
			domainCosmeticMap = domainCosmetics,
			domainCosmeticExceptions = domainCosmeticExceptions,
			removeParams = removeParams,
			domainCount = domainTotal,
			routeCount = routeTotal,
			cosmeticCount = cosmeticTotal,
		)
	}

	companion object {
		private const val BIN_MAGIC = 0x54424C33
		private const val BIN_VERSION = 3
		private const val MAX_GENERIC_COSMETICS = 5000
		private const val MAX_BLOCKLIST_BYTES = 150L * 1024L * 1024L

		const val RES_SCRIPT = 1 shl 0
		const val RES_IMAGE = 1 shl 1
		const val RES_STYLESHEET = 1 shl 2
		const val RES_XHR = 1 shl 3
		const val RES_SUBDOCUMENT = 1 shl 4
		const val RES_MEDIA = 1 shl 5
		const val RES_FONT = 1 shl 6
		const val RES_PING = 1 shl 7
		const val RES_WEBSOCKET = 1 shl 8
		const val RES_DOCUMENT = 1 shl 9
		const val RES_OTHER = 1 shl 10
		const val RES_ALL_MASK = (1 shl 11) - 1

		private val IGNORED_HOSTS = setOf(
			"localhost",
			"localhost.localdomain",
			"local",
			"broadcasthost",
			"ip6-localhost",
			"ip6-loopback",
			"ip6-localnet",
			"ip6-mcastprefix",
			"ip6-allnodes",
			"ip6-allrouters",
			"ip6-allhosts",
			"0.0.0.0",
			"127.0.0.1",
			"::1",
			"::",
		)

		fun normalizeHost(input: String): String {
			var s = input.trim().removeSurrounding("[", "]").lowercase()
			if (s.endsWith('.'))
				s = s.dropLast(1)
			if (s.isNotEmpty() && !s.contains('*') && !s.contains('?') && !s.contains('/') && s.any { it.code > 127 })
				s = runCatching { IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).lowercase() }.getOrDefault(s)

			return s
		}

		fun extractRegistrableDomain(rawHost: String): String {
			val host = normalizeHost(rawHost)
			val dots = ArrayList<Int>(4)
			for (i in host.indices) {
				if (host[i] == '.')
					dots.add(i)
			}
			if (dots.size <= 1)
				return host

			val lastLabel = host.substring(dots.last() + 1)
			val prevLabel = host.substring(dots[dots.size - 2] + 1, dots.last())
			val isMultipartTld = lastLabel.length == 2 && prevLabel.length in 2..3 &&
				(prevLabel == "co" || prevLabel == "com" || prevLabel == "org" || prevLabel == "net" || prevLabel == "gov" || prevLabel == "edu" || prevLabel == "ac")

			if (isMultipartTld && dots.size >= 3)
				return host.substring(dots[dots.size - 3] + 1)

			return host.substring(dots[dots.size - 2] + 1)
		}

		fun classifyRequestTypeMask(
			method: String,
			pathAndQuery: String,
			acceptHeader: String,
			secDest: String,
			isWebSocket: Boolean,
		): Int {
			if (isWebSocket)
				return RES_WEBSOCKET

			val dest = secDest.trim().lowercase()
			when (dest) {
				"script", "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet" -> return RES_SCRIPT
				"image" -> return RES_IMAGE
				"style" -> return RES_STYLESHEET
				"iframe", "frame", "fencedframe", "embed" -> return RES_SUBDOCUMENT
				"document" -> return RES_DOCUMENT
				"audio", "video", "track" -> return RES_MEDIA
				"font" -> return RES_FONT
				"object" -> return RES_OTHER
			}

			if (method.equals("POST", ignoreCase = true) && dest == "empty")
				return RES_XHR or RES_PING

			val cleanPath = pathAndQuery.substringBefore('?').substringBefore('#').lowercase()
			val accept = acceptHeader.lowercase()

			if (cleanPath.endsWith(".js") || cleanPath.endsWith(".mjs") || accept.contains("javascript"))
				return RES_SCRIPT
			if (cleanPath.endsWith(".css") || accept.contains("text/css"))
				return RES_STYLESHEET
			if (
				cleanPath.endsWith(".png") || cleanPath.endsWith(".jpg") || cleanPath.endsWith(".jpeg") ||
				cleanPath.endsWith(".gif") || cleanPath.endsWith(".webp") || cleanPath.endsWith(".svg") ||
				cleanPath.endsWith(".ico") || cleanPath.endsWith(".avif") || accept.startsWith("image/")
			) {
				return RES_IMAGE
			}
			if (
				cleanPath.endsWith(".woff2") || cleanPath.endsWith(".woff") ||
				cleanPath.endsWith(".ttf") || cleanPath.endsWith(".otf")
			) {
				return RES_FONT
			}
			if (
				cleanPath.endsWith(".mp4") || cleanPath.endsWith(".webm") ||
				cleanPath.endsWith(".m3u8") || cleanPath.endsWith(".mp3")
			) {
				return RES_MEDIA
			}
			if (accept.contains("text/html"))
				return RES_DOCUMENT
			if (dest == "empty" || accept.contains("application/json") || accept.contains("*/*"))
				return RES_XHR

			return RES_OTHER
		}

		fun validateRegex(pattern: String): String? {
			return try {
				Regex(pattern, RegexOption.IGNORE_CASE)
				null
			} catch (e: Exception) {
				e.message ?: "Invalid regular expression"
			}
		}

		fun compileCustomRule(rule: CustomRule): CompiledCustomRule? {
			val rawPat = rule.pattern.trim()
			if (rawPat.isEmpty())
				return null

			if (rule.matchMode == MODE_REGEX) {
				val rx = runCatching { Regex(rawPat, RegexOption.IGNORE_CASE) }.getOrNull() ?: return null
				return CompiledCustomRule(rule, rawPat, true, rx)
			}

			val lower = rawPat.lowercase()
			val hasScheme = lower.startsWith("http://") ||
				lower.startsWith("https://") ||
				lower.startsWith("ws://") ||
				lower.startsWith("wss://")

			val cleaned = if (!rule.isRoute && !hasScheme) {
				val stripped = lower.removePrefix("||").removeSuffix("^").trimEnd('.')
				if (stripped.startsWith("*.")) {
					"*.${normalizeHost(stripped.substring(2))}"
				} else {
					normalizeHost(stripped)
				}
			} else {
				lower
			}

			return CompiledCustomRule(rule, cleaned, hasScheme, null)
		}

		fun testSingleCustomRule(rule: CustomRule, sampleInput: String): Boolean {
			val compiled = compileCustomRule(rule) ?: return false
			val s = sampleInput.trim()
			if (s.isEmpty())
				return false

			val schemeIdx = s.indexOf("://")
			val withoutScheme = if (schemeIdx >= 0) s.substring(schemeIdx + 3) else s
			val slashIdx = withoutScheme.indexOf('/')
			val hostPart = normalizeHost(if (slashIdx >= 0) withoutScheme.substring(0, slashIdx) else withoutScheme)
			val pathPart = if (slashIdx >= 0) withoutScheme.substring(slashIdx) else "/"
			val fullUrl = if (schemeIdx >= 0) s else "https://$hostPart$pathPart"
			val hostWithPath = "$hostPart$pathPart"

			return if (!rule.isRoute) {
				matchesCustomDomain(hostPart, compiled)
			} else {
				matchesCustomFull(fullUrl, hostPart, hostWithPath, compiled)
			}
		}

		private fun matchesCustomDomain(host: String, r: CompiledCustomRule): Boolean {
			return when (r.raw.matchMode) {
				MODE_EXACT -> host == r.normPattern
				MODE_WILDCARD -> {
					if (r.normPattern.startsWith("*.")) {
						val base = r.normPattern.substring(2)
						host == base || (host.endsWith(base) && host.length > base.length && host[host.length - base.length - 1] == '.')
					} else {
						globMatch(host, r.normPattern)
					}
				}
				MODE_REGEX -> r.compiledRegex?.containsMatchIn(host) == true
				else -> false
			}
		}

		private fun matchesCustomFull(
			fullUrl: String,
			host: String,
			hostWithPath: String,
			r: CompiledCustomRule,
		): Boolean {
			if (!r.raw.isRoute)
				return matchesCustomDomain(host, r)

			val candidate = if (r.isSchemeIncluded) fullUrl else hostWithPath
			return when (r.raw.matchMode) {
				MODE_EXACT -> {
					if (candidate.equals(r.normPattern, ignoreCase = true))
						return true
					if (candidate.startsWith(r.normPattern, ignoreCase = true) && candidate.length > r.normPattern.length) {
						val nextChar = candidate[r.normPattern.length]
						nextChar == '/' || nextChar == '?' || nextChar == '#'
					} else {
						false
					}
				}
				MODE_WILDCARD -> globMatch(candidate, r.normPattern)
				MODE_REGEX -> r.compiledRegex?.containsMatchIn(fullUrl) == true ||
					r.compiledRegex?.containsMatchIn(hostWithPath) == true
				else -> false
			}
		}

		private fun formatCustomSource(rule: CustomRule): String {
			val action = if (rule.isAllow) "Allowed" else "Blocked"
			val mode = when (rule.matchMode) {
				MODE_WILDCARD -> "Wildcard"
				MODE_REGEX -> "Regex"
				else -> "Exact"
			}
			val scope = if (rule.isRoute) " • Route" else ""
			val noteSuffix = if (rule.note.isNotBlank()) " — ${rule.note}" else ""

			return "Custom Rule ($action • $mode$scope)$noteSuffix"
		}

		private fun matchesZoneSet(host: String, zones: Set<String>): String? {
			if (zones.isEmpty())
				return null
			if (zones.contains(host))
				return host

			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				val parent = host.substring(dot + 1)
				if (zones.contains(parent))
					return parent
				dot = host.indexOf('.', dot + 1)
			}

			return null
		}

		private fun matchesZoneMap(host: String, zones: Map<String, String>): Pair<String, String>? {
			if (zones.isEmpty())
				return null
			zones[host]?.let { return host to it }

			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				val parent = host.substring(dot + 1)
				zones[parent]?.let { return parent to it }
				dot = host.indexOf('.', dot + 1)
			}

			return null
		}

		private fun matchesHostRouteMap(
			host: String,
			hostWithPath: String,
			isWebSocket: Boolean,
			reqTypeMask: Int,
			isThirdParty: Boolean?,
			map: Map<String, List<FastRouteRule>>,
		): FastRouteRule? {
			if (map.isEmpty())
				return null

			map[host]?.let { list ->
				for (r in list) {
					if (r.matchesContext(isWebSocket, reqTypeMask, isThirdParty) && adblockWildcardMatch(hostWithPath, r.pattern))
						return r
				}
			}

			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				val parent = host.substring(dot + 1)
				map[parent]?.let { list ->
					for (r in list) {
						val subPath = hostWithPath.substring(dot + 1)
						if (r.matchesContext(isWebSocket, reqTypeMask, isThirdParty) && adblockWildcardMatch(subPath, r.pattern))
							return r
					}
				}
				dot = host.indexOf('.', dot + 1)
			}

			return null
		}

		private fun matchesTokenRoutes(
			fullUrl: String,
			hostWithPath: String,
			isWebSocket: Boolean,
			reqTypeMask: Int,
			isThirdParty: Boolean?,
			tokenMap: Map<String, List<FastRouteRule>>,
		): FastRouteRule? {
			if (tokenMap.isEmpty())
				return null

			var i = 0
			val len = fullUrl.length
			while (i < len) {
				while (i < len && !isAlphaNumAscii(fullUrl[i]))
					i++
				val start = i
				while (i < len && isAlphaNumAscii(fullUrl[i]))
					i++
				val wordLen = i - start
				if (wordLen >= 4) {
					val tok = fullUrl.substring(start, i).lowercase()
					tokenMap[tok]?.let { rules ->
						for (r in rules) {
							if (!r.matchesContext(isWebSocket, reqTypeMask, isThirdParty))
								continue
							val target = if (r.isHostAnchored) hostWithPath else fullUrl
							if (adblockWildcardMatch(target, r.pattern))
								return r
						}
					}
				}
			}

			return null
		}

		fun globMatch(text: String, pattern: String): Boolean {
			var ti = 0
			var pi = 0
			var starIdx = -1
			var matchIdx = 0
			val tLen = text.length
			val pLen = pattern.length

			while (ti < tLen) {
				if (pi < pLen && (pattern[pi] == '?' || pattern[pi].equals(text[ti], ignoreCase = true))) {
					ti++
					pi++
				} else if (pi < pLen && pattern[pi] == '*') {
					starIdx = pi
					matchIdx = ti
					pi++
				} else if (starIdx != -1) {
					pi = starIdx + 1
					matchIdx++
					ti = matchIdx
				} else {
					return false
				}
			}

			while (pi < pLen && pattern[pi] == '*')
				pi++

			return pi == pLen
		}

		// Adblock '^' matches either end of URL or any separator character outside [a-zA-Z0-9_.-%]
		fun adblockWildcardMatch(text: String, pattern: String): Boolean {
			var ti = 0
			var pi = 0
			var starIdx = -1
			var matchIdx = 0
			val tLen = text.length
			val pLen = pattern.length

			while (ti < tLen) {
				if (pi < pLen) {
					val pc = pattern[pi]
					if (pc == '*') {
						starIdx = pi
						matchIdx = ti
						pi++
						continue
					}
					if (pc == '^' && isAdblockSeparator(text[ti])) {
						ti++
						pi++
						continue
					}
					if (pc != '^' && pc.equals(text[ti], ignoreCase = true)) {
						ti++
						pi++
						continue
					}
				}

				if (starIdx != -1) {
					pi = starIdx + 1
					matchIdx++
					ti = matchIdx
				} else {
					return false
				}
			}

			while (pi < pLen && pattern[pi] == '*')
				pi++
			if (pi < pLen && pattern[pi] == '^') {
				var tail = pi + 1
				while (tail < pLen && pattern[tail] == '*')
					tail++
				if (tail == pLen)
					return true
			}

			return pi == pLen
		}

		private fun isAdblockSeparator(c: Char): Boolean {
			if (c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9')
				return false

			return c != '_' && c != '-' && c != '.' && c != '%'
		}

		private fun isAlphaNumAscii(c: Char): Boolean {
			return c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9'
		}

		private fun isValidDomain(s: String): Boolean {
			if (s.length < 3 || s.length > 253 || !s.contains('.'))
				return false
			if (IGNORED_HOSTS.contains(s))
				return false
			if (s.startsWith('.') || s.endsWith('.') || s.contains(".."))
				return false

			for (c in s) {
				val isOk = (c in 'a'..'z') || (c in '0'..'9') || c == '.' || c == '-' || c == '_'
				if (!isOk)
					return false
			}

			return true
		}

		private fun putMergedSource(
			map: MutableMap<String, String>,
			key: String,
			addedSource: String,
			pool: MutableMap<String, String>,
		) {
			val prev = map[key]
			if (prev == null) {
				map[key] = addedSource
				return
			}
			if (prev == addedSource || prev.contains(addedSource))
				return
			val commaCount = prev.count { it == ',' }
			val combined = if (commaCount >= 2) {
				if (prev.endsWith("...")) prev else "$prev, ..."
			} else {
				"$prev, $addedSource"
			}
			map[key] = pool.getOrPut(combined) { combined }
		}

		internal fun compactRuleSets(
			allowExact: Map<String, String>,
			allowZones: Map<String, String>,
			blockExact: MutableMap<String, String>,
			blockZones: MutableMap<String, String>,
			hostRouteBlocks: MutableMap<String, MutableList<FastRouteRule>>,
			sourcePool: MutableMap<String, String> = HashMap(),
		) {
			if (blockZones.isNotEmpty()) {
				val redundantZones = ArrayList<String>()
				for (zone in blockZones.keys) {
					var dot = zone.indexOf('.')
					while (dot >= 0 && dot + 1 < zone.length) {
						val parent = zone.substring(dot + 1)
						if (blockZones.containsKey(parent)) {
							redundantZones.add(zone)
							break
						}
						dot = zone.indexOf('.', dot + 1)
					}
				}
				for (rz in redundantZones)
					blockZones.remove(rz)
			}

			if (blockExact.isNotEmpty() && blockZones.isNotEmpty()) {
				val it = blockExact.entries.iterator()
				while (it.hasNext()) {
					val entry = it.next()
					val host = entry.key
					val zoneHit = matchesZoneMap(host, blockZones)
					if (zoneHit != null) {
						if (zoneHit.first == host)
							putMergedSource(blockZones, host, entry.value, sourcePool)
						it.remove()
					}
				}
			}

			if (hostRouteBlocks.isNotEmpty() && blockZones.isNotEmpty()) {
				val allowedRootsAndParents = HashSet<String>(allowExact.size + allowZones.size)
				for (a in allowExact.keys)
					addSelfAndParents(a, allowedRootsAndParents)
				for (a in allowZones.keys)
					addSelfAndParents(a, allowedRootsAndParents)

				val it = hostRouteBlocks.entries.iterator()
				while (it.hasNext()) {
					val dom = it.next().key
					val isAnySubAllowed = allowedRootsAndParents.contains(dom) || matchesZoneMap(dom, allowZones) != null
					if (!isAnySubAllowed && matchesZoneMap(dom, blockZones) != null)
						it.remove()
				}
			}
		}

		private fun addSelfAndParents(host: String, dst: MutableSet<String>) {
			dst.add(host)
			var dot = host.indexOf('.')
			while (dot >= 0 && dot + 1 < host.length) {
				dst.add(host.substring(dot + 1))
				dot = host.indexOf('.', dot + 1)
			}
		}

		private fun isStandardCssSelector(sel: String): Boolean {
			if (sel.length !in 2..220)
				return false
			if (sel.startsWith("+js(") || sel.startsWith('^') || sel.startsWith("script:"))
				return false
			for (c in sel) {
				if (c == '<' || c == '{' || c == '}' || c == ';' || c == '\r' || c == '\n')
					return false
			}
			val lower = sel.lowercase()
			if (
				lower.contains(":has(") ||
				lower.contains(":has-text(") ||
				lower.contains(":xpath(") ||
				lower.contains(":style(") ||
				lower.contains(":matches-css(") ||
				lower.contains(":matches-attr(") ||
				lower.contains(":matches-path(") ||
				lower.contains(":upward(") ||
				lower.contains(":remove(") ||
				lower.contains(":-abp-") ||
				lower.contains(":contains(")
			) {
				return false
			}

			return true
		}

		private class ParsedModifiers(
			val isWebSocketOnly: Boolean,
			val typeMask: Int,
			val partyMode: Int,
		) {
			val isUnconditional: Boolean
				get() = !isWebSocketOnly && typeMask == 0 && partyMode == FastRouteRule.PARTY_ANY
		}

		private fun parseAdblockModifiers(modsRaw: String): ParsedModifiers? {
			var isWsOnly = false
			var posTypes = 0
			var negTypes = 0
			var hasNegType = false
			var party = FastRouteRule.PARTY_ANY

			for (rawTok in modsRaw.split(',')) {
				val m = rawTok.trim()
				if (m.isEmpty())
					continue
				when (m) {
					"important", "all", "match-case" -> {}
					"3p", "third-party" -> party = FastRouteRule.PARTY_THIRD_ONLY
					"~3p", "~third-party", "1p", "first-party" -> party = FastRouteRule.PARTY_FIRST_ONLY
					"websocket" -> {
						isWsOnly = true
						posTypes = posTypes or RES_WEBSOCKET
					}
					"~websocket" -> {
						hasNegType = true
						negTypes = negTypes or RES_WEBSOCKET
					}
					"script" -> posTypes = posTypes or RES_SCRIPT
					"~script" -> {
						hasNegType = true
						negTypes = negTypes or RES_SCRIPT
					}
					"image" -> posTypes = posTypes or RES_IMAGE
					"~image" -> {
						hasNegType = true
						negTypes = negTypes or RES_IMAGE
					}
					"stylesheet", "css" -> posTypes = posTypes or RES_STYLESHEET
					"~stylesheet", "~css" -> {
						hasNegType = true
						negTypes = negTypes or RES_STYLESHEET
					}
					"xmlhttprequest", "xhr" -> posTypes = posTypes or RES_XHR
					"~xmlhttprequest", "~xhr" -> {
						hasNegType = true
						negTypes = negTypes or RES_XHR
					}
					"subdocument", "frame" -> posTypes = posTypes or RES_SUBDOCUMENT
					"~subdocument", "~frame" -> {
						hasNegType = true
						negTypes = negTypes or RES_SUBDOCUMENT
					}
					"media" -> posTypes = posTypes or RES_MEDIA
					"~media" -> {
						hasNegType = true
						negTypes = negTypes or RES_MEDIA
					}
					"font" -> posTypes = posTypes or RES_FONT
					"~font" -> {
						hasNegType = true
						negTypes = negTypes or RES_FONT
					}
					"ping", "beacon" -> posTypes = posTypes or RES_PING
					"~ping", "~beacon" -> {
						hasNegType = true
						negTypes = negTypes or RES_PING
					}
					"document", "doc" -> posTypes = posTypes or RES_DOCUMENT
					"~document", "~doc" -> {
						hasNegType = true
						negTypes = negTypes or RES_DOCUMENT
					}
					"other", "object", "object-subrequest" -> posTypes = posTypes or RES_OTHER
					"~other", "~object" -> {
						hasNegType = true
						negTypes = negTypes or RES_OTHER
					}
					else -> return null
				}
			}

			val finalMask = when {
				posTypes != 0 && !hasNegType -> {
					if (posTypes == RES_WEBSOCKET) 0 else posTypes
				}
				posTypes != 0 && hasNegType -> posTypes and negTypes.inv()
				hasNegType -> RES_ALL_MASK and negTypes.inv()
				else -> 0
			}
			if ((posTypes != 0 || hasNegType) && finalMask == 0 && !isWsOnly)
				return null

			return ParsedModifiers(
				isWebSocketOnly = isWsOnly && (finalMask == 0 || finalMask == RES_WEBSOCKET),
				typeMask = if (isWsOnly && finalMask == RES_WEBSOCKET) 0 else finalMask,
				partyMode = party,
			)
		}

		internal fun parseLineIntoSets(
			rawLine: String,
			listTitle: String,
			allowExact: MutableMap<String, String>,
			allowZones: MutableMap<String, String>,
			blockExact: MutableMap<String, String>,
			blockZones: MutableMap<String, String>,
			hostRouteAllows: MutableMap<String, MutableList<FastRouteRule>>,
			hostRouteBlocks: MutableMap<String, MutableList<FastRouteRule>>,
			tokenRouteAllows: MutableMap<String, MutableList<FastRouteRule>>,
			tokenRouteBlocks: MutableMap<String, MutableList<FastRouteRule>>,
			fallbackRouteBlocks: MutableList<FastRouteRule>,
			seenRouteKeys: MutableSet<String>? = null,
			sourcePool: MutableMap<String, String> = HashMap(),
			genericCosmetics: MutableSet<String>? = null,
			domainCosmetics: MutableMap<String, MutableList<String>>? = null,
			domainCosmeticExceptions: MutableMap<String, MutableSet<String>>? = null,
			removeParams: MutableSet<String>? = null,
		): Boolean? {
			var line = rawLine.trim()
			if (line.isEmpty() || line[0] == '!' || line[0] == '[')
				return null
			if (line[0] == '#' && !line.startsWith("##") && !line.startsWith("#@#"))
				return null
			if (line.contains("#?#") || line.contains("#$#") || line.contains("#%#"))
				return null

			val cosAllowIdx = line.indexOf("#@#")
			if (cosAllowIdx >= 0) {
				if (domainCosmeticExceptions == null)
					return null
				val domainsPart = line.substring(0, cosAllowIdx).trim()
				val selector = line.substring(cosAllowIdx + 3).trim()
				if (domainsPart.isNotEmpty() && isStandardCssSelector(selector)) {
					for (rawDom in domainsPart.split(',')) {
						val d = normalizeHost(rawDom.removePrefix("~"))
						if (isValidDomain(d)) {
							val exSet = domainCosmeticExceptions.getOrPut(d) { HashSet(2) }
							if (exSet.size < 256)
								exSet.add(selector)
						}
					}
				}
				return null
			}

			val cosIdx = line.indexOf("##")
			if (cosIdx >= 0) {
				if (genericCosmetics == null && domainCosmetics == null)
					return null
				val domainsPart = line.substring(0, cosIdx).trim()
				val selector = line.substring(cosIdx + 2).trim()
				if (!isStandardCssSelector(selector))
					return null

				if (domainsPart.isEmpty() || domainsPart == "*") {
					if (genericCosmetics != null && genericCosmetics.size < MAX_GENERIC_COSMETICS)
						genericCosmetics.add(selector)
				} else {
					val posDoms = ArrayList<String>(2)
					val negDoms = ArrayList<String>(2)
					for (rawDom in domainsPart.split(',')) {
						val trimmedDom = rawDom.trim()
						if (trimmedDom.startsWith('~')) {
							val nd = normalizeHost(trimmedDom.substring(1))
							if (isValidDomain(nd))
								negDoms.add(nd)
						} else {
							val pd = normalizeHost(trimmedDom)
							if (isValidDomain(pd))
								posDoms.add(pd)
						}
					}

					if (posDoms.isEmpty() && negDoms.isNotEmpty()) {
						if (genericCosmetics != null && genericCosmetics.size < MAX_GENERIC_COSMETICS)
							genericCosmetics.add(selector)
					} else if (domainCosmetics != null) {
						for (d in posDoms) {
							val list = domainCosmetics.getOrPut(d) { ArrayList(2) }
							if (list.size < 128 && !list.contains(selector))
								list.add(selector)
						}
					}

					if (domainCosmeticExceptions != null && negDoms.isNotEmpty()) {
						for (nd in negDoms) {
							val exSet = domainCosmeticExceptions.getOrPut(nd) { HashSet(2) }
							if (exSet.size < 256)
								exSet.add(selector)
						}
					}
				}
				return null
			}

			val wsCommentIdx = findInlineCommentIndex(line)
			if (wsCommentIdx > 0)
				line = line.substring(0, wsCommentIdx).trim()

			if (
				line.startsWith("0.0.0.0 ") ||
				line.startsWith("127.0.0.1 ") ||
				line.startsWith("0.0.0.0\t") ||
				line.startsWith("127.0.0.1\t") ||
				line.startsWith("::1 ") ||
				line.startsWith("::1\t") ||
				line.startsWith(":: ") ||
				line.startsWith("::\t")
			) {
				val hashAny = line.indexOf('#')
				val cleanHostsLine = if (hashAny >= 0) line.substring(0, hashAny).trim() else line
				val spaceIdx = cleanHostsLine.indexOfFirst { it == ' ' || it == '\t' }
				if (spaceIdx > 0) {
					var isAdded = false
					val tail = cleanHostsLine.substring(spaceIdx + 1)
					for (tok in tail.split(' ', '\t')) {
						if (tok.isEmpty())
							continue
						val host = normalizeHost(tok)
						if (isValidDomain(host)) {
							putMergedSource(blockExact, host, listTitle, sourcePool)
							isAdded = true
						}
					}
					if (isAdded)
						return false
				}
				return null
			}

			if (line.startsWith("address=/")) {
				val inner = line.removePrefix("address=/").substringBefore('/')
				val host = normalizeHost(inner)
				if (isValidDomain(host)) {
					putMergedSource(blockZones, host, listTitle, sourcePool)
					return false
				}
				return null
			}

			if (line.startsWith("*.") && !line.contains('/')) {
				val host = normalizeHost(line.substring(2))
				if (isValidDomain(host)) {
					putMergedSource(blockZones, host, listTitle, sourcePool)
					return false
				}
				return null
			}

			if (!line.contains('$') && !line.contains('/') && !line.contains('*') && !line.contains('^') && !line.startsWith("||") && !line.startsWith("@@")) {
				val host = normalizeHost(line)
				if (isValidDomain(host)) {
					putMergedSource(blockZones, host, listTitle, sourcePool)
					return false
				}
				return null
			}

			val isAllow = line.startsWith("@@")
			if (isAllow)
				line = line.substring(2)

			var parsedMods = DEFAULT_PARSED_MODS
			val dollarIdx = line.indexOf('$')
			if (dollarIdx >= 0) {
				val patPart = line.substring(0, dollarIdx).trim()
				val mods = line.substring(dollarIdx + 1).lowercase()
				if (!isAllow && removeParams != null && mods.contains("removeparam=") && !mods.contains("domain=")) {
					val isGlobalPattern = patPart.isEmpty() ||
						patPart == "*" ||
						patPart == "||*" ||
						patPart == "http://*" ||
						patPart == "https://*"
					if (isGlobalPattern) {
						for (tok in mods.split(',')) {
							val m = tok.trim()
							if (m.startsWith("removeparam=")) {
								val rp = m.substring("removeparam=".length).trim()
								if (rp.length in 2..64 && !rp.startsWith('/') && !rp.startsWith('~') && !rp.contains('|') && !rp.contains('*'))
									removeParams.add(rp)
							}
						}
					}
					return null
				}
				if (
					mods.contains("badfilter") ||
					mods.contains("elemhide") ||
					mods.contains("generichide") ||
					mods.contains("specifichide") ||
					mods.contains("csp=") ||
					mods.contains("removeparam") ||
					mods.contains("redirect-rule=") ||
					mods.contains("redirect=") ||
					mods.contains("domain=") ||
					mods.contains("popup")
				) {
					return null
				}
				parsedMods = parseAdblockModifiers(mods) ?: return null
				line = patPart
			}

			if (line.isEmpty() || (line.startsWith('/') && line.endsWith('/')))
				return null

			if (line.startsWith("||")) {
				val body = line.substring(2)
				val slashIdx = body.indexOf('/')
				val caretIdx = body.indexOf('^')
				val sepIdx = when {
					slashIdx >= 0 && caretIdx in 0 until slashIdx -> caretIdx
					slashIdx >= 0 -> slashIdx
					caretIdx >= 0 && caretIdx < body.length - 1 -> caretIdx
					else -> -1
				}

				if (sepIdx < 0) {
					val cleanHost = normalizeHost(body.removeSuffix("^").removeSuffix("|"))
					if (isValidDomain(cleanHost)) {
						if (parsedMods.isUnconditional) {
							if (isAllow)
								putMergedSource(allowZones, cleanHost, listTitle, sourcePool)
							else
								putMergedSource(blockZones, cleanHost, listTitle, sourcePool)
							return false
						}

						val pat = "$cleanHost^*"
						val dedupKey = "$isAllow|1|${parsedMods.isWebSocketOnly}|${parsedMods.typeMask}|${parsedMods.partyMode}|$pat"
						if (seenRouteKeys != null && !seenRouteKeys.add(dedupKey))
							return null
						val rule = FastRouteRule(
							pattern = pat,
							isHostAnchored = true,
							isWebSocketOnly = parsedMods.isWebSocketOnly,
							sourceTitle = listTitle,
							displayRule = "||$cleanHost^",
							typeMask = parsedMods.typeMask,
							partyMode = parsedMods.partyMode,
						)
						val targetMap = if (isAllow) hostRouteAllows else hostRouteBlocks
						targetMap.getOrPut(cleanHost) { ArrayList(2) }.add(rule)
						return true
					}
				} else {
					val rawDomain = normalizeHost(body.substring(0, sepIdx).removeSuffix("^"))
					if (isValidDomain(rawDomain)) {
						val isEndPipe = body.endsWith('|')
						val trimmedBody = if (isEndPipe) body.dropLast(1) else body
						val pat = "$rawDomain${trimmedBody.substring(sepIdx).lowercase()}".let { p ->
							if (isEndPipe || p.endsWith('*')) p else "$p*"
						}
						val dedupKey = "$isAllow|1|${parsedMods.isWebSocketOnly}|${parsedMods.typeMask}|${parsedMods.partyMode}|$pat"
						if (seenRouteKeys != null && !seenRouteKeys.add(dedupKey))
							return null
						val rule = FastRouteRule(
							pattern = pat,
							isHostAnchored = true,
							isWebSocketOnly = parsedMods.isWebSocketOnly,
							sourceTitle = listTitle,
							displayRule = "||${body.take(80)}",
							typeMask = parsedMods.typeMask,
							partyMode = parsedMods.partyMode,
						)
						val targetMap = if (isAllow) hostRouteAllows else hostRouteBlocks
						targetMap.getOrPut(rawDomain) { ArrayList(2) }.add(rule)
						return true
					}
				}
			}

			if (line.length < 5)
				return null

			val isStartAnchored = line.startsWith('|')
			val afterLeftPipe = line.removePrefix("|")
			val isEndAnchored = afterLeftPipe.endsWith('|')
			val corePat = if (isEndAnchored) afterLeftPipe.dropLast(1) else afterLeftPipe
			if (corePat.isEmpty())
				return null

			val wildPat = buildString(corePat.length + 2) {
				if (!isStartAnchored && !corePat.startsWith('*'))
					append('*')
				append(corePat.lowercase())
				if (!isEndAnchored && !corePat.endsWith('*'))
					append('*')
			}

			val bestToken = extractBoundedToken(corePat)
			val dedupKey = "$isAllow|0|${parsedMods.isWebSocketOnly}|${parsedMods.typeMask}|${parsedMods.partyMode}|$wildPat"
			if (seenRouteKeys != null && !seenRouteKeys.add(dedupKey))
				return null

			val rule = FastRouteRule(
				pattern = wildPat,
				isHostAnchored = false,
				isWebSocketOnly = parsedMods.isWebSocketOnly,
				sourceTitle = listTitle,
				displayRule = line.take(80),
				typeMask = parsedMods.typeMask,
				partyMode = parsedMods.partyMode,
			)

			if (bestToken != null) {
				val map = if (isAllow) tokenRouteAllows else tokenRouteBlocks
				map.getOrPut(bestToken) { ArrayList(2) }.add(rule)
				return true
			} else if (!isAllow && fallbackRouteBlocks.size < 200) {
				fallbackRouteBlocks.add(rule)
				return true
			}

			return null
		}

		private val DEFAULT_PARSED_MODS = ParsedModifiers(false, 0, FastRouteRule.PARTY_ANY)

		private fun findInlineCommentIndex(line: String): Int {
			for (i in 1 until line.length) {
				if (line[i] == '#' && (line[i - 1] == ' ' || line[i - 1] == '\t'))
					return i
			}

			return -1
		}

		private fun extractBoundedToken(pattern: String): String? {
			var best: String? = null
			var i = 0
			val n = pattern.length
			while (i < n) {
				while (i < n && !isAlphaNumAscii(pattern[i]))
					i++
				val start = i
				while (i < n && isAlphaNumAscii(pattern[i]))
					i++
				val wordLen = i - start
				if (wordLen >= 4) {
					val leftOk = start == 0 || (pattern[start - 1] != '*' && pattern[start - 1] != '?')
					val rightOk = i == n || (pattern[i] != '*' && pattern[i] != '?')
					if (leftOk && rightOk) {
						val tok = pattern.substring(start, i).lowercase()
						if (tok != "http" && tok != "https" && tok != "html" && (best == null || tok.length > best.length))
							best = tok
					}
				}
			}

			return best
		}
	}
}
