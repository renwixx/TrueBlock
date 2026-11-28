package com.renwixx.trueadblocker.net

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.LruCache
import androidx.core.app.NotificationCompat
import com.renwixx.trueadblocker.BlockerApp
import com.renwixx.trueadblocker.MainActivity
import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.TrafficSample
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class VpnRuntimeState(
	val isRunning: Boolean = false,
	val isPausedByNetworkRule: Boolean = false,
	val isSnoozed: Boolean = false,
	val snoozeRemainingSec: Int = 0,
	val isL3CaptureActive: Boolean = false,
	val activeTransport: String = "Unknown",
	val proxyPort: Int = 0,
	val sessionBlocked: Long = 0L,
)

data class NotificationStats(
	val totalRequests: Long = 0L,
	val totalBlocked: Long = 0L,
	val totalCname: Long = 0L,
	val totalTrackerParams: Long = 0L,
)

private data class ActiveTunnelSpec(
	val isFullL3: Boolean,
	val clientIp: String,
	val dnsIp: String,
	val mtu: Int,
	val isBlockIpv6: Boolean,
	val proxyPort: Int,
	val bypassedApps: Set<String>,
)

class AdBlockVpnService : VpnService() {
	private val _scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
	private var _tunFd: ParcelFileDescriptor? = null
	private var _loopFlag: AtomicBoolean? = null
	private var _readerThread: Thread? = null
	private var _dnsWorkers: ExecutorService? = null
	private var _proxy: MitmProxy? = null
	private var _l3Router: TunL3Router? = null
	private var _dohHttp: okhttp3.OkHttpClient? = null
	private var _activeSpec: ActiveTunnelSpec? = null
	private var _configWatchJob: Job? = null
	private var _dnsWatchJob: Job? = null
	private var _statsWatchJob: Job? = null
	private var _snoozeTickerJob: Job? = null
	private var _netCallback: ConnectivityManager.NetworkCallback? = null

	@Volatile
	private var _isOnWifi = false

	@Volatile
	private var _isOnMobile = false

	@Volatile
	private var _lastStats = NotificationStats()

	private val _dnsCache = LruCache<String, CachedDns>(2048)
	private val _sessionBlocked = AtomicLong(0L)
	private val _lastNotifUpdateMs = AtomicLong(0L)
	private val _netCapsMap = ConcurrentHashMap<Network, NetworkCapabilities>()
	private val _proxyDnsPortBlockedUntil = ConcurrentHashMap<String, Long>()

	override fun onCreate() {
		super.onCreate()
		ensureNotificationChannel()
		registerTransportWatcher()
	}

	override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
		val initNotif = buildNotification(
			title = "TrueBlock · Active",
			statusText = formatActiveNotificationText(_lastStats, _sessionBlocked.get()),
			isSnoozed = false,
		)
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
			startForeground(NOTIF_ID, initNotif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
		else
			startForeground(NOTIF_ID, initNotif)

		val act = intent?.action
		if (act == ACTION_STOP) {
			requestStop()
			return START_NOT_STICKY
		}

		instance = this

		if (act == ACTION_SNOOZE) {
			val minutes = intent.getIntExtra(EXTRA_SNOOZE_MINUTES, 5).coerceIn(1, 180)
			val untilMs = System.currentTimeMillis() + minutes * 60_000L
			BlockerApp.instance.prefs.update { it.copy(isVpnDesired = true, snoozeUntilMs = untilMs) }
			enterSnoozeMode(untilMs)
			watchConfigChanges()
			return START_STICKY
		}

		if (act == ACTION_RESUME) {
			cancelSnoozeAlarmAndTicker()
			BlockerApp.instance.prefs.update { it.copy(isVpnDesired = true, snoozeUntilMs = 0L) }
			startOrReloadTunnel()
			watchConfigChanges()
			return START_STICKY
		}

		BlockerApp.instance.prefs.update { it.copy(isVpnDesired = true) }
		val savedSnooze = BlockerApp.instance.prefs.state.value.snoozeUntilMs
		if (savedSnooze > System.currentTimeMillis()) {
			enterSnoozeMode(savedSnooze)
		} else {
			if (savedSnooze != 0L)
				BlockerApp.instance.prefs.update { it.copy(snoozeUntilMs = 0L) }
			startOrReloadTunnel()
		}
		watchConfigChanges()

		return START_STICKY
	}

	override fun onRevoke() {
		cancelSnoozeAlarmAndTicker()
		BlockerApp.instance.prefs.update { it.copy(isVpnDesired = false, snoozeUntilMs = 0L) }
		teardownAll()
		runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
		showStoppedNotification(this, _lastStats)
		stopSelf()
		super.onRevoke()
	}

	override fun onDestroy() {
		cancelSnoozeAlarmAndTicker()
		unregisterTransportWatcher()
		teardownAll()
		runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
		showStoppedNotification(this, _lastStats)
		instance = null
		_scope.cancel()
		super.onDestroy()
	}

	fun pinnedHosts(): Set<String> = _proxy?.pinnedHostsSnapshot() ?: emptySet()

	fun clearPinnedHosts() {
		_proxy?.clearPinnedHosts()
	}

	private fun incrementSessionBlocked() {
		val updated = _sessionBlocked.incrementAndGet()
		_runtime.value = _runtime.value.copy(sessionBlocked = updated)
		maybeRefreshActiveNotification(isForce = false)
	}

	// Keeps ForegroundService alive during Snooze so Android 15-17 never kills the process or blocks FGS restart
	@Synchronized
	private fun enterSnoozeMode(untilMs: Long) {
		stopTunnelOnly()
		_proxy?.stop()
		_proxy = null

		scheduleSnoozeWakeupAlarm(untilMs)
		updateNotification(
			title = "TrueBlock · Snoozed",
			text = formatPausedOrSnoozedText("Protection paused", _lastStats),
			isSnoozed = true,
			snoozeUntilMs = untilMs,
		)

		_snoozeTickerJob?.cancel()
		_snoozeTickerJob = _scope.launch {
			while (isActive) {
				val remMs = untilMs - System.currentTimeMillis()
				if (remMs <= 0L) {
					BlockerApp.instance.prefs.update { it.copy(snoozeUntilMs = 0L) }
					cancelSnoozeAlarmOnly()
					startOrReloadTunnel()
					break
				}
				val remSec = ((remMs + 999L) / 1000L).toInt()
				_runtime.value = VpnRuntimeState(
					isRunning = true,
					isSnoozed = true,
					snoozeRemainingSec = remSec,
					activeTransport = currentTransportLabel(),
					sessionBlocked = _sessionBlocked.get(),
				)
				delay(1000L)
			}
		}
	}

	private fun scheduleSnoozeWakeupAlarm(untilMs: Long) {
		val am = getSystemService(AlarmManager::class.java) ?: return
		val pi = buildResumePendingIntent()
		runCatching {
			am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, untilMs, pi)
		}
	}

	private fun cancelSnoozeAlarmOnly() {
		val am = getSystemService(AlarmManager::class.java) ?: return
		runCatching { am.cancel(buildResumePendingIntent()) }
	}

	private fun cancelSnoozeAlarmAndTicker() {
		_snoozeTickerJob?.cancel()
		_snoozeTickerJob = null
		cancelSnoozeAlarmOnly()
	}

	private fun watchConfigChanges() {
		val prefs = BlockerApp.instance.prefs
		if (_configWatchJob == null) {
			_configWatchJob = _scope.launch {
				prefs.state
					.map { c ->
						listOf(
							c.bypassedApps,
							c.isHttpsFiltering,
							c.isWifiProtection,
							c.isMobileProtection,
							c.vpnClientIp,
							c.vpnDnsIp,
							c.vpnMtu,
							c.dnsWorkerThreads,
							c.l3RoutingMode,
							c.isBlockIpv6,
							c.dnsCacheSize,
							c.firewallWifiApps,
							c.firewallMobileApps,
							c.proxies,
						)
					}
					.distinctUntilChanged()
					.collect {
						_dnsCache.evictAll()
						val cur = prefs.state.value
						if (cur.isVpnDesired && cur.snoozeUntilMs <= System.currentTimeMillis())
							startOrReloadTunnel()
					}
			}
		}

		if (_dnsWatchJob == null) {
			_dnsWatchJob = _scope.launch {
				prefs.state
					.map { c ->
						listOf(
							c.dnsPresetKey,
							c.isUseDoh,
							c.isStrictDoh,
							c.customDnsIp,
							c.customSecondaryDnsIp,
							c.customDohUrl,
							c.isWifiCustomOverride,
							c.isMobileCustomOverride,
							c.isWifiUseDoh,
							c.isMobileUseDoh,
							c.wifiDnsIp,
							c.wifiSecondaryDnsIp,
							c.wifiDohUrl,
							c.mobileDnsIp,
							c.mobileSecondaryDnsIp,
							c.mobileDohUrl,
							c.proxies,
						)
					}
					.distinctUntilChanged()
					.collect {
						_dnsCache.evictAll()
						_proxyDnsPortBlockedUntil.clear()
						_dohHttp?.connectionPool?.evictAll()
					}
			}
		}

		if (_statsWatchJob == null) {
			val db = BlockerApp.instance.db
			_statsWatchJob = _scope.launch {
				combine(
					db.trafficDao().observeTotalsEntity(),
					db.trackerParamDao().observeTotalRemoved(),
				) { totals, params ->
					NotificationStats(
						totalRequests = totals?.totalRequests ?: 0L,
						totalBlocked = totals?.totalBlocked ?: 0L,
						totalCname = totals?.totalCname ?: 0L,
						totalTrackerParams = params,
					)
				}
					.distinctUntilChanged()
					.collect { stats ->
						_lastStats = stats
						maybeRefreshActiveNotification(isForce = false)
					}
			}
		}
	}

	private fun registerTransportWatcher() {
		val cm = getSystemService(ConnectivityManager::class.java) ?: return
		cm.activeNetwork?.let { active ->
			cm.getNetworkCapabilities(active)?.let { _netCapsMap[active] = it }
		}
		refreshTransportSnapshot(cm)

		val req = NetworkRequest.Builder()
			.addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
			.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
			.build()

		val cb = object : ConnectivityManager.NetworkCallback() {
			override fun onAvailable(network: Network) {
				val prevWifi = _isOnWifi
				val prevMob = _isOnMobile
				cm.getNetworkCapabilities(network)?.let { _netCapsMap[network] = it }
				refreshTransportSnapshot(cm)
				if (prevWifi != _isOnWifi || prevMob != _isOnMobile) {
					_dohHttp?.connectionPool?.evictAll()
					val cfg = BlockerApp.instance.prefs.state.value
					if (cfg.isVpnDesired && cfg.snoozeUntilMs <= System.currentTimeMillis())
						startOrReloadTunnel()
				}
			}

			override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
				_netCapsMap[network] = caps
				val prevWifi = _isOnWifi
				val prevMob = _isOnMobile
				refreshTransportSnapshot(cm)
				if (prevWifi != _isOnWifi || prevMob != _isOnMobile) {
					_dohHttp?.connectionPool?.evictAll()
					val cfg = BlockerApp.instance.prefs.state.value
					if (cfg.isVpnDesired && cfg.snoozeUntilMs <= System.currentTimeMillis())
						startOrReloadTunnel()
				}
			}

			override fun onLost(network: Network) {
				val prevWifi = _isOnWifi
				val prevMob = _isOnMobile
				_netCapsMap.remove(network)
				refreshTransportSnapshot(cm)
				if (prevWifi != _isOnWifi || prevMob != _isOnMobile) {
					_dohHttp?.connectionPool?.evictAll()
					val cfg = BlockerApp.instance.prefs.state.value
					if (cfg.isVpnDesired && cfg.snoozeUntilMs <= System.currentTimeMillis())
						startOrReloadTunnel()
				}
			}
		}

		runCatching { cm.registerNetworkCallback(req, cb) }
		_netCallback = cb
	}

	private fun unregisterTransportWatcher() {
		val cb = _netCallback ?: return
		_netCallback = null
		_netCapsMap.clear()
		val cm = getSystemService(ConnectivityManager::class.java) ?: return
		runCatching { cm.unregisterNetworkCallback(cb) }
	}

	private fun refreshTransportSnapshot(cm: ConnectivityManager?) {
		val activeCaps = cm?.activeNetwork?.let { n ->
			val c = cm.getNetworkCapabilities(n)
			if (c != null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) c else null
		}
		if (activeCaps != null) {
			val wifi = activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
			val cell = activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
			_isOnWifi = wifi
			_isOnMobile = !wifi && cell
			return
		}

		var isValidatedWifi = false
		var isValidatedCell = false
		var isAnyWifi = false
		var isAnyCell = false

		for (caps in _netCapsMap.values) {
			if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
				continue
			if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
				continue
			val isValid = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
			if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
				isAnyWifi = true
				if (isValid)
					isValidatedWifi = true
			}
			if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
				isAnyCell = true
				if (isValid)
					isValidatedCell = true
			}
		}

		if (isValidatedWifi || isValidatedCell) {
			_isOnWifi = isValidatedWifi
			_isOnMobile = !isValidatedWifi && isValidatedCell
		} else {
			_isOnWifi = isAnyWifi
			_isOnMobile = !isAnyWifi && isAnyCell
		}
	}

	private fun currentTransportLabel(): String {
		return when {
			_isOnWifi -> "Wi-Fi"
			_isOnMobile -> "Mobile"
			else -> "Default"
		}
	}

	@Synchronized
	private fun startOrReloadTunnel() {
		val app = BlockerApp.instance
		val cfg = app.prefs.state.value
		if (!cfg.isVpnDesired || cfg.snoozeUntilMs > System.currentTimeMillis())
			return

		val transportLabel = currentTransportLabel()
		val isPausedForNet = (_isOnWifi && !cfg.isWifiProtection) || (_isOnMobile && !cfg.isMobileProtection)
		if (isPausedForNet) {
			stopTunnelOnly()
			_proxy?.stop()
			_proxy = null
			_runtime.value = VpnRuntimeState(
				isRunning = true,
				isPausedByNetworkRule = true,
				activeTransport = transportLabel,
				proxyPort = 0,
				sessionBlocked = _sessionBlocked.get(),
			)
			updateNotification(
				title = "TrueBlock · Paused ($transportLabel)",
				text = formatPausedOrSnoozedText("Paused on $transportLabel", _lastStats),
				isSnoozed = false,
			)
			return
		}

		_dnsCache.resize(cfg.dnsCacheSize.coerceIn(64, 16384))
		val dohHttp = _dohHttp ?: DnsWire.createProtectedHttpClient(
			protectSocket = { sock -> protect(sock) },
			protectDatagram = { dg -> protect(dg) },
		).also { _dohHttp = it }

		val cm = getSystemService(ConnectivityManager::class.java)
		val resolveHostFn: (String) -> InetAddress? = { host ->
			val liveCfg = app.prefs.state.value
			val dnsPair = liveCfg.activeDnsServers(_isOnWifi, _isOnMobile)
			val dohEndpoint = liveCfg.activeDohEndpoint(_isOnWifi, _isOnMobile)
			DnsWire.resolveHostForProxy(
				host = host,
				primaryDns = dnsPair.first,
				secondaryDns = dnsPair.second,
				dohUrl = dohEndpoint,
				dohClient = dohHttp,
				protectDatagram = { dg -> protect(dg) },
				cache = _dnsCache,
				timeoutMs = liveCfg.upstreamDnsTimeoutMs,
				cacheTtlSec = liveCfg.dnsCacheTtlSec,
				protectSocket = { sock -> protect(sock) },
				isStrictDoh = liveCfg.isStrictDoh,
			)
		}

		val isNeedHttpProxy = cfg.isHttpsFiltering || cfg.hasActiveUpstreamProxy()
		val localProxyPort = if (isNeedHttpProxy) {
			val proxy = _proxy ?: MitmProxy(
				_engine = app.engine,
				_ca = app.ca,
				_prefs = app.prefs,
				_traffic = app.traffic,
				_cm = cm,
				_pm = packageManager,
				_protectSocket = { sock -> protect(sock) },
				_transportProvider = { _isOnWifi to _isOnMobile },
				_onBlockedHit = { incrementSessionBlocked() },
				_resolveHostIp = resolveHostFn,
			).also { _proxy = it }
			proxy.start()
		} else {
			_proxy?.stop()
			_proxy = null
			0
		}

		val isFullL3 = cfg.shouldEnableFullL3Capture(_isOnWifi, _isOnMobile)
		val isEffectiveBlockIpv6 = cfg.isBlockIpv6 || isFullL3
		val rawClientIp = cfg.vpnClientIp.trim().ifEmpty { DEFAULT_VPN_CLIENT_IP }
		val rawDnsIp = cfg.vpnDnsIp.trim().ifEmpty { DEFAULT_VPN_DNS_IP }
		val isValidCustomPair = CertAuthority.isIpv4Literal(rawClientIp) &&
			CertAuthority.isIpv4Literal(rawDnsIp) &&
			rawClientIp != rawDnsIp
		val clientIp = if (isValidCustomPair) rawClientIp else DEFAULT_VPN_CLIENT_IP
		val dnsIp = if (isValidCustomPair) rawDnsIp else DEFAULT_VPN_DNS_IP
		val mtu = cfg.vpnMtu.coerceIn(1280, 9000)

		val desiredSpec = ActiveTunnelSpec(
			isFullL3 = isFullL3,
			clientIp = clientIp,
			dnsIp = dnsIp,
			mtu = mtu,
			isBlockIpv6 = isEffectiveBlockIpv6,
			proxyPort = localProxyPort,
			bypassedApps = cfg.bypassedApps,
		)

		if (_tunFd != null && _loopFlag?.get() == true && _activeSpec == desiredSpec) {
			publishActiveRuntimeAndNotification(cfg, app, isFullL3, transportLabel, localProxyPort)
			return
		}

		val builder = Builder()
			.setSession("TrueBlock")
			.setMtu(mtu)
			.setBlocking(true)
			.setMetered(false)

		var effectiveClientIp = clientIp
		var effectiveDnsIp = dnsIp
		val isIpApplied = runCatching {
			builder.addAddress(clientIp, 30)
			builder.addDnsServer(dnsIp)
			if (isFullL3)
				builder.addRoute("0.0.0.0", 0)
			else
				builder.addRoute(dnsIp, 32)
		}.isSuccess

		if (!isIpApplied) {
			effectiveClientIp = DEFAULT_VPN_CLIENT_IP
			effectiveDnsIp = DEFAULT_VPN_DNS_IP
			builder.addAddress(DEFAULT_VPN_CLIENT_IP, 30)
			builder.addDnsServer(DEFAULT_VPN_DNS_IP)
			if (isFullL3)
				builder.addRoute("0.0.0.0", 0)
			else
				builder.addRoute(DEFAULT_VPN_DNS_IP, 32)
		}

		if (isEffectiveBlockIpv6) {
			runCatching {
				builder.addAddress("fd00:1:fd00::2", 126)
				builder.addRoute("::", 0)
			}
		}

		if (localProxyPort > 0)
			builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", localProxyPort))

		runCatching { builder.addDisallowedApplication(packageName) }
		for (pkg in cfg.bypassedApps) {
			if (pkg.isNotBlank() && pkg != packageName)
				runCatching { builder.addDisallowedApplication(pkg) }
		}

		// Establish new TUN interface BEFORE closing the old descriptor so kernel switches routes atomically without an unencrypted leak gap
		val newPfd = runCatching { builder.establish() }.getOrNull()
		if (newPfd == null) {
			stopTunnelOnly()
			_runtime.value = VpnRuntimeState(isRunning = false)
			return
		}

		stopTunnelOnly()

		_tunFd = newPfd
		_activeSpec = desiredSpec.copy(clientIp = effectiveClientIp, dnsIp = effectiveDnsIp)
		val loopActive = AtomicBoolean(true)
		_loopFlag = loopActive

		val workerCount = cfg.dnsWorkerThreads.coerceIn(2, 32)
		val workers = Executors.newFixedThreadPool(workerCount)
		_dnsWorkers = workers

		val writeLock = Any()
		val output = FileOutputStream(newPfd.fileDescriptor)
		val writeTunFn: (ByteArray) -> Unit = { pktBytes ->
			synchronized(writeLock) {
				runCatching { output.write(pktBytes) }
			}
		}

		val dispatchDnsFrameFn: (IpUdpFrame) -> Unit = frameDispatch@{ frame ->
			val parsed = DnsWire.parseDnsQuery(frame.payload) ?: return@frameDispatch
			val liveCfg = app.prefs.state.value
			val ownerPkg = resolveUdpOwner(cm, frame, liveCfg.bypassedApps)

			val syncReply = evaluateSyncDnsDecision(app, liveCfg, frame.payload, parsed, ownerPkg)
			if (syncReply != null) {
				val ipReply = DnsWire.buildIpv4Udp(frame.dstIp, frame.srcIp, frame.dstPort, frame.srcPort, syncReply)
				writeTunFn(ipReply)
				return@frameDispatch
			}

			runCatching {
				workers.execute {
					val asyncReply = resolveAsyncDnsDecision(app, liveCfg, dohHttp, resolveHostFn, frame.payload, parsed, ownerPkg) ?: return@execute
					val ipReply = DnsWire.buildIpv4Udp(frame.dstIp, frame.srcIp, frame.dstPort, frame.srcPort, asyncReply)
					writeTunFn(ipReply)
				}
			}
		}

		val localDnsTcpFn: (ByteArray, String) -> ByteArray? = { rawQuery, ownerPkg ->
			val parsed = DnsWire.parseDnsQuery(rawQuery)
			if (parsed == null) {
				null
			} else {
				val liveCfg = app.prefs.state.value
				evaluateSyncDnsDecision(app, liveCfg, rawQuery, parsed, ownerPkg)
					?: resolveAsyncDnsDecision(app, liveCfg, dohHttp, resolveHostFn, rawQuery, parsed, ownerPkg)
			}
		}

		val l3 = TunL3Router(
			_configProvider = { app.prefs.state.value },
			_pushTraffic = { sample -> app.traffic.push(sample) },
			_cm = cm,
			_pm = packageManager,
			_protectSocket = { sock -> protect(sock) },
			_protectDatagram = { dg -> protect(dg) },
			_transportProvider = { _isOnWifi to _isOnMobile },
			_onBlockedHit = { incrementSessionBlocked() },
			_writeTunPacket = writeTunFn,
			tunMtu = mtu,
			_engine = app.engine,
			_isCaReady = { app.ca.isReady },
			_localProxyPortProvider = { _proxy?.port ?: 0 },
			_resolveHostIp = resolveHostFn,
			_onDnsFrame = dispatchDnsFrameFn,
			_localDnsTcpHandler = localDnsTcpFn,
		).also { _l3Router = it }

		val thread = Thread({
			val input = FileInputStream(newPfd.fileDescriptor)
			val readBuf = ByteArray(mtu.coerceAtLeast(4096))

			while (loopActive.get()) {
				val len = try {
					input.read(readBuf)
				} catch (_: Throwable) {
					break
				}
				if (len <= 0)
					continue

				val ver = (readBuf[0].toInt() ushr 4) and 0x0F
				if (ver == 6) {
					l3.handleIpv6Packet(readBuf, len)
					continue
				}
				if (ver != 4)
					continue

				val frame = DnsWire.parseIpv4Udp(readBuf, len)
				if (frame == null || frame.dstPort != 53) {
					l3.handleIpv4Packet(readBuf, len)
					continue
				}

				dispatchDnsFrameFn(frame)
			}
		}, "TrueBlock-TunReader")

		thread.isDaemon = true
		thread.start()
		_readerThread = thread

		publishActiveRuntimeAndNotification(cfg, app, isFullL3, transportLabel, localProxyPort)
	}

	private fun evaluateSyncDnsDecision(
		app: BlockerApp,
		liveCfg: AppConfig,
		rawQuery: ByteArray,
		parsed: ParsedDnsQuery,
		ownerPkg: String,
	): ByteArray? {
		if (liveCfg.isAppBypassed(ownerPkg))
			return null

		val qHost = parsed.qname
		if (liveCfg.isAppFirewalled(ownerPkg, _isOnWifi, _isOnMobile)) {
			incrementSessionBlocked()
			app.traffic.push(
				TrafficSample(
					target = qHost,
					host = qHost,
					proto = "DNS",
					isBlocked = true,
					isRoute = false,
					appPkg = ownerPkg,
					matchedRule = "Per-App Firewall",
				)
			)
			return DnsWire.buildBlockedDnsReply(rawQuery, parsed, liveCfg.blockedDnsMode)
		}

		val verdict = app.engine.matchDns(qHost)
		if (verdict.isBlocked) {
			incrementSessionBlocked()
			app.traffic.push(
				TrafficSample(
					target = qHost,
					host = qHost,
					proto = "DNS",
					isBlocked = true,
					isRoute = false,
					appPkg = ownerPkg,
					matchedRule = verdict.summaryText(),
				)
			)
			return DnsWire.buildBlockedDnsReply(rawQuery, parsed, liveCfg.blockedDnsMode)
		}

		val isBlockAaaa = liveCfg.isBlockIpv6 || liveCfg.shouldEnableFullL3Capture(_isOnWifi, _isOnMobile)
		if (
			(isBlockAaaa && parsed.qtype == DnsWire.TYPE_AAAA) ||
			(
				liveCfg.isHttpsFiltering &&
				liveCfg.isStripHttpsDnsRecord &&
				(parsed.qtype == DnsWire.TYPE_HTTPS || parsed.qtype == DnsWire.TYPE_SVCB)
			)
		) {
			return DnsWire.buildEmptyNoDataDns(rawQuery, parsed)
		}

		return null
	}

	private fun resolveAsyncDnsDecision(
		app: BlockerApp,
		liveCfg: AppConfig,
		dohHttp: okhttp3.OkHttpClient,
		resolveHostFn: (String) -> InetAddress?,
		rawQuery: ByteArray,
		parsed: ParsedDnsQuery,
		ownerPkg: String,
	): ByteArray? {
		val dnsPair = liveCfg.activeDnsServers(_isOnWifi, _isOnMobile)
		val dohEndpoint = liveCfg.activeDohEndpoint(_isOnWifi, _isOnMobile)
		val isBypassed = liveCfg.isAppBypassed(ownerPkg)
		val dnsProxy = if (isBypassed) {
			null
		} else {
			UpstreamProxy.selectProxy(liveCfg.proxies, ownerPkg, parsed.qname, 443, liveCfg.bypassedApps)
				?.takeIf { it.isRemoteDns }
		}

		var isResolvedViaProxy = false
		var upstreamBytes: ByteArray? = null
		if (dnsProxy != null) {
			val proxyCacheKey = "proxy:${dnsProxy.id}:${parsed.qname}:${parsed.qtype}:${parsed.qclass}"
			val now = System.currentTimeMillis()
			upstreamBytes = DnsWire.getCachedDnsWire(_dnsCache, proxyCacheKey, rawQuery, now)
			if (upstreamBytes != null) {
				isResolvedViaProxy = true
			} else {
				val blockedUntil = _proxyDnsPortBlockedUntil[dnsProxy.id] ?: 0L
				if (blockedUntil <= now) {
					upstreamBytes = UpstreamProxy.queryDnsOverProxyTcp(
						profile = dnsProxy,
						rawQuery = rawQuery,
						dnsIp = dnsPair.first,
						timeoutMs = liveCfg.upstreamDnsTimeoutMs,
						protectSocket = { sock -> protect(sock) },
						resolveHost = resolveHostFn,
					) ?: if (dnsPair.second.isNotBlank() && dnsPair.second != dnsPair.first) {
						UpstreamProxy.queryDnsOverProxyTcp(
							profile = dnsProxy,
							rawQuery = rawQuery,
							dnsIp = dnsPair.second,
							timeoutMs = liveCfg.upstreamDnsTimeoutMs,
							protectSocket = { sock -> protect(sock) },
							resolveHost = resolveHostFn,
						)
					} else {
						null
					}
					if (upstreamBytes != null) {
						isResolvedViaProxy = true
						DnsWire.storeDnsCacheEntry(_dnsCache, proxyCacheKey, upstreamBytes, now, liveCfg.dnsCacheTtlSec)
					} else if (dnsProxy.type.equals("HTTP", ignoreCase = true)) {
						_proxyDnsPortBlockedUntil[dnsProxy.id] = now + 60_000L
					}
				}
			}
		}

		if (upstreamBytes == null) {
			upstreamBytes = DnsWire.resolveUpstream(
				rawQuery = rawQuery,
				parsed = parsed,
				primaryDns = dnsPair.first,
				secondaryDns = dnsPair.second,
				dohUrl = dohEndpoint,
				dohClient = dohHttp,
				protectDatagram = { dg -> protect(dg) },
				cache = _dnsCache,
				timeoutMs = liveCfg.upstreamDnsTimeoutMs,
				cacheTtlSec = liveCfg.dnsCacheTtlSec,
				protectSocket = { sock -> protect(sock) },
				isStrictDoh = liveCfg.isStrictDoh,
			) ?: return null
		}

		if (isBypassed)
			return upstreamBytes

		val qHost = parsed.qname
		val verdict = app.engine.matchDns(qHost)
		val inspection = DnsWire.inspectDnsAnswer(
			dns = upstreamBytes,
			queryHost = qHost,
			maxCnames = liveCfg.maxCnameDepth,
			isRecordIpMapping = false,
			appPkg = ownerPkg,
		)
		val isExplicitlyAllowed = verdict.matchedRule.startsWith("@@")

		if (liveCfg.isCnameUncloaking && !isExplicitlyAllowed && inspection.cnameChain.isNotEmpty()) {
			var cnameHit: Pair<String, String>? = null
			for (alias in inspection.cnameChain) {
				val cv = app.engine.matchDns(alias)
				if (cv.isBlocked) {
					cnameHit = alias to cv.summaryText()
					break
				}
			}
			if (cnameHit != null) {
				incrementSessionBlocked()
				app.traffic.push(
					TrafficSample(
						target = qHost,
						host = qHost,
						proto = "CNAME",
						isBlocked = true,
						isRoute = false,
						appPkg = ownerPkg,
						matchedRule = "CNAME (${cnameHit.first}) • ${cnameHit.second}",
						isCname = true,
					)
				)
				return DnsWire.buildBlockedDnsReply(rawQuery, parsed, liveCfg.blockedDnsMode)
			}
		}

		for (ip in inspection.ipv4Addresses) {
			if (ip != "0.0.0.0")
				DnsWire.recordIpHost(ip, qHost, ownerPkg)
		}

		val protoLabel = when {
			isResolvedViaProxy -> "Proxy-DNS"
			dohEndpoint != null -> "DoH"
			else -> "DNS"
		}
		app.traffic.push(
			TrafficSample(
				target = qHost,
				host = qHost,
				proto = protoLabel,
				isBlocked = false,
				isRoute = false,
				appPkg = ownerPkg,
				matchedRule = verdict.summaryText(),
			)
		)

		return upstreamBytes
	}

	private fun publishActiveRuntimeAndNotification(
		cfg: AppConfig,
		app: BlockerApp,
		isFullL3: Boolean,
		transportLabel: String,
		localProxyPort: Int,
	) {
		_runtime.value = VpnRuntimeState(
			isRunning = true,
			isPausedByNetworkRule = false,
			isSnoozed = false,
			snoozeRemainingSec = 0,
			isL3CaptureActive = isFullL3,
			activeTransport = transportLabel,
			proxyPort = localProxyPort,
			sessionBlocked = _sessionBlocked.get(),
		)
		maybeRefreshActiveNotification(isForce = true)
		AdBlockTileService.requestRefresh(this)
	}

	private fun resolveUdpOwner(
		cm: ConnectivityManager?,
		frame: IpUdpFrame,
		bypassedApps: Set<String>,
	): String {
		if (cm == null)
			return ""

		return runCatching {
			val srcAddr = InetSocketAddress(InetAddress.getByAddress(frame.srcIp), frame.srcPort)
			val dstAddr = InetSocketAddress(InetAddress.getByAddress(frame.dstIp), frame.dstPort)
			val uid = cm.getConnectionOwnerUid(OsConstants.IPPROTO_UDP, srcAddr, dstAddr)
			if (uid <= 0)
				return ""
			val pkgs = packageManager.getPackagesForUid(uid)
			pkgs?.firstOrNull { bypassedApps.contains(it) }
				?: pkgs?.firstOrNull()
				?: if (uid == 1051) "System DNS" else ""
		}.getOrDefault("")
	}

	private fun stopTunnelOnly() {
		_loopFlag?.set(false)
		_loopFlag = null
		_activeSpec = null
		_l3Router?.closeAll()
		_l3Router = null
		runCatching { _tunFd?.close() }
		_tunFd = null
		_readerThread?.interrupt()
		_readerThread = null
		_dnsWorkers?.shutdownNow()
		_dnsWorkers = null
	}

	internal fun requestStop() {
		cancelSnoozeAlarmAndTicker()
		BlockerApp.instance.prefs.update { it.copy(isVpnDesired = false, snoozeUntilMs = 0L) }
		teardownAll()
		runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
		showStoppedNotification(this, _lastStats)
		stopSelf()
	}

	@Synchronized
	private fun teardownAll() {
		_configWatchJob?.cancel()
		_configWatchJob = null
		_dnsWatchJob?.cancel()
		_dnsWatchJob = null
		_statsWatchJob?.cancel()
		_statsWatchJob = null
		stopTunnelOnly()
		_proxy?.stop()
		_proxy = null
		_runtime.value = VpnRuntimeState(isRunning = false)
		AdBlockTileService.requestRefresh(this)
	}

	private fun ensureNotificationChannel() {
		ensureNotificationChannel(this)
	}

	private fun maybeRefreshActiveNotification(isForce: Boolean) {
		val state = _runtime.value
		if (!state.isRunning || state.isSnoozed || state.isPausedByNetworkRule)
			return
		val now = System.currentTimeMillis()
		if (!isForce) {
			val prev = _lastNotifUpdateMs.get()
			if (now - prev < NOTIF_UPDATE_MIN_INTERVAL_MS)
				return
		}
		_lastNotifUpdateMs.set(now)
		val title = "TrueBlock · Active (${state.activeTransport})"
		val text = formatActiveNotificationText(_lastStats, _sessionBlocked.get())
		updateNotification(title = title, text = text, isSnoozed = false)
	}

	private fun updateNotification(title: String, text: String, isSnoozed: Boolean, snoozeUntilMs: Long = 0L) {
		val nm = getSystemService(NotificationManager::class.java) ?: return
		runCatching { nm.notify(NOTIF_ID, buildNotification(title, text, isSnoozed, snoozeUntilMs)) }
	}

	private fun buildResumePendingIntent(): PendingIntent {
		return PendingIntent.getService(
			this,
			3,
			Intent(this, AdBlockVpnService::class.java).apply { action = ACTION_RESUME },
			PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
		)
	}

	private fun buildNotification(
		title: String,
		statusText: String,
		isSnoozed: Boolean,
		snoozeUntilMs: Long = 0L,
	): Notification {
		val openIntent = buildOpenAppPendingIntent(this)
		val stopIntent = PendingIntent.getService(
			this,
			2,
			Intent(this, AdBlockVpnService::class.java).apply { action = ACTION_STOP },
			PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
		)

		val builder = NotificationCompat.Builder(this, CHANNEL_ID)
			.setSmallIcon(android.R.drawable.ic_secure)
			.setContentTitle(title)
			.setContentText(statusText)
			.setStyle(NotificationCompat.BigTextStyle().bigText(statusText))
			.setOngoing(true)
			.setAutoCancel(false)
			.setSilent(true)
			.setOnlyAlertOnce(true)
			.setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
			.setContentIntent(openIntent)

		if (isSnoozed) {
			if (snoozeUntilMs > System.currentTimeMillis()) {
				builder.setWhen(snoozeUntilMs)
					.setShowWhen(true)
					.setUsesChronometer(true)
					.setChronometerCountDown(true)
			}
			builder.addAction(0, "Resume", buildResumePendingIntent())
		}

		builder.addAction(0, "Stop", stopIntent)

		return builder.build()
	}

	companion object {
		const val ACTION_START = "com.renwixx.trueadblocker.START_VPN"
		const val ACTION_STOP = "com.renwixx.trueadblocker.STOP_VPN"
		const val ACTION_SNOOZE = "com.renwixx.trueadblocker.SNOOZE_VPN"
		const val ACTION_RESUME = "com.renwixx.trueadblocker.RESUME_VPN"
		const val EXTRA_SNOOZE_MINUTES = "snooze_minutes"

		private const val CHANNEL_ID = "trueadblocker_vpn_channel"
		internal const val NOTIF_ID = 1001
		private const val NOTIF_UPDATE_MIN_INTERVAL_MS = 2_000L
		private const val DEFAULT_VPN_CLIENT_IP = "10.111.222.2"
		private const val DEFAULT_VPN_DNS_IP = "10.111.222.1"

		@Volatile
		var instance: AdBlockVpnService? = null
			private set

		private val _runtime = MutableStateFlow(VpnRuntimeState())
		val runtime: StateFlow<VpnRuntimeState> = _runtime.asStateFlow()

		fun start(ctx: Context) {
			val i = Intent(ctx, AdBlockVpnService::class.java).apply { action = ACTION_START }
			ctx.startForegroundService(i)
		}

		fun stop(ctx: Context) {
			BlockerApp.instance.prefs.update { it.copy(isVpnDesired = false, snoozeUntilMs = 0L) }
			val active = instance
			if (active != null) {
				active.requestStop()
				return
			}
			_runtime.value = VpnRuntimeState(isRunning = false)
			AdBlockTileService.requestRefresh(ctx)
			showStoppedNotification(ctx)
			ctx.stopService(Intent(ctx, AdBlockVpnService::class.java))
		}

		fun showStoppedNotification(ctx: Context, stats: NotificationStats = NotificationStats()) {
			ensureNotificationChannel(ctx)
			val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
			val openIntent = buildOpenAppPendingIntent(ctx)
			val startActionIntent = if (runCatching { VpnService.prepare(ctx) == null }.getOrDefault(false)) {
				PendingIntent.getForegroundService(
					ctx,
					4,
					Intent(ctx, AdBlockVpnService::class.java).apply { action = ACTION_START },
					PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
				)
			} else {
				openIntent
			}
			val text = formatPausedOrSnoozedText("Filtering stopped", stats)
			val notif = NotificationCompat.Builder(ctx, CHANNEL_ID)
				.setSmallIcon(android.R.drawable.ic_secure)
				.setContentTitle("TrueBlock · Stopped")
				.setContentText(text)
				.setStyle(NotificationCompat.BigTextStyle().bigText(text))
				.setOngoing(true)
				.setAutoCancel(false)
				.setSilent(true)
				.setOnlyAlertOnce(true)
				.setContentIntent(openIntent)
				.addAction(0, "Start", startActionIntent)
				.build()
			runCatching { nm.notify(NOTIF_ID, notif) }
		}

		internal fun formatActiveNotificationText(stats: NotificationStats, sessionBlocked: Long): String {
			val blocked = stats.totalBlocked.coerceAtLeast(sessionBlocked)
			val total = stats.totalRequests.coerceAtLeast(blocked)
			val sb = StringBuilder()
			sb.append("Blocked ")
			sb.append(formatCompactCount(blocked))
			sb.append(" / ")
			sb.append(formatCompactCount(total))
			if (total > 0L) {
				val pct = (blocked * 100L / total).coerceIn(0L, 100L)
				sb.append(" (").append(pct).append("%)")
			}
			sb.append(" · Session ").append(formatCompactCount(sessionBlocked))
			if (stats.totalTrackerParams > 0L)
				sb.append(" · Params ").append(formatCompactCount(stats.totalTrackerParams))
			if (stats.totalCname > 0L)
				sb.append(" · CNAME ").append(formatCompactCount(stats.totalCname))

			return sb.toString()
		}

		internal fun formatPausedOrSnoozedText(prefix: String, stats: NotificationStats): String {
			val blocked = stats.totalBlocked
			val total = stats.totalRequests.coerceAtLeast(blocked)
			if (total <= 0L)
				return prefix

			return "$prefix · Blocked ${formatCompactCount(blocked)} / ${formatCompactCount(total)}"
		}

		internal fun formatCompactCount(value: Long): String {
			val n = value.coerceAtLeast(0L)
			return when {
				n >= 1_000_000L -> String.format(java.util.Locale.US, "%.1fM", n / 1_000_000.0)
				n >= 10_000L -> "${n / 1_000L}K"
				n >= 1_000L -> String.format(java.util.Locale.US, "%.1fK", n / 1_000.0)
				else -> n.toString()
			}
		}

		private fun ensureNotificationChannel(ctx: Context) {
			val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
			val channel = NotificationChannel(
				CHANNEL_ID,
				"TrueBlock Protection",
				NotificationManager.IMPORTANCE_LOW,
			).apply {
				description = "Persistent local VPN ad & route filtering status"
				setShowBadge(false)
			}
			nm.createNotificationChannel(channel)
		}

		private fun buildOpenAppPendingIntent(ctx: Context): PendingIntent {
			return PendingIntent.getActivity(
				ctx,
				1,
				Intent(ctx, MainActivity::class.java).apply {
					flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
				},
				PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
			)
		}

		fun snooze(ctx: Context, minutes: Int) {
			val i = Intent(ctx, AdBlockVpnService::class.java).apply {
				action = ACTION_SNOOZE
				putExtra(EXTRA_SNOOZE_MINUTES, minutes)
			}
			ctx.startForegroundService(i)
		}

		fun resume(ctx: Context) {
			val i = Intent(ctx, AdBlockVpnService::class.java).apply { action = ACTION_RESUME }
			ctx.startForegroundService(i)
		}
	}
}
