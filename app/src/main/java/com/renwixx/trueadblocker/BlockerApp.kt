package com.renwixx.trueadblocker

import android.app.Application
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.renwixx.trueadblocker.data.AppDatabase
import com.renwixx.trueadblocker.data.AppPrefs
import com.renwixx.trueadblocker.data.TrafficPipeline
import com.renwixx.trueadblocker.engine.RuleEngine
import com.renwixx.trueadblocker.net.AdBlockVpnService
import com.renwixx.trueadblocker.net.CertAuthority
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class BlockerApp : Application() {
	lateinit var db: AppDatabase
		private set
	lateinit var prefs: AppPrefs
		private set
	lateinit var traffic: TrafficPipeline
		private set
	lateinit var engine: RuleEngine
		private set
	lateinit var ca: CertAuthority
		private set

	private val _appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

	override fun onCreate() {
		super.onCreate()
		instance = this

		db = AppDatabase.get(this)
		prefs = AppPrefs(this)
		traffic = TrafficPipeline(db.trafficDao(), db.trackerParamDao(), prefs)
		engine = RuleEngine(this, db)
		ca = CertAuthority(this, isAutoLoad = false)
		if (!AdBlockVpnService.runtime.value.isRunning)
			AdBlockVpnService.showStoppedNotification(this)

		_appScope.launch {
			ca.loadExistingIfPresent()
			engine.reloadCustomRulesOnly()
			engine.ensureCatalogSeeded()
			engine.reloadBlocklists()
			if (hasValidatedInternet()) {
				val isDone = engine.syncAllEnabled(isForce = false)
				if (isDone && prefs.state.value.lastAutoSyncMs == 0L && engine.areAllEnabledCached())
					prefs.update { it.copy(lastAutoSyncMs = System.currentTimeMillis()) }
			}
		}

		_appScope.launch {
			while (isActive) {
				delay(60_000L)
				val cfg = prefs.state.value
				if (engine.stats.value.isSyncing || !hasValidatedInternet())
					continue
				if (!engine.areAllEnabledCached()) {
					val isSeeded = engine.syncAllEnabled(isForce = false)
					if (isSeeded && engine.areAllEnabledCached() && cfg.lastAutoSyncMs == 0L)
						prefs.update { it.copy(lastAutoSyncMs = System.currentTimeMillis()) }
					continue
				}
				if (!cfg.isAutoUpdateLists)
					continue
				val intervalMs = cfg.autoUpdateIntervalHours.coerceAtLeast(1) * 3_600_000L
				val now = System.currentTimeMillis()
				if (now - cfg.lastAutoSyncMs >= intervalMs) {
					val isCompleted = engine.syncAllEnabled(isForce = true)
					if (isCompleted)
						prefs.update { it.copy(lastAutoSyncMs = System.currentTimeMillis()) }
				}
			}
		}
	}

	private fun hasValidatedInternet(): Boolean {
		val cm = getSystemService(ConnectivityManager::class.java) ?: return true
		val active = cm.activeNetwork ?: return false
		val caps = cm.getNetworkCapabilities(active) ?: return false

		return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
			caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
	}

	companion object {
		lateinit var instance: BlockerApp
			private set
	}
}
