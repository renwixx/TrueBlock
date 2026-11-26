package com.renwixx.trueadblocker.net

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.renwixx.trueadblocker.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class AdBlockTileService : TileService() {
	private var _listenScope: CoroutineScope? = null
	private var _collectJob: Job? = null

	override fun onTileAdded() {
		super.onTileAdded()
		syncTile(AdBlockVpnService.runtime.value)
	}

	override fun onStartListening() {
		super.onStartListening()
		_collectJob?.cancel()
		_listenScope?.cancel()
		val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
		_listenScope = scope
		_collectJob = scope.launch {
			AdBlockVpnService.runtime.collect { state ->
				syncTile(state)
			}
		}
	}

	override fun onStopListening() {
		_collectJob?.cancel()
		_collectJob = null
		_listenScope?.cancel()
		_listenScope = null
		super.onStopListening()
	}

	override fun onClick() {
		super.onClick()
		if (isLocked) {
			unlockAndRun { handleUnlockedClick() }
			return
		}
		handleUnlockedClick()
	}

	private fun handleUnlockedClick() {
		val cur = AdBlockVpnService.runtime.value
		if (cur.isRunning) {
			if (cur.isSnoozed) {
				AdBlockVpnService.resume(this)
			} else {
				AdBlockVpnService.stop(this)
				syncTile(VpnRuntimeState(isRunning = false))
			}
			return
		}

		val prepIntent = VpnService.prepare(this)
		if (prepIntent == null) {
			AdBlockVpnService.start(this)
			syncTile(cur.copy(isRunning = true))
			return
		}

		val openIntent = Intent(this, MainActivity::class.java).apply {
			flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
		}
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
			val pi = PendingIntent.getActivity(
				this,
				101,
				openIntent,
				PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
			)
			startActivityAndCollapse(pi)
		} else {
			@Suppress("DEPRECATION")
			startActivityAndCollapse(openIntent)
		}
	}

	private fun syncTile(state: VpnRuntimeState) {
		val tile = qsTile ?: return
		tile.label = "TrueBlock"
		when {
			!state.isRunning -> {
				tile.state = Tile.STATE_INACTIVE
				tile.subtitle = "Off"
			}
			state.isSnoozed -> {
				tile.state = Tile.STATE_INACTIVE
				val mm = state.snoozeRemainingSec / 60
				val ss = state.snoozeRemainingSec % 60
				tile.subtitle = "Snoozed %d:%02d".format(mm, ss)
			}
			state.isPausedByNetworkRule -> {
				tile.state = Tile.STATE_ACTIVE
				tile.subtitle = "Paused (${state.activeTransport})"
			}
			else -> {
				tile.state = Tile.STATE_ACTIVE
				tile.subtitle = "Active (${state.activeTransport})"
			}
		}
		tile.updateTile()
	}

	companion object {
		fun requestRefresh(ctx: Context) {
			runCatching {
				requestListeningState(ctx, ComponentName(ctx, AdBlockTileService::class.java))
			}
		}
	}
}
