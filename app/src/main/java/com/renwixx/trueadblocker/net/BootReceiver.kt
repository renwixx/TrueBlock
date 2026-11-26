package com.renwixx.trueadblocker.net

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.renwixx.trueadblocker.BlockerApp

class BootReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent?) {
		val act = intent?.action ?: return
		if (act != Intent.ACTION_BOOT_COMPLETED && act != Intent.ACTION_MY_PACKAGE_REPLACED)
			return

		val cfg = BlockerApp.instance.prefs.state.value
		if (cfg.isStartOnBoot && cfg.isVpnDesired && VpnService.prepare(context) == null)
			AdBlockVpnService.start(context)
	}
}
