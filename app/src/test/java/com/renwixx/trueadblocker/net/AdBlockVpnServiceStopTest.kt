package com.renwixx.trueadblocker.net

import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import com.renwixx.trueadblocker.BlockerApp
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(application = BlockerApp::class, sdk = [34])
class AdBlockVpnServiceStopTest {

	@After
	fun tearDown() {
		AdBlockVpnService.instance?.requestStop()
		setRuntimeState(VpnRuntimeState(isRunning = false))
		setServiceInstance(null)
	}

	@Test
	fun stopTearsDownBoundServiceWithoutWaitingForOnDestroy() {
		val app = ApplicationProvider.getApplicationContext<BlockerApp>()
		val controller = Robolectric.buildService(AdBlockVpnService::class.java).create()
		val service = controller.get()

		val fakeFile = File(app.cacheDir, "fake_tun_fd.tmp").apply { writeBytes(byteArrayOf(1)) }
		val fakeTun = ParcelFileDescriptor.open(fakeFile, ParcelFileDescriptor.MODE_READ_WRITE)
		setPrivateField(service, "_tunFd", fakeTun)
		setServiceInstance(service)
		setRuntimeState(VpnRuntimeState(isRunning = true, activeTransport = "Wi-Fi"))
		app.prefs.update { it.copy(isVpnDesired = true, snoozeUntilMs = 0L) }

		// Simulate stopping while system_server still holds BIND_VPN_SERVICE (onDestroy not invoked)
		AdBlockVpnService.stop(app)

		assertFalse(AdBlockVpnService.runtime.value.isRunning)
		assertFalse(app.prefs.state.value.isVpnDesired)
		assertNull(getPrivateField(service, "_tunFd"))
		assertTrue(shadowOf(service).isStoppedBySelf)
		assertTrue(runCatching { fakeTun.fileDescriptor.valid() }.getOrDefault(false).not())
		val nm = app.getSystemService(NotificationManager::class.java)
		val stoppedNotif = shadowOf(nm).getNotification(AdBlockVpnService.NOTIF_ID)
		assertNotNull(stoppedNotif)
		assertEquals("TrueBlock · Stopped", stoppedNotif.extras.getString(Notification.EXTRA_TITLE))
		assertTrue((stoppedNotif.flags and Notification.FLAG_ONGOING_EVENT) != 0)
		assertTrue(stoppedNotif.actions?.any { it.title == "Start" } == true)
		fakeFile.delete()
	}

	@Test
	fun activeNotificationFormatsMicroStatsCleanly() {
		val text = AdBlockVpnService.formatActiveNotificationText(
			stats = NotificationStats(
				totalRequests = 8_400L,
				totalBlocked = 1_260L,
				totalCname = 5L,
				totalTrackerParams = 18L,
			),
			sessionBlocked = 42L,
		)
		assertEquals("Blocked 1.3K / 8.4K (15%) · Session 42 · Params 18 · CNAME 5", text)
		assertEquals("999", AdBlockVpnService.formatCompactCount(999L))
		assertEquals("1.2K", AdBlockVpnService.formatCompactCount(1_240L))
		assertEquals("12K", AdBlockVpnService.formatCompactCount(12_900L))
		assertEquals("1.5M", AdBlockVpnService.formatCompactCount(1_500_000L))
	}

	@Test
	fun stopResetsStaleRuntimeStateWhenInstanceIsNull() {
		val app = ApplicationProvider.getApplicationContext<BlockerApp>()
		setServiceInstance(null)
		setRuntimeState(VpnRuntimeState(isRunning = true, activeTransport = "Mobile"))
		app.prefs.update { it.copy(isVpnDesired = true, snoozeUntilMs = System.currentTimeMillis() + 60_000L) }

		AdBlockVpnService.stop(app)

		assertFalse(AdBlockVpnService.runtime.value.isRunning)
		assertFalse(app.prefs.state.value.isVpnDesired)
		assertTrue(app.prefs.state.value.snoozeUntilMs == 0L)
	}

	@Test
	fun actionStopOnStartCommandTearsDownImmediately() {
		val app = ApplicationProvider.getApplicationContext<BlockerApp>()
		val stopIntent = Intent(app, AdBlockVpnService::class.java).apply {
			action = AdBlockVpnService.ACTION_STOP
		}
		val controller = Robolectric.buildService(AdBlockVpnService::class.java, stopIntent).create()
		val service = controller.get()

		setServiceInstance(service)
		setRuntimeState(VpnRuntimeState(isRunning = true))
		app.prefs.update { it.copy(isVpnDesired = true) }

		controller.startCommand(0, 1)

		assertFalse(AdBlockVpnService.runtime.value.isRunning)
		assertFalse(app.prefs.state.value.isVpnDesired)
		assertTrue(shadowOf(service).isStoppedBySelf)
	}

	@Suppress("UNCHECKED_CAST")
	private fun setRuntimeState(state: VpnRuntimeState) {
		val field = AdBlockVpnService::class.java.getDeclaredField("_runtime")
		field.isAccessible = true
		val flow = field.get(null) as MutableStateFlow<VpnRuntimeState>
		flow.value = state
	}

	private fun setServiceInstance(service: AdBlockVpnService?) {
		val field = AdBlockVpnService::class.java.getDeclaredField("instance")
		field.isAccessible = true
		field.set(null, service)
	}

	private fun setPrivateField(target: Any, name: String, value: Any?) {
		val field = target.javaClass.getDeclaredField(name)
		field.isAccessible = true
		field.set(target, value)
	}

	private fun getPrivateField(target: Any, name: String): Any? {
		val field = target.javaClass.getDeclaredField(name)
		field.isAccessible = true
		return field.get(target)
	}
}
