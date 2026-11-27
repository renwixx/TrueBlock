package com.renwixx.trueadblocker.data

import com.renwixx.trueadblocker.engine.BUILTIN_BLOCKLISTS
import com.renwixx.trueadblocker.engine.REMOVED_BLOCKLIST_IDS
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppConfigAndDataTest {
	@Test
	fun bypassFirewallAndL3CaptureDecisionMatrix() {
		val enabledProxy = ProxyProfile(id = "p1", name = "P1", isEnabled = true, host = "127.0.0.1", port = 1080, isAllApps = true)
		val disabledProxy = enabledProxy.copy(isEnabled = false)
		val blankHostProxy = enabledProxy.copy(host = "   ")
		val emptyAppsProxy = enabledProxy.copy(isAllApps = false, appPackages = emptySet())
		val appScopedProxy = enabledProxy.copy(isAllApps = false, appPackages = setOf("com.app"))

		assertFalse(AppConfig(proxies = listOf(disabledProxy, blankHostProxy, emptyAppsProxy)).hasActiveUpstreamProxy())
		assertTrue(AppConfig(proxies = listOf(enabledProxy)).hasActiveUpstreamProxy())
		assertTrue(AppConfig(proxies = listOf(appScopedProxy)).hasActiveUpstreamProxy())

		val cfg = AppConfig(
			bypassedApps = setOf("com.bypass"),
			firewallWifiApps = setOf("com.wifi.only", "com.both", "com.bypass"),
			firewallMobileApps = setOf("com.mobile.only", "com.both", "com.bypass"),
		)

		assertFalse(cfg.isAppBypassed(""))
		assertTrue(cfg.isAppBypassed("com.bypass"))
		assertFalse(cfg.isAppBypassed("com.other"))

		assertFalse(cfg.isAppFirewalled("", isOnWifi = true, isOnMobile = true))
		assertFalse(cfg.isAppFirewalled("com.bypass", isOnWifi = true, isOnMobile = true))
		assertTrue(cfg.isAppFirewalled("com.wifi.only", isOnWifi = true, isOnMobile = false))
		assertFalse(cfg.isAppFirewalled("com.wifi.only", isOnWifi = false, isOnMobile = true))
		assertTrue(cfg.isAppFirewalled("com.mobile.only", isOnWifi = false, isOnMobile = true))
		assertFalse(cfg.isAppFirewalled("com.wifi.only", isOnWifi = false, isOnMobile = false))
		assertTrue(cfg.isAppFirewalled("com.both", isOnWifi = false, isOnMobile = false))

		assertTrue(AppConfig(l3RoutingMode = L3_MODE_ALWAYS).shouldEnableFullL3Capture(false, false))
		assertFalse(AppConfig(l3RoutingMode = L3_MODE_OFF, proxies = listOf(enabledProxy)).shouldEnableFullL3Capture(true, true))
		assertFalse(
			AppConfig(
				l3RoutingMode = L3_MODE_AUTO,
				bypassedApps = setOf("com.bypass"),
				firewallWifiApps = setOf("com.bypass"),
			).shouldEnableFullL3Capture(isOnWifi = true, isOnMobile = false),
		)
		assertTrue(
			AppConfig(
				l3RoutingMode = L3_MODE_AUTO,
				firewallWifiApps = setOf("com.wifi"),
			).shouldEnableFullL3Capture(isOnWifi = true, isOnMobile = false),
		)
		assertFalse(
			AppConfig(
				l3RoutingMode = L3_MODE_AUTO,
				firewallWifiApps = setOf("com.wifi"),
			).shouldEnableFullL3Capture(isOnWifi = false, isOnMobile = true),
		)
		assertTrue(
			AppConfig(
				l3RoutingMode = L3_MODE_AUTO,
				firewallMobileApps = setOf("com.mob"),
			).shouldEnableFullL3Capture(isOnWifi = false, isOnMobile = false),
		)
		assertTrue(AppConfig(l3RoutingMode = L3_MODE_AUTO, proxies = listOf(enabledProxy)).shouldEnableFullL3Capture(false, false))
	}

	@Test
	fun activeDnsServersAndDohEndpointRespectOverridesPresetsAndFallbacks() {
		val custom = AppConfig(
			dnsPresetKey = "custom",
			customDnsIp = "9.9.9.9",
			customSecondaryDnsIp = "",
			isUseDoh = true,
			customDohUrl = "https://custom.doh.test/dns-query",
			isWifiCustomOverride = true,
			wifiDnsIp = "192.168.1.1",
			wifiSecondaryDnsIp = "",
			isWifiUseDoh = true,
			wifiDohUrl = "https://wifi.doh.test/dns-query",
			isMobileCustomOverride = true,
			mobileDnsIp = "10.0.0.53",
			mobileSecondaryDnsIp = "10.0.0.54",
			isMobileUseDoh = false,
		)

		assertEquals("192.168.1.1" to "", custom.activeDnsServers(isOnWifi = true, isOnMobile = false))
		assertEquals("10.0.0.53" to "10.0.0.54", custom.activeDnsServers(isOnWifi = false, isOnMobile = true))
		assertEquals("9.9.9.9" to "", custom.activeDnsServers(isOnWifi = false, isOnMobile = false))

		assertEquals("https://wifi.doh.test/dns-query", custom.activeDohEndpoint(isOnWifi = true, isOnMobile = false))
		assertNull(custom.activeDohEndpoint(isOnWifi = false, isOnMobile = true))
		assertEquals("https://custom.doh.test/dns-query", custom.activeDohEndpoint(isOnWifi = false, isOnMobile = false))

		val presetQuad9 = AppConfig(dnsPresetKey = "quad9", isUseDoh = true)
		assertEquals("9.9.9.9" to "149.112.112.112", presetQuad9.activeDnsServers(false, false))
		assertEquals("https://dns.quad9.net/dns-query", presetQuad9.activeDohEndpoint(false, false))

		val unknownPreset = AppConfig(dnsPresetKey = "nonexistent", isUseDoh = true)
		assertEquals("1.1.1.1" to "1.0.0.1", unknownPreset.activeDnsServers(false, false))
		assertEquals("https://cloudflare-dns.com/dns-query", unknownPreset.activeDohEndpoint(false, false))

		val insecureDoh = AppConfig(dnsPresetKey = "custom", customDohUrl = "http://plain.example/dns", isUseDoh = true)
		assertEquals("https://cloudflare-dns.com/dns-query", insecureDoh.activeDohEndpoint(false, false))

		assertNull(AppConfig(isUseDoh = false).activeDohEndpoint(false, false))
	}

	@Test
	fun sanitizedClampsAllNumericBoundsAndSyncsPureOledFlag() {
		val low = AppConfig(
			themeMode = -5,
			maxCnameDepth = 0,
			maxGenericCosmeticSelectors = 1,
			maxAggEntries = 1,
			maxRawEntries = 1,
			logFlushIntervalMs = 1,
			logMaxBatchSize = 1,
			autoUpdateIntervalHours = 0,
			vpnMtu = 500,
			dnsWorkerThreads = 0,
			l3RoutingMode = -1,
			dnsCacheSize = 1,
			dnsCacheTtlSec = 0,
			blockedDnsMode = -2,
			upstreamDnsTimeoutMs = 10,
			proxyConnectTimeoutMs = 10,
			proxyReadTimeoutMs = 10,
			leafCertValidityDays = 0,
		).sanitized()

		assertEquals(THEME_OLED, low.themeMode)
		assertTrue(low.isPureOled)
		assertEquals(1, low.maxCnameDepth)
		assertEquals(50, low.maxGenericCosmeticSelectors)
		assertEquals(10_000, low.maxAggEntries)
		assertEquals(1000, low.maxRawEntries)
		assertEquals(50, low.logFlushIntervalMs)
		assertEquals(32, low.logMaxBatchSize)
		assertEquals(1, low.autoUpdateIntervalHours)
		assertEquals(1280, low.vpnMtu)
		assertEquals(2, low.dnsWorkerThreads)
		assertEquals(0, low.l3RoutingMode)
		assertEquals(64, low.dnsCacheSize)
		assertEquals(5, low.dnsCacheTtlSec)
		assertEquals(0, low.blockedDnsMode)
		assertEquals(500, low.upstreamDnsTimeoutMs)
		assertEquals(1000, low.proxyConnectTimeoutMs)
		assertEquals(2000, low.proxyReadTimeoutMs)
		assertEquals(1, low.leafCertValidityDays)

		val high = AppConfig(
			themeMode = 99,
			maxCnameDepth = 99,
			maxGenericCosmeticSelectors = 99_999,
			maxAggEntries = 99_999_999,
			maxRawEntries = 99_999_999,
			logFlushIntervalMs = 99_999,
			logMaxBatchSize = 99_999,
			autoUpdateIntervalHours = 99_999,
			vpnMtu = 99_999,
			dnsWorkerThreads = 999,
			l3RoutingMode = 99,
			dnsCacheSize = 99_999,
			dnsCacheTtlSec = 99_999,
			blockedDnsMode = 99,
			upstreamDnsTimeoutMs = 99_999,
			proxyConnectTimeoutMs = 99_999,
			proxyReadTimeoutMs = 99_999,
			leafCertValidityDays = 999,
		).sanitized()

		assertEquals(THEME_LIGHT, high.themeMode)
		assertFalse(high.isPureOled)
		assertEquals(16, high.maxCnameDepth)
		assertEquals(5000, high.maxGenericCosmeticSelectors)
		assertEquals(2_000_000, high.maxAggEntries)
		assertEquals(500_000, high.maxRawEntries)
		assertEquals(5000, high.logFlushIntervalMs)
		assertEquals(4096, high.logMaxBatchSize)
		assertEquals(720, high.autoUpdateIntervalHours)
		assertEquals(9000, high.vpnMtu)
		assertEquals(32, high.dnsWorkerThreads)
		assertEquals(2, high.l3RoutingMode)
		assertEquals(16384, high.dnsCacheSize)
		assertEquals(3600, high.dnsCacheTtlSec)
		assertEquals(2, high.blockedDnsMode)
		assertEquals(15_000, high.upstreamDnsTimeoutMs)
		assertEquals(30_000, high.proxyConnectTimeoutMs)
		assertEquals(60_000, high.proxyReadTimeoutMs)
		assertEquals(397, high.leafCertValidityDays)
	}

	@Test
	fun backupSectionsEscapeSqlLikeAndSanitizeBlocklistId() {
		assertTrue(BackupSections(false, false, false, true, false).hasAnySelected)
		assertFalse(BackupSections(false, false, false, false, false).hasAnySelected)

		assertEquals("", escapeSqlLike(""))
		assertEquals("plain", escapeSqlLike("plain"))
		assertEquals("utm\\_source\\%20\\\\x", escapeSqlLike("utm_source%20\\x"))

		assertEquals("etc_passwd", sanitizeBlocklistId("../../etc/passwd"))
		assertEquals("my_list-1", sanitizeBlocklistId("  my list-1  "))
		assertEquals("", sanitizeBlocklistId("///...___"))
		assertEquals(64, sanitizeBlocklistId("a".repeat(100)).length)
	}

	@Test
	fun builtinBlocklistsCatalogIntegrity() {
		val ids = BUILTIN_BLOCKLISTS.map { it.id }
		assertEquals("Blocklist IDs must be unique", ids.size, ids.toSet().size)
		for (item in BUILTIN_BLOCKLISTS) {
			assertEquals("ID must be pre-sanitized: ${item.id}", item.id, sanitizeBlocklistId(item.id))
			assertTrue("URL must use HTTPS: ${item.url}", item.url.startsWith("https://"))
			assertTrue("Title must not be blank: ${item.id}", item.title.isNotBlank())
			assertTrue("Category must not be blank: ${item.id}", item.category.isNotBlank())
			assertFalse("Removed ID must not be in active catalog: ${item.id}", REMOVED_BLOCKLIST_IDS.contains(item.id))
		}
	}
}
