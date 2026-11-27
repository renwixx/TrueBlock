package com.renwixx.trueadblocker.data

import android.app.Application
import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class AppPrefsAndBackupTest {
	private lateinit var ctx: Context
	private lateinit var db: AppDatabase

	@Before
	fun setUp() {
		ctx = ApplicationProvider.getApplicationContext()
		ctx.getSharedPreferences("true_adblocker_prefs", Context.MODE_PRIVATE).edit().clear().commit()
		db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
			.allowMainThreadQueries()
			.build()
	}

	@After
	fun tearDown() {
		db.close()
	}

	@Test
	fun proxyProfileJsonRoundTripAndPortClamping() {
		val original = ProxyProfile(
			id = "p_test",
			name = "My SOCKS",
			isEnabled = true,
			type = "SOCKS5",
			host = "10.0.0.2",
			port = 1080,
			username = "u",
			password = "p",
			isRemoteDns = false,
			isUdpRelay = false,
			isBlockUdpFallback = false,
			isAllApps = false,
			appPackages = setOf("com.a", "com.b"),
			hostFilter = "*.example.com",
			portFilter = "443,8443",
		)
		val restored = ProxyProfile.fromJson(original.toJson())
		assertEquals(original, restored)

		val clamped = ProxyProfile.fromJson(JSONObject().put("port", 999999))
		assertEquals(65535, clamped.port)
		assertEquals("127.0.0.1", clamped.host)
	}

	@Test
	fun appPrefsPersistsDifferentialUpdatesResetsTuningAndMigratesLegacyOled() {
		val sp = ctx.getSharedPreferences("true_adblocker_prefs", Context.MODE_PRIVATE)
		sp.edit().putBoolean("is_pure_oled", false).commit()

		val prefs = AppPrefs(ctx)
		assertEquals(THEME_DARK, prefs.state.value.themeMode)
		assertFalse(prefs.state.value.isPureOled)
		assertEquals(DEFAULT_BROWSER_PACKAGES, prefs.state.value.httpsInspectedApps)

		prefs.update {
			it.copy(
				themeMode = THEME_LIGHT,
				vpnMtu = 1420,
				dnsCacheSize = 4096,
				bypassedApps = setOf("com.keep"),
			)
		}

		// Re-instantiate AppPrefs to verify SharedPreferences persistence
		val reloaded = AppPrefs(ctx)
		assertEquals(THEME_LIGHT, reloaded.state.value.themeMode)
		assertEquals(1420, reloaded.state.value.vpnMtu)
		assertEquals(4096, reloaded.state.value.dnsCacheSize)
		assertEquals(setOf("com.keep"), reloaded.state.value.bypassedApps)

		reloaded.resetEngineTuningToDefaults()
		assertEquals(1500, reloaded.state.value.vpnMtu)
		assertEquals(2048, reloaded.state.value.dnsCacheSize)
		assertEquals(THEME_LIGHT, reloaded.state.value.themeMode)
		assertEquals(setOf("com.keep"), reloaded.state.value.bypassedApps)
	}

	@Test
	fun selectiveJsonBackupExportInspectImportAndSecurityGuards() = runBlocking {
		val prefs = AppPrefs(ctx)
		val proxy = ProxyProfile(id = "px1", name = "PX", host = "127.0.0.1", port = 1080, isAllApps = true)
		prefs.update {
			it.copy(
				themeMode = THEME_LIGHT,
				customCosmeticCss = ".promo{display:none}",
				dnsPresetKey = "quad9",
				isUseDoh = true,
				bypassedApps = setOf("com.bypass"),
				proxies = listOf(proxy),
			)
		}
		db.ruleDao().upsert(CustomRule(pattern = "ads.example.com", matchMode = MODE_EXACT, isAllow = false, isRoute = false))
		db.blocklistDao().upsert(
			BlocklistSource("my_list", "My List", "https://example.com/list.txt", "Custom", "desc", isHighlight = false, isEnabled = true)
		)

		val fullJson = prefs.exportJson(db, BackupSections())
		val inspection = prefs.inspectBackupContent(fullJson)
		assertFalse(inspection.isPlainTextRules)
		assertTrue(inspection.hasGeneralConfig)
		assertTrue(inspection.hasDnsAndNetworks)
		assertTrue(inspection.hasAppsAndProxies)
		assertEquals(1, inspection.proxyCount)
		assertTrue(inspection.hasCustomCss)
		assertEquals(1, inspection.customRulesCount)
		assertEquals(1, inspection.blocklistsCount)

		// Reset state and import ONLY DNS & Networks section
		prefs.update { AppConfig() }
		db.ruleDao().clearAll()
		db.blocklistDao().deleteById("my_list")

		prefs.importJson(
			fullJson,
			db,
			BackupSections(
				isGeneralConfig = false,
				isDnsAndNetworks = true,
				isAppsAndProxies = false,
				isCustomRules = false,
				isBlocklists = false,
			),
		)
		assertEquals("quad9", prefs.state.value.dnsPresetKey)
		assertTrue(prefs.state.value.isUseDoh)
		assertEquals(THEME_OLED, prefs.state.value.themeMode)
		assertTrue(prefs.state.value.proxies.isEmpty())
		assertTrue(db.ruleDao().getAll().isEmpty())

		// Import remaining sections
		prefs.importJson(fullJson, db, BackupSections())
		assertEquals(THEME_LIGHT, prefs.state.value.themeMode)
		assertEquals(1, prefs.state.value.proxies.size)
		assertEquals(1, db.ruleDao().getAll().size)
		assertEquals(1, db.blocklistDao().getAll().size)

		// Security: non-HTTPS blocklist URL must be rejected during import; legacy v2 isPureOled works
		val maliciousAndV2 = """
			{
				"version": 2,
				"settings": { "isPureOled": false },
				"blocklists": [
					{ "id": "../../evil", "title": "Evil", "url": "http://insecure.example/list.txt", "isEnabled": true },
					{ "id": "safe_https", "title": "Safe", "url": "https://secure.example/list.txt", "isEnabled": true }
				]
			}
		""".trimIndent()
		prefs.importJson(maliciousAndV2, db, BackupSections())
		assertEquals(THEME_DARK, prefs.state.value.themeMode)
		val allLists = db.blocklistDao().getAll().map { it.id }.toSet()
		assertFalse(allLists.contains("evil"))
		assertTrue(allLists.contains("safe_https"))
	}

	@Test
	fun plainTextRulesInspectionAndImportFiltersUnsupportedSyntax() = runBlocking {
		val prefs = AppPrefs(ctx)
		val rawText = """
			! Comment
			# Another comment
			[Adblock Plus]
			example.com##.cosmetic
			0.0.0.0 localhost
			0.0.0.0 tracker.example.com # inline comment
			127.0.0.1 ads.example.org
			||banner.site.net^
			@@||allowed.site.net^
			||news.com/ads/*
			||skip.me^${'$'}popup
			||skip2.me^${'$'}badfilter
		""".trimIndent()

		val info = prefs.inspectBackupContent(rawText)
		assertTrue(info.isPlainTextRules)
		assertEquals(5, info.customRulesCount)

		prefs.importJson(rawText, db, BackupSections(isCustomRules = true))
		val imported = db.ruleDao().getAll()
		assertEquals(5, imported.size)
		assertTrue(imported.any { it.pattern == "tracker.example.com" && !it.isAllow && it.matchMode == MODE_EXACT })
		assertTrue(imported.any { it.pattern == "allowed.site.net" && it.isAllow })
		assertTrue(imported.any { it.pattern == "news.com/ads/*" && it.isRoute && it.matchMode == MODE_WILDCARD })
	}
}
