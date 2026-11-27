package com.renwixx.trueadblocker.engine

import android.app.Application
import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.renwixx.trueadblocker.data.AppDatabase
import com.renwixx.trueadblocker.data.BlocklistSource
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class RuleEngineIntegrationTest {
	private lateinit var ctx: Context
	private lateinit var db: AppDatabase
	private lateinit var cacheDir: File

	@Before
	fun setUp() {
		ctx = ApplicationProvider.getApplicationContext()
		cacheDir = File(ctx.filesDir, "blocklists")
		cacheDir.deleteRecursively()
		db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
			.allowMainThreadQueries()
			.build()
	}

	@After
	fun tearDown() {
		db.close()
		cacheDir.deleteRecursively()
	}

	@Test
	fun ensureCatalogSeededRemovesLegacyFilesAndRemovedLists() = runBlocking {
		cacheDir.mkdirs()
		val v1 = File(cacheDir, "compiled_lists_v1.bin").apply { writeText("old") }
		val v2 = File(cacheDir, "compiled_lists_v2.bin").apply { writeText("old") }
		val oldListFile = File(cacheDir, "urlhaus.txt").apply { writeText("0.0.0.0 bad.test") }
		db.blocklistDao().upsert(BlocklistSource("urlhaus", "Old", "https://example.com/u", "Sec", "", false, true))

		val engine = RuleEngine(ctx, db)
		engine.ensureCatalogSeeded()

		assertFalse(v1.exists())
		assertFalse(v2.exists())
		assertFalse(oldListFile.exists())
		val all = db.blocklistDao().getAll()
		assertTrue(all.size >= BUILTIN_BLOCKLISTS.size)
		assertFalse(all.any { it.id == "urlhaus" })
	}

	@Test
	fun matchingPriorityBinaryCacheRoundTripAndCosmeticCssWorkEndToEnd() = runBlocking {
		val engine = RuleEngine(ctx, db)
		val listContent = """
			! Local test list
			||blockedzone.test^
			@@||allow.blockedzone.test^
			0.0.0.0 exacthost.test
			||portal.test/ads/banner^
			@@||portal.test/ads/banner/safe^
			/tracker_pixel/collect.js
			||ws.tracker.test/live^${'$'}websocket
			||third.only.test^${'$'}third-party
			##.global-ad
			##.global-popup
			~exempt.test##.global-ad
			news.test##.news-sponsor
			sub.news.test#@#.news-sponsor
			*${'$'}removeparam=custom_trk
		""".trimIndent()

		engine.importLocalListFile("local_test", "Local Test", listContent)
		assertTrue(engine.areAllEnabledCached())

		// Add custom rules to test full priority: Custom Allow > Custom Block > List Allow > List Block
		db.ruleDao().upsertAll(
			listOf(
				CustomRule(pattern = "override.blockedzone.test", matchMode = MODE_EXACT, isAllow = true, isRoute = false, note = "VIP"),
				CustomRule(pattern = "*.customblock.test", matchMode = MODE_WILDCARD, isAllow = false, isRoute = false),
				CustomRule(pattern = "custom.route.test/secret/*", matchMode = MODE_WILDCARD, isAllow = false, isRoute = true),
				CustomRule(pattern = "^https://regex\\.test/bad/[0-9]+$", matchMode = MODE_REGEX, isAllow = false, isRoute = true),
			)
		)
		engine.reloadCustomRulesOnly()

		// Verify binary snapshot was written and a fresh RuleEngine loads identically from binary cache
		val binCache = File(cacheDir, "compiled_lists_v3.bin")
		assertTrue("Binary snapshot cache must be created", binCache.exists() && binCache.length() > 0L)

		val engineFromCache = RuleEngine(ctx, db)
		engineFromCache.reloadFromDiskAndDb()

		// DNS priority checks
		assertFalse(engineFromCache.matchDns("override.blockedzone.test").isBlocked)
		assertTrue(engineFromCache.matchDns("override.blockedzone.test").ruleSource.contains("Custom Rule"))
		assertTrue(engineFromCache.matchDns("sub.customblock.test").isBlocked)
		assertFalse(engineFromCache.matchDns("allow.blockedzone.test").isBlocked)
		assertTrue(engineFromCache.matchDns("sub.blockedzone.test").isBlocked)
		assertTrue(engineFromCache.matchDns("exacthost.test").isBlocked)
		assertFalse(engineFromCache.matchDns("clean.example.org").isBlocked)

		// URL route & context checks
		assertTrue(engineFromCache.matchUrl("https://custom.route.test/secret/a", "custom.route.test", "/secret/a", false).isBlocked)
		assertTrue(engineFromCache.matchUrl("https://regex.test/bad/42", "regex.test", "/bad/42", false).isBlocked)
		assertTrue(engineFromCache.matchUrl("https://portal.test/ads/banner?x=1", "portal.test", "/ads/banner?x=1", false).isBlocked)
		assertFalse(engineFromCache.matchUrl("https://portal.test/ads/banner/safe", "portal.test", "/ads/banner/safe", false).isBlocked)
		assertTrue(engineFromCache.matchUrl("https://any.site/tracker_pixel/collect.js", "any.site", "/tracker_pixel/collect.js", false).isBlocked)
		assertTrue(engineFromCache.matchUrl("wss://ws.tracker.test/live", "ws.tracker.test", "/live", isWebSocket = true).isBlocked)
		assertFalse(engineFromCache.matchUrl("https://ws.tracker.test/live", "ws.tracker.test", "/live", isWebSocket = false).isBlocked)
		assertTrue(engineFromCache.matchUrl("https://third.only.test/a.js", "third.only.test", "/a.js", false, RuleEngine.RES_SCRIPT, isThirdParty = true).isBlocked)
		assertFalse(engineFromCache.matchUrl("https://third.only.test/a.js", "third.only.test", "/a.js", false, RuleEngine.RES_SCRIPT, isThirdParty = false).isBlocked)

		// matchCustomOnly & evaluateTargetLive
		assertNull(engineFromCache.matchCustomOnly("exacthost.test", isRoute = false))
		assertTrue(engineFromCache.matchCustomOnly("sub.customblock.test", isRoute = false)?.isBlocked == true)
		assertTrue(engineFromCache.evaluateTargetLive("portal.test/ads/banner", isRoute = true).isBlocked)
		assertTrue(engineFromCache.evaluateTargetLive("exacthost.test", isRoute = false).isBlocked)

		// Cosmetic CSS with exceptions, subdomain inheritance, maxGeneric cap, and customCss
		val exemptCss = engineFromCache.cosmeticCssForHost("sub.exempt.test", maxGeneric = 10, customCss = ".mine{opacity:0}")
		assertFalse(exemptCss.contains(".global-ad"))
		assertTrue(exemptCss.contains(".global-popup"))
		assertTrue(exemptCss.contains(".mine{opacity:0}"))

		val newsCss = engineFromCache.cosmeticCssForHost("news.test", maxGeneric = 1, customCss = "")
		assertTrue(newsCss.contains(".global-ad"))
		assertFalse(newsCss.contains(".global-popup")) // capped by maxGeneric = 1
		assertTrue(newsCss.contains(".news-sponsor"))

		val subNewsCss = engineFromCache.cosmeticCssForHost("sub.news.test", maxGeneric = 0, customCss = "")
		assertFalse(subNewsCss.contains(".news-sponsor")) // excluded by sub.news.test#@#.news-sponsor

		assertTrue(engineFromCache.listRemoveParams().contains("custom_trk"))
		assertTrue(engineFromCache.stats.value.totalDomainRules > 0)
		assertTrue(engineFromCache.stats.value.totalRouteRules > 0)

		engineFromCache.deleteCachedList("local_test")
		assertFalse(engineFromCache.areAllEnabledCached())
	}

	@Test
	fun syncBlocklistDownloadsOverHttpRecordsErrorsAndBlocksPathTraversal() = runBlocking {
		val srv = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
		val srvThread = Thread {
			srv.use { s ->
				s.soTimeout = 3000
				// 1. 200 OK list
				s.accept().use { c ->
					c.getInputStream().read(ByteArray(1024))
					val body = "||synced-ad.test^\n||synced-site.test/ad/banner^\n"
					val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
					c.getOutputStream().write(resp.toByteArray(Charsets.UTF_8))
					c.getOutputStream().flush()
				}
				// 2. 500 Internal Server Error
				s.accept().use { c ->
					c.getInputStream().read(ByteArray(1024))
					c.getOutputStream().write("HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
					c.getOutputStream().flush()
				}
			}
		}.apply { isDaemon = true; start() }

		val engine = RuleEngine(ctx, db)
		val okSrc = BlocklistSource("http_ok", "HTTP OK", "http://127.0.0.1:${srv.localPort}/list.txt", "Test", "", false, true)
		val errSrc = BlocklistSource("http_err", "HTTP ERR", "http://127.0.0.1:${srv.localPort}/fail.txt", "Test", "", false, true)
		val traversalSrc = BlocklistSource("trav", "Trav", "file:///etc/hosts", "Test", "", false, true)
		db.blocklistDao().upsert(okSrc)
		db.blocklistDao().upsert(errSrc)
		db.blocklistDao().upsert(traversalSrc)

		val resOk = engine.syncBlocklist(okSrc, isReloadAfter = true)
		assertTrue(resOk.isSuccess)
		assertEquals(1 to 1, resOk.getOrNull())
		assertTrue(engine.matchDns("synced-ad.test").isBlocked)

		val resErr = engine.syncBlocklist(errSrc, isReloadAfter = false)
		assertTrue(resErr.isFailure)
		assertTrue(db.blocklistDao().getAll().first { it.id == "http_err" }.lastError.contains("500"))

		val resTrav = engine.syncBlocklist(traversalSrc, isReloadAfter = false)
		assertTrue(resTrav.isFailure)

		engine.cancelActiveSync()
		assertTrue(engine.isCancelRequested)
		val resCancelled = engine.syncBlocklist(okSrc, isReloadAfter = false)
		assertTrue(resCancelled.isFailure)
		engine.resetCancelFlag()
		assertFalse(engine.isCancelRequested)

		srvThread.join(1500)
	}
}
