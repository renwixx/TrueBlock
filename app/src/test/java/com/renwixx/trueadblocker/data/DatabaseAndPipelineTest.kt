package com.renwixx.trueadblocker.data

import android.app.Application
import android.content.Context
import androidx.paging.PagingSource
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
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
import org.robolectric.annotation.SQLiteMode

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
@SQLiteMode(SQLiteMode.Mode.NATIVE)
class DatabaseAndPipelineTest {
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

	private suspend fun <V : Any> loadPage(source: PagingSource<Int, V>): List<V> {
		val res = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 100, placeholdersEnabled = false))
		return (res as PagingSource.LoadResult.Page).data
	}

	@Test
	fun trafficDaoFlushPagingFiltersTrimAndDeleteByApp() = runBlocking {
		val dao = db.trafficDao()
		val baseTs = 1_700_000_000_000L
		val hour = baseTs / 3_600_000L

		dao.flushSamples(
			aggItems = listOf(
				AggBatchItem(
					target = "ads.example.com",
					isBlocked = true,
					isRoute = false,
					delta = 5,
					blockedDelta = 5,
					allowedDelta = 0,
					cnameDelta = 2,
					firstSeen = baseTs,
					lastSeen = baseTs + 1000,
					lastApp = "com.app.one",
					lastRule = "CNAME (tracker.io)",
					host = "ads.example.com",
				),
				AggBatchItem(
					target = "cdn.site.com/pic/hero.webp",
					isBlocked = false,
					isRoute = true,
					delta = 3,
					blockedDelta = 0,
					allowedDelta = 3,
					cnameDelta = 0,
					firstSeen = baseTs,
					lastSeen = baseTs + 2000,
					lastApp = "com.app.two",
					lastRule = "",
					host = "cdn.site.com",
					contentType = "image",
					fileExt = "webp",
				),
				AggBatchItem(
					target = "dl.site.com/app_v1.apk",
					isBlocked = false,
					isRoute = true,
					delta = 1,
					blockedDelta = 0,
					allowedDelta = 1,
					cnameDelta = 0,
					firstSeen = baseTs,
					lastSeen = baseTs + 3000,
					lastApp = "com.app.two",
					lastRule = "",
					host = "dl.site.com",
					contentType = "file",
					fileExt = "apk",
				),
			),
			hourlyItems = listOf(HourlyBatchItem(hour, blockedDelta = 5, allowedDelta = 4)),
			appItems = listOf(
				AppBatchItem("com.app.one", totalDelta = 5, blockedDelta = 5, lastSeen = baseTs + 1000),
				AppBatchItem("com.app.two", totalDelta = 4, blockedDelta = 0, lastSeen = baseTs + 3000),
			),
			rawItems = listOf(
				RawLog(target = "ads.example.com", host = "ads.example.com", proto = "CNAME", isBlocked = true, appPkg = "com.app.one", matchedRule = "r1", ts = baseTs),
				RawLog(target = "cdn.site.com/pic/hero.webp", host = "cdn.site.com", proto = "HTTPS", isBlocked = false, appPkg = "com.app.two", matchedRule = "", ts = baseTs + 2000, contentType = "image", fileExt = "webp"),
			),
			totalReqDelta = 9,
			totalBlockedDelta = 5,
			totalAllowedDelta = 4,
			totalCnameDelta = 2,
		)

		// Totals
		assertEquals(9L, dao.observeTotalRequests().first())
		assertEquals(5L, dao.observeTotalBlocked().first())
		assertEquals(4L, dao.observeTotalAllowed().first())
		assertEquals(2L, dao.observeTotalCnameUncloaked().first())

		// System DNS must NOT overwrite a real app package on conflict
		dao.upsertAgg(
			target = "ads.example.com",
			isBlocked = true,
			isRoute = false,
			delta = 1,
			blockedDelta = 1,
			allowedDelta = 0,
			cnameDelta = 0,
			firstSeen = baseTs,
			lastSeen = baseTs + 5000,
			lastApp = "System DNS",
			lastRule = "EasyList",
			host = "ads.example.com",
			contentType = "",
			fileExt = "",
		)
		val agg = dao.getAggByTarget("ads.example.com")!!
		assertEquals(6L, agg.hitCount)
		assertEquals("com.app.one", agg.lastApp)

		// Paging filters: recent, top, image, file+customExt, escaped LIKE search, HTTPS domain groups, raw
		val topAll = loadPage(dao.pageTop(q = "", blockFilter = -1, routeMode = -1))
		assertEquals(listOf("ads.example.com", "cdn.site.com/pic/hero.webp", "dl.site.com/app_v1.apk"), topAll.map { it.target })

		val onlyImages = loadPage(dao.pageRecent(q = "", blockFilter = -1, routeMode = 1, typeFilter = "image"))
		assertEquals(listOf("cdn.site.com/pic/hero.webp"), onlyImages.map { it.target })

		val onlyApk = loadPage(dao.pageRecent(q = "", blockFilter = -1, routeMode = 1, typeFilter = "file", customExt = "apk"))
		assertEquals(listOf("dl.site.com/app_v1.apk"), onlyApk.map { it.target })

		val escapedSearch = loadPage(dao.pageRecent(q = escapeSqlLike("app_v1"), blockFilter = -1, routeMode = -1))
		assertEquals(listOf("dl.site.com/app_v1.apk"), escapedSearch.map { it.target })

		val httpsDomains = loadPage(dao.pageHttpsDomains(q = "", blockFilter = -1, appPkg = "com.app.two", typeFilter = "", customExt = "", isTopSort = 1))
		assertEquals(listOf("cdn.site.com", "dl.site.com"), httpsDomains.map { it.host })

		val rawRoutes = loadPage(dao.pageRaw(q = "", blockFilter = -1, isRoutesOnly = 1))
		assertEquals(1, rawRoutes.size)
		assertEquals("cdn.site.com/pic/hero.webp", rawRoutes.first().target)

		// Hourly & Top apps breakdown
		assertEquals(1, dao.getHourlyActivity(baseTs - 3_600_000L).size)
		val topApps = dao.getTopAppsBreakdown(10)
		assertEquals(listOf("com.app.one", "com.app.two"), topApps.map { it.appPkg })

		// deleteAllByApp detaches shared agg (hitCount 6 > appTotalHits 5) and subtracts totals
		dao.deleteAllByApp("com.app.one")
		assertNull(dao.getAppStat("com.app.one"))
		val detached = dao.getAggByTarget("ads.example.com")
		assertNotNull(detached)
		assertEquals("", detached!!.lastApp)
		assertEquals(4L, dao.observeTotalRequests().first())
		assertEquals(0L, dao.observeTotalBlocked().first())

		// trimOldestAgg & trimRaw & clearAllTraffic
		dao.trimOldestAgg(1)
		assertEquals(2, dao.countAgg())
		dao.trimRaw(0)
		assertTrue(loadPage(dao.pageRaw(q = "", blockFilter = -1)).isEmpty())
		dao.clearAllTraffic()
		assertEquals(0, dao.countAgg())
		assertEquals(0L, dao.observeTotalRequests().first())
	}

	@Test
	fun ruleBlocklistAndTrackerParamDaosWorkEndToEnd() = runBlocking {
		val rDao = db.ruleDao()
		val id1 = rDao.upsert(CustomRule(pattern = "ads.test", matchMode = MODE_EXACT, isAllow = false, isRoute = false, note = "block_note"))
		rDao.upsert(CustomRule(pattern = "site.test/ad*", matchMode = MODE_WILDCARD, isAllow = false, isRoute = true))
		rDao.upsert(CustomRule(pattern = "safe.test", matchMode = MODE_EXACT, isAllow = true, isRoute = false))

		assertEquals(3, rDao.getAll().size)
		assertEquals(3, rDao.getEnabled().size)
		rDao.setEnabled(id1, false)
		assertEquals(2, rDao.getEnabled().size)

		assertEquals(1, loadPage(rDao.pageRouteRules("")).size)
		assertEquals(1, loadPage(rDao.pageRules(isAllow = true, isRoutesOnly = 0, q = "")).size)
		assertEquals(1, loadPage(rDao.pageAllRules("block\\_note")).size)

		rDao.deleteByPattern("safe.test", isAllow = true)
		assertEquals(2, rDao.getAll().size)
		rDao.deleteById(id1)
		assertEquals(1, rDao.getAll().size)
		rDao.clearAll()
		assertTrue(rDao.getAll().isEmpty())

		val bDao = db.blocklistDao()
		val src = BlocklistSource("id1", "List 1", "https://example.com/1.txt", "Ads", "desc", isHighlight = true, isEnabled = true)
		bDao.insertIgnore(listOf(src))
		bDao.insertIgnore(listOf(src.copy(title = "ShouldBeIgnored")))
		assertEquals("List 1", bDao.getAll().first().title)
		bDao.updateStats("id1", 100, 20, 12345L, "")
		assertEquals(100, bDao.getEnabled().first().ruleCount)
		bDao.setEnabled("id1", false)
		assertTrue(bDao.getEnabled().isEmpty())
		bDao.deleteByIds(listOf("id1"))
		assertTrue(bDao.getAll().isEmpty())

		val pDao = db.trackerParamDao()
		pDao.upsertBatch(
			listOf(
				ParamBatchItem("utm_source", 3, "a.com", 1000L),
				ParamBatchItem("fbclid", 2, "b.com", 2000L),
			)
		)
		pDao.upsertBatch(listOf(ParamBatchItem("utm_source", 4, "c.com", 3000L)))
		assertEquals(9L, pDao.observeTotalRemoved().first())
		val top = pDao.observeTopParams().first()
		assertEquals("utm_source", top.first().paramName)
		assertEquals(7L, top.first().removedCount)
		assertEquals("c.com", top.first().lastHost)
		pDao.clearAll()
		assertEquals(0L, pDao.observeTotalRemoved().first())
	}

	@Test
	fun trafficPipelineBatchesFiltersBypassedAppsAndHandlesClearAll() = runBlocking {
		val prefs = AppPrefs(ctx)
		prefs.update {
			it.copy(
				logFlushIntervalMs = 50,
				bypassedApps = setOf("com.bypassed"),
				isRawLoggingEnabled = true,
			)
		}
		val pipeline = TrafficPipeline(db.trafficDao(), db.trackerParamDao(), prefs)

		pipeline.push(TrafficSample("bypass.com", "bypass.com", "DNS", false, false, "com.bypassed", ""))
		pipeline.push(TrafficSample("ads.com", "ads.com", "DNS", true, false, "com.browser", "EasyList", ts = 1_700_000_000_000L))
		pipeline.push(TrafficSample("ads.com", "ads.com", "CNAME", true, false, "com.browser", "CNAME (t.io)", ts = 1_700_000_001_000L))
		pipeline.pushRemovedParams("shop.com", listOf("UTM_SOURCE", "fbclid"))

		// Wait for async batch flush (50ms traffic + 500ms params)
		val deadline = System.currentTimeMillis() + 3000L
		while (System.currentTimeMillis() < deadline) {
			if (db.trafficDao().observeTotalRequests().first() >= 2L && db.trackerParamDao().observeTotalRemoved().first() >= 2L)
				break
			delay(40)
		}

		assertNull("Bypassed app traffic must not be persisted", db.trafficDao().getAggByTarget("bypass.com"))
		val ads = db.trafficDao().getAggByTarget("ads.com")
		assertNotNull(ads)
		assertEquals(2L, ads!!.hitCount)
		assertEquals(2L, ads.blockedHits)
		assertEquals(1L, ads.cnameHits)
		assertEquals(2L, db.trackerParamDao().observeTotalRemoved().first())

		pipeline.clearAll()
		assertEquals(0L, db.trafficDao().observeTotalRequests().first())
		assertEquals(0, db.trafficDao().countAgg())
	}
}
