package com.renwixx.trueadblocker.net

import android.app.Application
import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.renwixx.trueadblocker.data.AppDatabase
import com.renwixx.trueadblocker.data.AppPrefs
import com.renwixx.trueadblocker.data.TrafficPipeline
import com.renwixx.trueadblocker.engine.RuleEngine
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class MitmProxyLiveTest {
	private lateinit var ctx: Context
	private lateinit var db: AppDatabase
	private lateinit var prefs: AppPrefs
	private lateinit var engine: RuleEngine
	private lateinit var ca: CertAuthority
	private lateinit var traffic: TrafficPipeline

	@Before
	fun setUp() {
		ctx = ApplicationProvider.getApplicationContext()
		ctx.getSharedPreferences("true_adblocker_prefs", Context.MODE_PRIVATE).edit().clear().commit()
		db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
			.allowMainThreadQueries()
			.build()
		prefs = AppPrefs(ctx)
		engine = RuleEngine(ctx, db)
		ca = CertAuthority(ctx, isAutoLoad = false)
		traffic = TrafficPipeline(db.trafficDao(), db.trackerParamDao(), prefs)
	}

	@After
	fun tearDown() {
		db.close()
	}

	private fun sendRawHttp(port: Int, rawRequest: String): String {
		Socket("127.0.0.1", port).use { s ->
			s.soTimeout = 3000
			s.getOutputStream().write(rawRequest.toByteArray(Charsets.ISO_8859_1))
			s.getOutputStream().flush()
			s.shutdownOutput()
			return String(s.getInputStream().readBytes(), Charsets.ISO_8859_1)
		}
	}

	@Test
	fun liveMitmProxyHandlesBlockingNoopStubsParamStrippingCosmeticInjectionAndConnect() = runBlocking {
		engine.importLocalListFile(
			"mitm_test",
			"MITM Test",
			"""
				||blocked.domain.test^
				||site.example.test/ads/sdk.js
				||site.example.test/ads/pixel.png
				site.example.test##.ad-box
			""".trimIndent(),
		)
		prefs.update {
			it.copy(
				isHttpsFiltering = false,
				isRemoveTrackParams = true,
				isCosmeticFiltering = true,
			)
		}

		val upstreamHits = AtomicInteger(0)
		val lastUpstreamReqLine = StringBuilder()
		val upstreamSrv = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
		val upPort = upstreamSrv.localPort
		val upThread = Thread {
			upstreamSrv.use { srv ->
				srv.soTimeout = 5000
				while (!Thread.currentThread().isInterrupted) {
					val c = runCatching { srv.accept() }.getOrNull() ?: break
					c.use { sock ->
						val buf = ByteArray(4096)
						val n = runCatching { sock.getInputStream().read(buf) }.getOrDefault(-1)
						if (n <= 0) return@use
						upstreamHits.incrementAndGet()
						val reqText = String(buf, 0, n, Charsets.ISO_8859_1)
						val firstLine = reqText.substringBefore("\r\n")
						synchronized(lastUpstreamReqLine) {
							lastUpstreamReqLine.setLength(0)
							lastUpstreamReqLine.append(firstLine)
						}
						if (firstLine.contains("/page")) {
							val html = "<html><head><title>Hi</title></head><body><div class=\"ad-box\">Ad</div></body></html>"
							val gz = ByteArrayOutputStream().use { bos ->
								GZIPOutputStream(bos).use { it.write(html.toByteArray(Charsets.UTF_8)) }
								bos.toByteArray()
							}
							val hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: ${gz.size}\r\nConnection: close\r\n\r\n"
							sock.getOutputStream().write(hdr.toByteArray(Charsets.ISO_8859_1))
							sock.getOutputStream().write(gz)
							sock.getOutputStream().flush()
						} else if (firstLine.contains("TUNNEL_PING")) {
							sock.getOutputStream().write("TUNNEL_PONG".toByteArray(Charsets.US_ASCII))
							sock.getOutputStream().flush()
						}
					}
				}
			}
		}.apply { isDaemon = true; start() }

		val blockedHits = AtomicInteger(0)
		val proxy = MitmProxy(
			_engine = engine,
			_ca = ca,
			_prefs = prefs,
			_traffic = traffic,
			_cm = null,
			_pm = null,
			_protectSocket = { true },
			_onBlockedHit = { blockedHits.incrementAndGet() },
			_resolveHostIp = { InetAddress.getByName("127.0.0.1") },
		)
		val proxyPort = proxy.start()
		assertTrue(proxyPort > 0)

		try {
			// 1. Blocked JS route returns 200 OK empty JS noop stub without hitting upstream
			val jsResp = sendRawHttp(
				proxyPort,
				"GET http://site.example.test:$upPort/ads/sdk.js HTTP/1.1\r\nHost: site.example.test:$upPort\r\nConnection: close\r\n\r\n",
			)
			assertTrue(jsResp.startsWith("HTTP/1.1 200 OK"))
			assertTrue(jsResp.contains("application/javascript"))
			assertTrue(jsResp.contains("Content-Length: 0"))
			assertEquals(0, upstreamHits.get())

			// 2. Blocked image returns 42-byte GIF89a without hitting upstream
			val imgResp = sendRawHttp(
				proxyPort,
				"GET http://site.example.test:$upPort/ads/pixel.png HTTP/1.1\r\nHost: site.example.test:$upPort\r\nConnection: close\r\n\r\n",
			)
			assertTrue(imgResp.startsWith("HTTP/1.1 200 OK"))
			assertTrue(imgResp.contains("Content-Type: image/gif"))
			assertTrue(imgResp.contains("Content-Length: 42"))
			assertTrue(imgResp.contains("GIF89a"))
			assertEquals(0, upstreamHits.get())

			// 3. Allowed HTML page: tracking params stripped AND gzipped HTML gets cosmetic CSS injected
			val pageResp = sendRawHttp(
				proxyPort,
				"GET http://site.example.test:$upPort/page?id=7&utm_source=ads&fbclid=xyz HTTP/1.1\r\nHost: site.example.test:$upPort\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
			)
			assertTrue(pageResp.startsWith("HTTP/1.1 200 OK"))
			assertTrue(pageResp.contains("<style id=\"tb-cosmetic\">.ad-box{display:none!important}</style></head>"))
			assertFalse(pageResp.contains("Content-Encoding: gzip"))
			assertEquals("GET /page?id=7 HTTP/1.1", lastUpstreamReqLine.toString())
			assertEquals(1, upstreamHits.get())

			// 4. CONNECT to blocked domain returns 403 Forbidden
			val connectBlocked = sendRawHttp(
				proxyPort,
				"CONNECT blocked.domain.test:443 HTTP/1.1\r\nHost: blocked.domain.test:443\r\n\r\n",
			)
			assertTrue(connectBlocked.startsWith("HTTP/1.1 403 Forbidden"))

			// 5. CONNECT to forbidden loopback returns 403 Forbidden
			val connectLoopback = sendRawHttp(
				proxyPort,
				"CONNECT 127.0.0.1:$upPort HTTP/1.1\r\nHost: 127.0.0.1:$upPort\r\n\r\n",
			)
			assertTrue(connectLoopback.startsWith("HTTP/1.1 403 Forbidden"))

			// 6. CONNECT passthrough tunnel to allowed domain
			Socket("127.0.0.1", proxyPort).use { s ->
				s.soTimeout = 3000
				val out = s.getOutputStream()
				val inp = s.getInputStream()
				out.write("CONNECT tunnel.example.test:$upPort HTTP/1.1\r\nHost: tunnel.example.test:$upPort\r\n\r\n".toByteArray())
				out.flush()
				val headBuf = ByteArray(128)
				val hn = inp.read(headBuf)
				assertTrue(String(headBuf, 0, hn, Charsets.ISO_8859_1).startsWith("HTTP/1.1 200 Connection Established"))
				out.write("TUNNEL_PING\r\n".toByteArray(Charsets.US_ASCII))
				out.flush()
				val respBuf = ByteArray(32)
				val rn = inp.read(respBuf)
				assertEquals("TUNNEL_PONG", String(respBuf, 0, rn, Charsets.US_ASCII))
			}

			assertTrue(blockedHits.get() >= 3)
			assertTrue(proxy.pinnedHostsSnapshot().isEmpty())
			proxy.clearPinnedHosts()
		} finally {
			proxy.stop()
			runCatching { upstreamSrv.close() }
			upThread.join(1500)
		}
	}
}
