package com.renwixx.trueadblocker.net

import android.app.Application
import android.util.LruCache
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import okhttp3.OkHttpClient
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DnsWireCacheAndDohTest {
	@Test
	fun dnsCacheRewritesTxIdRespectsTtlNxDomainCapAndSkipsServFail() {
		val cache = LruCache<String, CachedDns>(32)
		val now = 1_700_000_000_000L

		val query = DnsWire.buildDnsQueryWire("cached.example.com", DnsWire.TYPE_A).also {
			it[0] = 0x11
			it[1] = 0x22
		}
		val parsed = DnsWire.parseDnsQuery(query)!!
		val okResp = DnsWire.buildSyntheticBlockedDns(query, parsed) // RCODE=0, TTL=60

		DnsWire.storeDnsCacheEntry(cache, "k_ok", okResp, now = now, cacheTtlSec = 120)

		// Lookup with different txId rewrites first 2 bytes
		val query2 = query.copyOf().also { it[0] = 0x77; it[1] = 0x88.toByte() }
		val hit = DnsWire.getCachedDnsWire(cache, "k_ok", query2, now = now + 59_000L)
		assertNotNull(hit)
		assertEquals(0x77.toByte(), hit!![0])
		assertEquals(0x88.toByte(), hit[1])

		// Expired after 60s (minTtlSec from answer)
		assertNull(DnsWire.getCachedDnsWire(cache, "k_ok", query2, now = now + 60_001L))

		// NXDOMAIN capped at 30s even if cacheTtlSec = 300
		val nxResp = DnsWire.buildNxDomainDns(query, parsed)
		DnsWire.storeDnsCacheEntry(cache, "k_nx", nxResp, now = now, cacheTtlSec = 300)
		assertNotNull(DnsWire.getCachedDnsWire(cache, "k_nx", query2, now = now + 29_000L))
		assertNull(DnsWire.getCachedDnsWire(cache, "k_nx", query2, now = now + 30_001L))

		// SERVFAIL (RCODE = 2) must NOT be cached
		val servFail = okResp.copyOf().also { it[3] = ((it[3].toInt() and 0xF0) or 2).toByte() }
		DnsWire.storeDnsCacheEntry(cache, "k_sf", servFail, now = now, cacheTtlSec = 90)
		assertNull(DnsWire.getCachedDnsWire(cache, "k_sf", query2, now = now + 1000L))
	}

	@Test
	fun resolveUpstreamAndResolveHostForProxyOverLocalMockDoh() {
		val dohSrv = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
		val srvThread = Thread {
			dohSrv.use { srv ->
				srv.soTimeout = 3000
				// 1. Valid DoH 200 OK with A record 203.0.113.77
				srv.accept().use { c ->
					val inp = c.getInputStream()
					val reqRaw = ByteArray(4096)
					val n = inp.read(reqRaw)
					val text = String(reqRaw, 0, n, Charsets.ISO_8859_1)
					val bodyIdx = text.indexOf("\r\n\r\n") + 4
					val cl = text.lines().firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
						?.substringAfter(':')?.trim()?.toIntOrNull() ?: (n - bodyIdx)
					val qBytes = ByteArray(cl)
					val avail = n - bodyIdx
					System.arraycopy(reqRaw, bodyIdx, qBytes, 0, minOf(avail, cl))
					var off = avail
					while (off < cl) {
						val r = inp.read(qBytes, off, cl - off)
						if (r <= 0) break
						off += r
					}
					val parsed = DnsWire.parseDnsQuery(qBytes)!!
					val qSec = qBytes.copyOfRange(12, parsed.questionEndOffset)
					val dnsReply = ByteArrayOutputStream().apply {
						write(qBytes[0].toInt())
						write(qBytes[1].toInt())
						write(0x81)
						write(0x80)
						write(byteArrayOf(0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00))
						write(qSec)
						write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04))
						write(byteArrayOf(203.toByte(), 0, 113, 77))
					}.toByteArray()
					val hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ${dnsReply.size}\r\nConnection: close\r\n\r\n"
					c.getOutputStream().write(hdr.toByteArray(Charsets.ISO_8859_1))
					c.getOutputStream().write(dnsReply)
					c.getOutputStream().flush()
				}
				// 2. HTTP 500 for Strict DoH failure test
				srv.accept().use { c ->
					c.getInputStream().read(ByteArray(2048))
					c.getOutputStream().write("HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
					c.getOutputStream().flush()
				}
			}
		}.apply { isDaemon = true; start() }

		val cache = LruCache<String, CachedDns>(32)
		val dohUrl = "http://127.0.0.1:${dohSrv.localPort}/dns-query"
		val client = OkHttpClient()

		val resolved = DnsWire.resolveHostForProxy(
			host = "doh.example.test",
			primaryDns = "",
			secondaryDns = "",
			dohUrl = dohUrl,
			dohClient = client,
			protectDatagram = { true },
			cache = cache,
			timeoutMs = 2000,
			cacheTtlSec = 60,
			isStrictDoh = true,
		)
		assertNotNull(resolved)
		assertArrayEquals(byteArrayOf(203.toByte(), 0, 113, 77), resolved!!.address)

		// IP literal short-circuits without network
		val ipLit = DnsWire.resolveHostForProxy(
			host = "1.1.1.1",
			primaryDns = "",
			secondaryDns = "",
			dohUrl = null,
			dohClient = client,
			protectDatagram = { true },
			cache = cache,
			timeoutMs = 1000,
			cacheTtlSec = 60,
		)
		assertEquals("1.1.1.1", ipLit?.hostAddress)

		// Strict DoH returns null on DoH 500 without falling back to primaryDns
		val failQuery = DnsWire.buildDnsQueryWire("strict-fail.test", DnsWire.TYPE_A)
		val strictNull = DnsWire.resolveUpstream(
			rawQuery = failQuery,
			parsed = DnsWire.parseDnsQuery(failQuery)!!,
			primaryDns = "127.0.0.1",
			secondaryDns = "",
			dohUrl = dohUrl,
			dohClient = client,
			protectDatagram = { true },
			cache = cache,
			timeoutMs = 1000,
			cacheTtlSec = 60,
			isStrictDoh = true,
		)
		assertNull(strictNull)

		dohSrv.close()
		srvThread.join(1500)
	}
}
