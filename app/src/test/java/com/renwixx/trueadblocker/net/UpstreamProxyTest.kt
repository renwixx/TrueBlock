package com.renwixx.trueadblocker.net

import com.renwixx.trueadblocker.data.ProxyProfile
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpstreamProxyTest {
	@Test
	fun selectProxyMatchesAppHostPortBypassAndPriority() {
		val disabled = ProxyProfile(id = "d", name = "Disabled", isEnabled = false, host = "127.0.0.1", port = 1080, isAllApps = true)
		val invalidPort = ProxyProfile(id = "ip", name = "BadPort", isEnabled = true, host = "127.0.0.1", port = 0, isAllApps = true)
		val whatsapp = ProxyProfile(
			id = "wa",
			name = "WhatsApp SOCKS5",
			isEnabled = true,
			type = "SOCKS5",
			host = "127.0.0.1",
			port = 1080,
			isAllApps = false,
			appPackages = setOf("com.whatsapp"),
			hostFilter = "*.whatsapp.net, g.whatsapp.com",
			portFilter = "443,5222-5228",
		)
		val global = ProxyProfile(
			id = "all",
			name = "Global",
			isEnabled = true,
			type = "HTTP",
			host = "127.0.0.1",
			port = 8080,
			isAllApps = true,
		)
		val list = listOf(disabled, invalidPort, whatsapp, global)

		assertEquals("wa", UpstreamProxy.selectProxy(list, "com.whatsapp", "e1.whatsapp.net", 5224)?.id)
		assertEquals("all", UpstreamProxy.selectProxy(list, "com.whatsapp", "e1.whatsapp.net", 80)?.id)
		assertEquals("all", UpstreamProxy.selectProxy(list, "com.chrome", "example.com", 443)?.id)
		assertNull(UpstreamProxy.selectProxy(list, "com.whatsapp", "e1.whatsapp.net", 443, bypassedApps = setOf("com.whatsapp")))
		assertNull(UpstreamProxy.selectProxy(emptyList(), "com.whatsapp", "e1.whatsapp.net", 443))
	}

	@Test
	fun hostFilterPortFilterAndBasicAuthHeaderEdgeCases() {
		assertTrue(UpstreamProxy.matchesHostFilter("any.host", ""))
		assertTrue(UpstreamProxy.matchesHostFilter("any.host", "*"))
		assertTrue(UpstreamProxy.matchesHostFilter("api.example.com", "foo.com; *.example.com"))
		assertFalse(UpstreamProxy.matchesHostFilter("other.org", "*.example.com"))

		assertTrue(UpstreamProxy.matchesPortFilter(443, ""))
		assertTrue(UpstreamProxy.matchesPortFilter(443, "*"))
		assertTrue(UpstreamProxy.matchesPortFilter(8080, "80, 443, 8000-8100"))
		assertFalse(UpstreamProxy.matchesPortFilter(8101, "80, 443, 8000-8100"))
		assertFalse(UpstreamProxy.matchesPortFilter(443, "bad-range, abc"))

		assertEquals("", UpstreamProxy.buildBasicProxyAuthHeader(ProxyProfile(id = "1", name = "p", host = "127.0.0.1", port = 8080)))
		assertEquals(
			"Basic dXNlcjpwYXNz",
			UpstreamProxy.buildBasicProxyAuthHeader(ProxyProfile(id = "1", name = "p", host = "127.0.0.1", port = 8080, username = "user", password = "pass")),
		)
	}

	@Test
	fun socks5UdpWrapAndUnwrapHandlesIpv4DomainLiteralAndInvalidFrames() {
		val ip = byteArrayOf(198.toByte(), 51, 100, 7)
		val payload = "PING".toByteArray(Charsets.US_ASCII)
		val wrapped = UpstreamProxy.wrapSocks5UdpPayload(ip, 5353, payload)
		val unwrapped = UpstreamProxy.unwrapSocks5UdpPacket(wrapped, wrapped.size)
		assertNotNull(unwrapped)
		assertArrayEquals(ip, unwrapped!!.srcIp)
		assertEquals(5353, unwrapped.srcPort)
		assertArrayEquals(payload, unwrapped.payload)

		// Fragmented UDP (FRAG != 0) rejected
		val fragged = wrapped.copyOf().also { it[2] = 1 }
		assertNull(UpstreamProxy.unwrapSocks5UdpPacket(fragged, fragged.size))

		// Too short rejected
		assertNull(UpstreamProxy.unwrapSocks5UdpPacket(ByteArray(10), 10))

		// ATYP=0x03 with IPv4 literal accepted
		val domIp = "127.0.0.1".toByteArray(Charsets.ISO_8859_1)
		val domPkt = ByteArrayOutputStream().apply {
			write(byteArrayOf(0, 0, 0, 0x03, domIp.size.toByte()))
			write(domIp)
			write(byteArrayOf(0x00, 0x35))
			write(payload)
		}.toByteArray()
		val domUnwrapped = UpstreamProxy.unwrapSocks5UdpPacket(domPkt, domPkt.size)
		assertNotNull(domUnwrapped)
		assertArrayEquals(byteArrayOf(127, 0, 0, 1), domUnwrapped!!.srcIp)
		assertEquals(53, domUnwrapped.srcPort)

		// ATYP=0x03 with non-IP hostname rejected
		val badDom = "example.com".toByteArray(Charsets.ISO_8859_1)
		val badDomPkt = ByteArrayOutputStream().apply {
			write(byteArrayOf(0, 0, 0, 0x03, badDom.size.toByte()))
			write(badDom)
			write(byteArrayOf(0x00, 0x35))
			write(payload)
		}.toByteArray()
		assertNull(UpstreamProxy.unwrapSocks5UdpPacket(badDomPkt, badDomPkt.size))
	}

	@Test
	fun httpConnectAndSocks5AuthHandshakesAndErrorPaths() {
		// Local HTTP CONNECT mock server
		val httpSrv = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
		val receivedAuth = StringBuilder()
		val httpThread = Thread {
			httpSrv.use { srv ->
				srv.soTimeout = 3000
				// Connection 1: 200 OK
				srv.accept().use { c ->
					val text = buildString {
						val inp = c.getInputStream()
						val buf = ByteArray(1024)
						val n = inp.read(buf)
						if (n > 0) append(String(buf, 0, n, Charsets.ISO_8859_1))
					}
					receivedAuth.append(text)
					c.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\nOK".toByteArray(Charsets.ISO_8859_1))
					c.getOutputStream().flush()
				}
				// Connection 2: 407 Proxy Auth Required
				srv.accept().use { c ->
					c.getInputStream().read(ByteArray(1024))
					c.getOutputStream().write("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
					c.getOutputStream().flush()
				}
			}
		}.apply { isDaemon = true; start() }

		val httpProfile = ProxyProfile(
			id = "http1",
			name = "HTTP",
			type = "HTTP",
			host = "127.0.0.1",
			port = httpSrv.localPort,
			username = "alice",
			password = "secret",
		)
		val okSock = UpstreamProxy.connectSocket(httpProfile, "2606:4700:4700::1111", 443, 2000, 2000, { true })
		assertNotNull(okSock)
		val bodyBuf = ByteArray(2)
		assertEquals(2, okSock!!.getInputStream().read(bodyBuf))
		assertEquals("OK", String(bodyBuf, Charsets.ISO_8859_1))
		okSock.close()
		assertTrue(receivedAuth.toString().contains("CONNECT [2606:4700:4700::1111]:443 HTTP/1.1"))
		assertTrue(receivedAuth.toString().contains("Proxy-Authorization: Basic "))

		val failSock = UpstreamProxy.connectSocket(httpProfile, "example.com", 443, 2000, 2000, { true })
		assertNull(failSock)
		httpThread.join(1500)

		// Local SOCKS5 server with RFC 1929 user/pass auth
		val socksSrv = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
		val socksThread = Thread {
			socksSrv.use { srv ->
				srv.soTimeout = 3000
				// 1. Valid auth + remote DNS CONNECT
				srv.accept().use { c ->
					val inp = DataInputStream(c.getInputStream())
					val out = DataOutputStream(c.getOutputStream())
					assertEquals(0x05, inp.readUnsignedByte())
					val nMethods = inp.readUnsignedByte()
					inp.readFully(ByteArray(nMethods))
					out.write(byteArrayOf(0x05, 0x02))
					out.flush()

					assertEquals(0x01, inp.readUnsignedByte())
					val uLen = inp.readUnsignedByte()
					val user = String(ByteArray(uLen).also { inp.readFully(it) }, Charsets.UTF_8)
					val pLen = inp.readUnsignedByte()
					val pass = String(ByteArray(pLen).also { inp.readFully(it) }, Charsets.UTF_8)
					if (user == "bob" && pass == "pw123") {
						out.write(byteArrayOf(0x01, 0x00))
					} else {
						out.write(byteArrayOf(0x01, 0x01))
						out.flush()
						return@use
					}
					out.flush()

					val head = ByteArray(4)
					inp.readFully(head)
					assertEquals(0x03, head[3].toInt() and 0xFF) // ATYP = domain
					val dLen = inp.readUnsignedByte()
					inp.readFully(ByteArray(dLen + 2))
					out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90.toByte()))
					out.flush()
				}
				// 2. Rejected auth
				srv.accept().use { c ->
					val inp = DataInputStream(c.getInputStream())
					val out = DataOutputStream(c.getOutputStream())
					inp.readUnsignedByte()
					val nMethods = inp.readUnsignedByte()
					inp.readFully(ByteArray(nMethods))
					out.write(byteArrayOf(0x05, 0x02))
					out.flush()
					inp.readUnsignedByte()
					val uLen = inp.readUnsignedByte()
					inp.readFully(ByteArray(uLen))
					val pLen = inp.readUnsignedByte()
					inp.readFully(ByteArray(pLen))
					out.write(byteArrayOf(0x01, 0xFF.toByte()))
					out.flush()
				}
			}
		}.apply { isDaemon = true; start() }

		val goodSocks = ProxyProfile(id = "s1", name = "S1", type = "SOCKS5", host = "127.0.0.1", port = socksSrv.localPort, username = "bob", password = "pw123")
		val sSock = UpstreamProxy.connectSocket(goodSocks, "remote.example.com", 443, 2000, 2000, { true })
		assertNotNull(sSock)
		sSock!!.close()

		val badAuthSocks = goodSocks.copy(password = "wrong")
		assertNull(UpstreamProxy.connectSocket(badAuthSocks, "remote.example.com", 443, 2000, 2000, { true }))
		socksThread.join(1500)

		assertTrue(UpstreamProxy.testProxyLatency(ProxyProfile(id = "bad", name = "bad", host = "", port = 0)).isFailure)
		assertNull(UpstreamProxy.openSocks5UdpAssociate(httpProfile, 1000, 1000, { true }, { true }))
		assertNull(UpstreamProxy.queryDnsOverProxyTcp(goodSocks, ByteArray(4), "1.1.1.1", 1000, { true }))
		assertNull(UpstreamProxy.queryDnsOverProxyTcp(goodSocks, ByteArray(20), "", 1000, { true }))
	}
}
