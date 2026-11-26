package com.renwixx.trueadblocker

import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NXDOMAIN
import com.renwixx.trueadblocker.data.BackupSections
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.DEFAULT_TRACKING_PARAM_RULES
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.data.THEME_LIGHT
import com.renwixx.trueadblocker.data.escapeSqlLike
import com.renwixx.trueadblocker.engine.FastRouteRule
import com.renwixx.trueadblocker.engine.PrivacySanitizer
import com.renwixx.trueadblocker.engine.RuleEngine
import com.renwixx.trueadblocker.net.CertAuthority
import com.renwixx.trueadblocker.net.DnsWire
import com.renwixx.trueadblocker.net.MitmProxy
import com.renwixx.trueadblocker.net.TunL3Router
import com.renwixx.trueadblocker.net.UpstreamProxy
import java.io.ByteArrayOutputStream
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.util.zip.GZIPOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExampleUnitTest {
	@Test
	fun routeRuleAllowsContentAndBlocksAdPath() {
		val blockAdRoute = CustomRule(
			pattern = "xxx.com/ad*",
			matchMode = MODE_WILDCARD,
			isAllow = false,
			isRoute = true,
		)

		assertTrue(RuleEngine.testSingleCustomRule(blockAdRoute, "https://xxx.com/ad"))
		assertTrue(RuleEngine.testSingleCustomRule(blockAdRoute, "https://xxx.com/ad/banner.js?id=42"))
		assertFalse(RuleEngine.testSingleCustomRule(blockAdRoute, "https://xxx.com/content"))
		assertFalse(RuleEngine.testSingleCustomRule(blockAdRoute, "https://xxx.com/content/article-1"))
	}

	@Test
	fun customDomainModesExactWildcardAndRegex() {
		val exact = CustomRule(pattern = "ads.example.com", matchMode = MODE_EXACT, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(exact, "https://ads.example.com/pixel.gif"))
		assertFalse(RuleEngine.testSingleCustomRule(exact, "https://sub.ads.example.com/pixel.gif"))

		val wild = CustomRule(pattern = "*.doubleclick.net", matchMode = MODE_WILDCARD, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(wild, "googleads.g.doubleclick.net"))
		assertTrue(RuleEngine.testSingleCustomRule(wild, "doubleclick.net"))
		assertFalse(RuleEngine.testSingleCustomRule(wild, "notdoubleclick.net"))

		val regex = CustomRule(
			pattern = """^https?://([a-z0-9-]+\.)?tracker\.io/(collect|beacon).*$""",
			matchMode = MODE_REGEX,
			isAllow = false,
			isRoute = true,
		)
		assertNull(RuleEngine.validateRegex(regex.pattern))
		assertTrue(RuleEngine.testSingleCustomRule(regex, "https://eu.tracker.io/collect?uid=99"))
		assertFalse(RuleEngine.testSingleCustomRule(regex, "https://eu.tracker.io/static/logo.png"))
	}

	@Test
	fun multiFormatDictionaryParsingCoversAllSyntaxes() {
		val allowExact = HashMap<String, String>()
		val allowZones = HashMap<String, String>()
		val blockExact = HashMap<String, String>()
		val blockZones = HashMap<String, String>()
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>()
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val tokenAllows = HashMap<String, MutableList<FastRouteRule>>()
		val tokenBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val fallback = ArrayList<FastRouteRule>()

		val lines = listOf(
			"! Comment header",
			"0.0.0.0 telemetry.vendor.com",
			"*.wildtracker.org",
			"address=/dnsmasq-ad.net/",
			"||doubleclick.net^",
			"@@||safe.doubleclick.net^",
			"||news.site.com/ads/banner^",
			"/pagead/show_ads.js",
			"||stream.ad.io/socket^\$websocket",
			"example.com##.cosmetic-banner",
		)

		for (ln in lines) {
			RuleEngine.parseLineIntoSets(
				ln,
				"Test Dictionary",
				allowExact,
				allowZones,
				blockExact,
				blockZones,
				hostAllows,
				hostBlocks,
				tokenAllows,
				tokenBlocks,
				fallback,
			)
		}

		assertEquals("Test Dictionary", blockExact["telemetry.vendor.com"])
		assertEquals("Test Dictionary", blockZones["wildtracker.org"])
		assertEquals("Test Dictionary", blockZones["dnsmasq-ad.net"])
		assertEquals("Test Dictionary", blockZones["doubleclick.net"])
		assertEquals("Test Dictionary", allowZones["safe.doubleclick.net"])
		assertTrue(hostBlocks.containsKey("news.site.com"))
		assertEquals("Test Dictionary", hostBlocks["news.site.com"]!!.first().sourceTitle)
		assertTrue(hostBlocks["stream.ad.io"]!!.first().isWebSocketOnly)
		assertTrue(tokenBlocks.containsKey("show") || tokenBlocks.containsKey("pagead"))
	}

	@Test
	fun adblockCaretAndWildcardMatching() {
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad/script.js", "xxx.com/ad^*"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad?slot=1", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/admin/panel", "xxx.com/ad^*"))
	}

	@Test
	fun dnsIpv4UdpParseAndBlockedSynthesis() {
		val dnsQuery = ByteArrayOutputStream().apply {
			write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
			write(3)
			write("ads".toByteArray())
			write(7)
			write("example".toByteArray())
			write(3)
			write("com".toByteArray())
			write(0)
			write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
		}.toByteArray()

		val srcIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val dstIp = byteArrayOf(10, 111, 222.toByte(), 1)
		val rawPkt = DnsWire.buildIpv4Udp(srcIp, dstIp, 54321, 53, dnsQuery)

		val parsedFrame = DnsWire.parseIpv4Udp(rawPkt, rawPkt.size)
		assertNotNull(parsedFrame)
		assertEquals(53, parsedFrame!!.dstPort)
		assertArrayEquals(srcIp, parsedFrame.srcIp)

		val parsedDns = DnsWire.parseDnsQuery(parsedFrame.payload)
		assertNotNull(parsedDns)
		assertEquals("ads.example.com", parsedDns!!.qname)
		assertEquals(DnsWire.TYPE_A, parsedDns.qtype)

		val blockedWire = DnsWire.buildSyntheticBlockedDns(parsedFrame.payload, parsedDns)
		assertEquals(0x12.toByte(), blockedWire[0])
		assertEquals(0x34.toByte(), blockedWire[1])
		assertTrue(blockedWire.size > parsedDns.questionEndOffset)
	}

	@Test
	fun websocketRfc6455AcceptAndUblockNoopStubs() {
		// RFC 6455 section 4.2.2 test vector
		val accept = MitmProxy.computeWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")
		assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept)

		val jsStub = MitmProxy.selectNoopStub("GET", "/ads/sdk.js?v=2", "*/*", "script")
		assertNotNull(jsStub)
		assertTrue(jsStub!!.first.startsWith("application/javascript"))
		assertEquals(0, jsStub.second.size)

		val imgStub = MitmProxy.selectNoopStub("GET", "/pixel.png", "image/webp,*/*", "image")
		assertNotNull(imgStub)
		assertEquals("image/gif", imgStub!!.first)
		assertEquals(42, imgStub.second.size)
		assertEquals("GIF89a", String(imgStub.second, 0, 6, Charsets.US_ASCII))

		val beaconStub = MitmProxy.selectNoopStub("POST", "/telemetry/collect", "*/*", "empty")
		assertNull(beaconStub)
	}

	@Test
	fun rootCaAndLeafCertificatePassStrictPkixAndExactAsn1IssuerMatch() {
		val caPair = CertAuthority.generateRsaPair()
		val caCert = CertAuthority.buildRootCaCertificate(caPair)
		val leafPair = CertAuthority.generateRsaPair()
		val leafCert = CertAuthority.buildLeafCertificate("www.google.com", caCert, caPair.private, leafPair)

		// BoringSSL in Chrome requires exact byte-for-byte ASN.1 DER Name equality between leaf Issuer and CA Subject
		assertArrayEquals(caCert.subjectX500Principal.encoded, leafCert.issuerX500Principal.encoded)
		leafCert.verify(caCert.publicKey)

		val cf = CertificateFactory.getInstance("X.509")
		val certPath = cf.generateCertPath(listOf(leafCert))
		val params = PKIXParameters(setOf(TrustAnchor(caCert, null))).apply {
			isRevocationEnabled = false
		}
		CertPathValidator.getInstance("PKIX").validate(certPath, params)
	}

	@Test
	fun crossFormatDeduplicationEliminatesHostsWildcardSubdomainAndRouteDuplicates() {
		val allowExact = HashMap<String, String>()
		val allowZones = HashMap<String, String>()
		val blockExact = HashMap<String, String>()
		val blockZones = HashMap<String, String>()
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>()
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val tokenAllows = HashMap<String, MutableList<FastRouteRule>>()
		val tokenBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val fallback = ArrayList<FastRouteRule>()
		val seenRoutes = HashSet<String>()
		val pool = HashMap<String, String>()

		val mixedSources = listOf(
			"StevenBlack" to "0.0.0.0 doubleclick.net",
			"StevenBlack" to "127.0.0.1 googleads.g.doubleclick.net",
			"OISD Big" to "*.doubleclick.net",
			"AdGuard DNS" to "||doubleclick.net^",
			"Goodbye Ads" to "||sub.doubleclick.net^",
			"Dnsmasq List" to "address=/deep.sub.doubleclick.net/",
			"EasyList" to "||doubleclick.net/pagead/ads^",
			"EasyList" to "/pagead/show_ads.js",
			"uBlock Filters" to "/pagead/show_ads.js",
			"EasyList" to "||portal.example.org/banners/top^",
			"AdGuard DNS" to "||portal.example.org/banners/top^",
		)

		for ((srcName, ln) in mixedSources) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = srcName,
				allowExact = allowExact,
				allowZones = allowZones,
				blockExact = blockExact,
				blockZones = blockZones,
				hostRouteAllows = hostAllows,
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = tokenAllows,
				tokenRouteBlocks = tokenBlocks,
				fallbackRouteBlocks = fallback,
				seenRouteKeys = seenRoutes,
				sourcePool = pool,
			)
		}

		RuleEngine.compactRuleSets(
			allowExact = allowExact,
			allowZones = allowZones,
			blockExact = blockExact,
			blockZones = blockZones,
			hostRouteBlocks = hostBlocks,
			sourcePool = pool,
		)

		assertEquals(0, blockExact.size)
		assertEquals(setOf("doubleclick.net"), blockZones.keys)
		assertEquals("OISD Big, AdGuard DNS, StevenBlack", blockZones["doubleclick.net"])
		assertFalse(hostBlocks.containsKey("doubleclick.net"))
		assertEquals(1, hostBlocks["portal.example.org"]?.size)
		assertEquals("EasyList", hostBlocks["portal.example.org"]?.first()?.sourceTitle)
		val totalTokenRules = tokenBlocks.values.sumOf { it.size }
		assertEquals(1, totalTokenRules)
	}

	@Test
	fun trackingParameterCleanerAndCosmeticHtmlInjection() {
		val outcome = PrivacySanitizer.sanitizePathAndQuery(
			pathAndQuery = "/watch?v=abc123&utm_source=share&fbclid=IwAR99&page=2&custom_trk=77#comments",
			userRulesText = DEFAULT_TRACKING_PARAM_RULES,
			extraExactParams = setOf("custom_trk"),
		)
		assertEquals("/watch?v=abc123&page=2#comments", outcome.cleanedPathAndQuery)
		assertEquals(listOf("utm_source", "fbclid", "custom_trk"), outcome.removedParams)

		val html = "<!DOCTYPE html><html><head><title>News</title></head><body><div class=\"ad-slot\">Ad</div></body></html>"
		val gzBytes = ByteArrayOutputStream().use { bos ->
			GZIPOutputStream(bos).use { gz -> gz.write(html.toByteArray(Charsets.UTF_8)) }
			bos.toByteArray()
		}

		val injected = PrivacySanitizer.injectCosmeticCssIntoHtml(
			rawBody = gzBytes,
			isGzipEncoded = true,
			cssContent = ".ad-slot{display:none!important}",
		)
		assertNotNull(injected)
		val decoded = String(injected!!, Charsets.UTF_8)
		assertTrue(decoded.contains("<style id=\"tb-cosmetic\">.ad-slot{display:none!important}</style></head>"))
	}

	@Test
	fun cosmeticAndRemoveParamParsingInRuleEngine() {
		val genericCos = LinkedHashSet<String>()
		val domainCos = HashMap<String, MutableList<String>>()
		val removeParams = HashSet<String>()

		val sampleLines = listOf(
			"##.banner-ad",
			"news.example.com,blog.example.com##div > .sponsored-box",
			"example.com##div:has(.procedural)",
			"*\$removeparam=ttclid",
			"\$removeparam=igshid",
			"||site.example.com^\$removeparam=id",
		)

		for (ln in sampleLines) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = "Filter",
				allowExact = HashMap(),
				allowZones = HashMap(),
				blockExact = HashMap(),
				blockZones = HashMap(),
				hostRouteAllows = HashMap(),
				hostRouteBlocks = HashMap(),
				tokenRouteAllows = HashMap(),
				tokenRouteBlocks = HashMap(),
				fallbackRouteBlocks = ArrayList(),
				genericCosmetics = genericCos,
				domainCosmetics = domainCos,
				removeParams = removeParams,
			)
		}

		assertTrue(genericCos.contains(".banner-ad"))
		assertEquals(listOf("div > .sponsored-box"), domainCos["news.example.com"])
		assertFalse(domainCos.containsKey("example.com"))
		assertTrue(removeParams.contains("ttclid"))
		assertTrue(removeParams.contains("igshid"))
		assertFalse(removeParams.contains("id"))
	}

	@Test
	fun dnsCnameChainInspectionAndNxDomainSynthesis() {
		// Query: metrics.firstparty.com -> Answer 1: CNAME tracker.3rdparty.io -> Answer 2: A 93.184.216.34
		val resp = ByteArrayOutputStream().apply {
			write(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0x81.toByte(), 0x80.toByte()))
			write(byteArrayOf(0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00))
			// Question: metrics.firstparty.com
			for (lbl in listOf("metrics", "firstparty", "com")) {
				write(lbl.length)
				write(lbl.toByteArray())
			}
			write(0)
			write(byteArrayOf(0x00, 0x01, 0x00, 0x01))

			// Answer 1: pointer 0xC00C -> CNAME (5) -> tracker.3rdparty.io
			write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C))
			val cnameRdata = ByteArrayOutputStream().apply {
				for (lbl in listOf("tracker", "3rdparty", "io")) {
					write(lbl.length)
					write(lbl.toByteArray())
				}
				write(0)
			}.toByteArray()
			write((cnameRdata.size ushr 8) and 0xFF)
			write(cnameRdata.size and 0xFF)
			write(cnameRdata)

			// Answer 2: pointer 0xC00C -> A (1) -> 157.240.1.52
			write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04))
			write(byteArrayOf(157.toByte(), 240.toByte(), 1, 52))
		}.toByteArray()

		val insp = DnsWire.inspectDnsAnswer(resp, maxCnames = 8)
		assertEquals(listOf("tracker.3rdparty.io"), insp.cnameChain)
		assertEquals(listOf("157.240.1.52"), insp.ipv4Addresses)

		val rawQuery = resp.copyOfRange(0, 12 + "metrics.firstparty.com".length + 2 + 4).also {
			it[2] = 0x01
			it[3] = 0x00
			it[6] = 0x00
			it[7] = 0x00
		}
		val parsedQ = DnsWire.parseDnsQuery(rawQuery)!!
		val nxWire = DnsWire.buildBlockedDnsReply(rawQuery, parsedQ, BLOCKED_DNS_NXDOMAIN)
		assertEquals(3, nxWire[3].toInt() and 0x0F)
	}

	@Test
	fun perAppProxyMatchingAndL3TcpChecksumVerification() {
		val whatsappSocks = ProxyProfile(
			id = "p1",
			name = "WhatsApp SOCKS5",
			isEnabled = true,
			type = "SOCKS5",
			host = "127.0.0.1",
			port = 1080,
			isAllApps = false,
			appPackages = setOf("com.whatsapp"),
			hostFilter = "*",
			portFilter = "443,5222",
		)

		assertNotNull(UpstreamProxy.selectProxy(listOf(whatsappSocks), "com.whatsapp", "g.whatsapp.net", 443))
		assertNotNull(UpstreamProxy.selectProxy(listOf(whatsappSocks), "com.whatsapp", "g.whatsapp.net", 5222))
		assertNull(UpstreamProxy.selectProxy(listOf(whatsappSocks), "com.whatsapp", "g.whatsapp.net", 80))
		assertNull(UpstreamProxy.selectProxy(listOf(whatsappSocks), "com.android.chrome", "google.com", 443))

		val srcIp = byteArrayOf(157.toByte(), 240.toByte(), 1, 52)
		val dstIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val payload = "HELLO".toByteArray(Charsets.US_ASCII)
		val tcpPkt = TunL3Router.buildIpv4TcpPacket(
			srcIp = srcIp,
			dstIp = dstIp,
			srcPort = 443,
			dstPort = 51234,
			seqNum = 1001L,
			ackNum = 2002L,
			flags = TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK,
			payload = payload,
		)

		assertEquals(0, DnsWire.ipv4Checksum(tcpPkt, 0, 20))
		assertEquals(0, TunL3Router.tcpChecksum(srcIp, dstIp, tcpPkt, 20, tcpPkt.size - 20))
	}

	@Test
	fun dohBootstrapClientAndProxyDnsQueryBuilder() {
		val client = DnsWire.createProtectedHttpClient(
			protectSocket = { true },
			protectDatagram = { true },
		)
		val bootstrapIps = client.dns.lookup("cloudflare-dns.com").map { it.hostAddress }
		assertTrue(bootstrapIps.contains("1.1.1.1"))

		val queryWire = DnsWire.buildDnsQueryWire("example.org", DnsWire.TYPE_A)
		val parsed = DnsWire.parseDnsQuery(queryWire)
		assertNotNull(parsed)
		assertEquals("example.org", parsed!!.qname)
		assertEquals(DnsWire.TYPE_A, parsed.qtype)
	}

	@Test
	fun bypassedAppsExcludedFromProxyFirewallAndL3Trigger() {
		val allAppsProxy = ProxyProfile(
			id = "global_socks",
			name = "Global SOCKS5",
			isEnabled = true,
			type = "SOCKS5",
			host = "127.0.0.1",
			port = 1080,
			isAllApps = true,
		)
		val bypassed = setOf("com.carriez.flutter_hbb", "org.telegram.messenger")

		assertNull(
			UpstreamProxy.selectProxy(
				profiles = listOf(allAppsProxy),
				appPkg = "com.carriez.flutter_hbb",
				host = "rustdesk.com",
				port = 21116,
				bypassedApps = bypassed,
			)
		)
		assertNotNull(
			UpstreamProxy.selectProxy(
				profiles = listOf(allAppsProxy),
				appPkg = "com.whatsapp",
				host = "g.whatsapp.net",
				port = 443,
				bypassedApps = bypassed,
			)
		)

		val cfg = AppConfig(
			bypassedApps = bypassed,
			firewallWifiApps = setOf("org.telegram.messenger"),
			firewallMobileApps = setOf("org.telegram.messenger"),
		)
		assertTrue(cfg.isAppBypassed("org.telegram.messenger"))
		assertFalse(cfg.isAppFirewalled("org.telegram.messenger", isOnWifi = true, isOnMobile = false))
		assertFalse(cfg.shouldEnableFullL3Capture(isOnWifi = true, isOnMobile = false))
	}

	@Test
	fun largeUdpFragmentationAndTcpWindowScaleOptionsPassValidation() {
		val srcIp = byteArrayOf(203.toByte(), 0, 113, 10)
		val dstIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val largePayload = ByteArray(3200) { i -> (i and 0xFF).toByte() }
		val idGen = java.util.concurrent.atomic.AtomicInteger(100)

		val frames = TunL3Router.buildIpv4UdpFrames(
			srcIp = srcIp,
			dstIp = dstIp,
			srcPort = 21116,
			dstPort = 54321,
			payload = largePayload,
			mtu = 1400,
			ipIdGen = idGen,
		)
		assertTrue(frames.size == 3)

		val reconstructed = ByteArray(8 + largePayload.size)
		for ((idx, frame) in frames.withIndex()) {
			assertTrue(frame.size <= 1400)
			assertEquals(0, DnsWire.ipv4Checksum(frame, 0, 20))
			assertNull(DnsWire.parseIpv4Udp(frame, frame.size))

			val fragField = TunL3Router.u16(frame, 6)
			val isMore = (fragField and 0x2000) != 0
			val offBytes = (fragField and 0x1FFF) * 8
			assertEquals(idx < frames.lastIndex, isMore)
			if (idx < frames.lastIndex)
				assertEquals(0, (frame.size - 20) % 8)

			System.arraycopy(frame, 20, reconstructed, offBytes, frame.size - 20)
		}

		val udpLen = ((reconstructed[4].toInt() and 0xFF) shl 8) or (reconstructed[5].toInt() and 0xFF)
		assertEquals(8 + largePayload.size, udpLen)
		assertArrayEquals(largePayload, reconstructed.copyOfRange(8, reconstructed.size))

		val synAck = TunL3Router.buildIpv4TcpPacket(
			srcIp = srcIp,
			dstIp = dstIp,
			srcPort = 443,
			dstPort = 49152,
			seqNum = 5000L,
			ackNum = 9000L,
			flags = TunL3Router.FLAG_SYN or TunL3Router.FLAG_ACK,
			payload = ByteArray(0),
			tcpMss = 1240,
			winScale = 7,
			windowSize = 0xFFFF,
		)
		assertEquals(48, synAck.size)
		assertEquals(0, DnsWire.ipv4Checksum(synAck, 0, 20))
		assertEquals(0, TunL3Router.tcpChecksum(srcIp, dstIp, synAck, 20, 28))
		assertEquals(7, TunL3Router.parseSynWindowScale(synAck, 20, 28))
	}

	@Test
	fun endToEndL3TcpLargeImageTransferAndFragmentedUdpEchoWithFalseProtect() {
		val serverPayload = ByteArray(180_000) { i -> ((i * 31 + 7) and 0xFF).toByte() }
		val expectedReq = ByteArray(4096) { i -> ((i * 13 + 3) and 0xFF).toByte() }
		val receivedByServer = ByteArrayOutputStream()

		val tcpEchoServer = java.net.ServerSocket(0, 16, java.net.InetAddress.getByName("127.0.0.1"))
		val srvPort = tcpEchoServer.localPort
		val serverThread = Thread {
			tcpEchoServer.use { srv ->
				val sock = srv.accept()
				sock.use { s ->
					val inp = s.getInputStream()
					val buf = ByteArray(2048)
					while (receivedByServer.size() < expectedReq.size) {
						val n = inp.read(buf)
						if (n <= 0)
							break
						receivedByServer.write(buf, 0, n)
					}
					s.getOutputStream().write(serverPayload)
					s.getOutputStream().flush()
				}
			}
		}.apply { isDaemon = true; start() }

		val tunOutFrames = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
		val router = TunL3Router(
			_configProvider = { AppConfig() },
			_pushTraffic = {},
			_cm = null,
			_pm = null,
			_protectSocket = { false },
			_protectDatagram = { false },
			_transportProvider = { true to false },
			_onBlockedHit = {},
			_writeTunPacket = { pkt -> tunOutFrames.offer(pkt) },
			tunMtu = 1400,
		)

		val clientIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val loopbackIp = byteArrayOf(127, 0, 0, 1)
		val clientPort = 51999
		var clientSeq = 10_000L

		val synPkt = TunL3Router.buildIpv4TcpPacket(
			srcIp = clientIp,
			dstIp = loopbackIp,
			srcPort = clientPort,
			dstPort = srvPort,
			seqNum = clientSeq,
			ackNum = 0L,
			flags = TunL3Router.FLAG_SYN,
			payload = ByteArray(0),
			tcpMss = 1360,
			winScale = 7,
			windowSize = 512,
		)
		router.handleIpv4Packet(synPkt, synPkt.size)
		clientSeq++

		val synAck = tunOutFrames.poll(3, java.util.concurrent.TimeUnit.SECONDS)
		assertNotNull("Expected SYN-ACK even when protect() returns false", synAck)
		val serverInitSeq = TunL3Router.u32(synAck!!, 24)
		var clientExpectedServerSeq = (serverInitSeq + 1L) and 0xFFFFFFFFL

		val hsAck = TunL3Router.buildIpv4TcpPacket(
			srcIp = clientIp,
			dstIp = loopbackIp,
			srcPort = clientPort,
			dstPort = srvPort,
			seqNum = clientSeq,
			ackNum = clientExpectedServerSeq,
			flags = TunL3Router.FLAG_ACK,
			payload = ByteArray(0),
			windowSize = 512,
		)
		router.handleIpv4Packet(hsAck, hsAck.size)

		var off = 0
		while (off < expectedReq.size) {
			val slice = expectedReq.copyOfRange(off, minOf(off + 1024, expectedReq.size))
			val dataPkt = TunL3Router.buildIpv4TcpPacket(
				srcIp = clientIp,
				dstIp = loopbackIp,
				srcPort = clientPort,
				dstPort = srvPort,
				seqNum = clientSeq,
				ackNum = clientExpectedServerSeq,
				flags = TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK,
				payload = slice,
				windowSize = 512,
			)
			router.handleIpv4Packet(dataPkt, dataPkt.size)
			clientSeq += slice.size
			off += slice.size
		}

		val downloaded = ByteArrayOutputStream()
		val deadline = System.currentTimeMillis() + 5000L
		while (downloaded.size() < serverPayload.size && System.currentTimeMillis() < deadline) {
			val pkt = tunOutFrames.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
			if ((pkt[9].toInt() and 0xFF) != 6)
				continue
			val ihl = (pkt[0].toInt() and 0x0F) * 4
			val dataOff = ((pkt[ihl + 12].toInt() ushr 4) and 0x0F) * 4
			val pLen = pkt.size - ihl - dataOff
			if (pLen > 0) {
				val seq = TunL3Router.u32(pkt, ihl + 4)
				if (seq == clientExpectedServerSeq) {
					downloaded.write(pkt, ihl + dataOff, pLen)
					clientExpectedServerSeq = (clientExpectedServerSeq + pLen.toLong()) and 0xFFFFFFFFL
					val ack = TunL3Router.buildIpv4TcpPacket(
						srcIp = clientIp,
						dstIp = loopbackIp,
						srcPort = clientPort,
						dstPort = srvPort,
						seqNum = clientSeq,
						ackNum = clientExpectedServerSeq,
						flags = TunL3Router.FLAG_ACK,
						payload = ByteArray(0),
						windowSize = 512,
					)
					router.handleIpv4Packet(ack, ack.size)
				}
			}
		}

		// Also verify 3000-byte fragmented UDP echo through Full-Cone NAT session
		val udpEchoServer = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
		val udpSrvPort = udpEchoServer.localPort
		val udpThread = Thread {
			udpEchoServer.use { ds ->
				ds.soTimeout = 3000
				val buf = ByteArray(65535)
				val dp = java.net.DatagramPacket(buf, buf.size)
				ds.receive(dp)
				ds.send(java.net.DatagramPacket(dp.data, dp.length, dp.address, dp.port))
			}
		}.apply { isDaemon = true; start() }

		tunOutFrames.clear()
		val udpBigMsg = ByteArray(3000) { i -> ((i * 17 + 5) and 0xFF).toByte() }
		val outboundFrags = TunL3Router.buildIpv4UdpFrames(
			srcIp = clientIp,
			dstIp = loopbackIp,
			srcPort = 54321,
			dstPort = udpSrvPort,
			payload = udpBigMsg,
			mtu = 1400,
			ipIdGen = java.util.concurrent.atomic.AtomicInteger(777),
		)
		for (frag in outboundFrags)
			router.handleIpv4Packet(frag, frag.size)

		val udpReplyReconstructed = ByteArray(8 + udpBigMsg.size)
		var gotFinalUdpFrag = false
		val udpDeadline = System.currentTimeMillis() + 3000L
		while (!gotFinalUdpFrag && System.currentTimeMillis() < udpDeadline) {
			val f = tunOutFrames.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
			if ((f[9].toInt() and 0xFF) != 17)
				continue
			val fragField = TunL3Router.u16(f, 6)
			val isMore = (fragField and 0x2000) != 0
			val fragOff = (fragField and 0x1FFF) * 8
			System.arraycopy(f, 20, udpReplyReconstructed, fragOff, f.size - 20)
			if (!isMore)
				gotFinalUdpFrag = true
		}

		serverThread.join(2000)
		udpThread.join(2000)
		router.closeAll()

		assertArrayEquals("Upstream pipelined TCP bytes must arrive in exact order", expectedReq, receivedByServer.toByteArray())
		assertArrayEquals("Downstream 180KB image transfer must arrive intact", serverPayload, downloaded.toByteArray())
		assertTrue("Expected reassembled/fragmented 3000B UDP echo", gotFinalUdpFrag)
		assertArrayEquals(udpBigMsg, udpReplyReconstructed.copyOfRange(8, udpReplyReconstructed.size))
	}

	@Test
	fun adblockCaretExactEndPipeAnchorAndCaretWithoutSlash() {
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^*"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^more"))

		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val lines = listOf(
			"||news.site.com/ads/banner^",
			"||cdn.site.com^*.gif",
			"||static.site.com/sdk/ad.js|",
		)
		for (ln in lines) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = "Test",
				allowExact = HashMap(),
				allowZones = HashMap(),
				blockExact = HashMap(),
				blockZones = HashMap(),
				hostRouteAllows = HashMap(),
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = HashMap(),
				tokenRouteBlocks = HashMap(),
				fallbackRouteBlocks = ArrayList(),
			)
		}

		val bannerPat = hostBlocks["news.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("news.site.com/ads/banner", bannerPat))
		assertTrue(RuleEngine.adblockWildcardMatch("news.site.com/ads/banner?x=1", bannerPat))
		assertFalse(RuleEngine.adblockWildcardMatch("news.site.com/ads/banner2", bannerPat))

		val gifPat = hostBlocks["cdn.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("cdn.site.com/img/pixel.gif", gifPat))
		assertFalse(RuleEngine.adblockWildcardMatch("cdn.site.com/img/pixel.png", gifPat))

		val exactEndPat = hostBlocks["static.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("static.site.com/sdk/ad.js", exactEndPat))
		assertFalse(RuleEngine.adblockWildcardMatch("static.site.com/sdk/ad.js?v=2", exactEndPat))
	}

	@Test
	fun contextualAdblockModifiersDoNotPoisonDnsAndMatchOnlyIntendedContext() {
		val allowZones = HashMap<String, String>()
		val blockZones = HashMap<String, String>()
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>()
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()

		val lines = listOf(
			"||embed.widget.com^\$third-party",
			"@@||cdn.tracker.com^\$image",
			"||legit-portal.com^\$popup",
			"||adserver.net^\$important",
		)
		for (ln in lines) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = "EasyList",
				allowExact = HashMap(),
				allowZones = allowZones,
				blockExact = HashMap(),
				blockZones = blockZones,
				hostRouteAllows = hostAllows,
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = HashMap(),
				tokenRouteBlocks = HashMap(),
				fallbackRouteBlocks = ArrayList(),
			)
		}

		assertFalse(blockZones.containsKey("embed.widget.com"))
		assertFalse(blockZones.containsKey("legit-portal.com"))
		assertFalse(allowZones.containsKey("cdn.tracker.com"))
		assertTrue(blockZones.containsKey("adserver.net"))

		val tpRule = hostBlocks["embed.widget.com"]!!.first()
		assertFalse(tpRule.matchesContext(isWebSocket = false, reqTypeMask = RuleEngine.RES_SCRIPT, isThirdParty = false))
		assertTrue(tpRule.matchesContext(isWebSocket = false, reqTypeMask = RuleEngine.RES_SCRIPT, isThirdParty = true))

		val imgAllow = hostAllows["cdn.tracker.com"]!!.first()
		assertTrue(imgAllow.matchesContext(isWebSocket = false, reqTypeMask = RuleEngine.RES_IMAGE, isThirdParty = true))
		assertFalse(imgAllow.matchesContext(isWebSocket = false, reqTypeMask = RuleEngine.RES_SCRIPT, isThirdParty = true))
	}

	@Test
	fun compactRuleSetsPreservesSubdomainRoutesAndCosmeticExceptions() {
		val allowExact = HashMap<String, String>()
		val allowZones = hashMapOf("cdn.doubleclick.net" to "Unbreak")
		val blockExact = hashMapOf("portal.example.org" to "Hosts")
		val blockZones = hashMapOf("doubleclick.net" to "AdGuard")
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val genericCos = LinkedHashSet<String>()
		val domainCos = HashMap<String, MutableList<String>>()
		val domainEx = HashMap<String, MutableSet<String>>()

		for (ln in listOf(
			"||portal.example.org/ads/slot^",
			"||doubleclick.net/pagead/ads^",
			"~google.com##.global-sponsor",
			"news.com,~sub.news.com##.promo-banner",
			"blog.com#@#.global-sponsor",
		)) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = "Test",
				allowExact = allowExact,
				allowZones = allowZones,
				blockExact = blockExact,
				blockZones = blockZones,
				hostRouteAllows = HashMap(),
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = HashMap(),
				tokenRouteBlocks = HashMap(),
				fallbackRouteBlocks = ArrayList(),
				genericCosmetics = genericCos,
				domainCosmetics = domainCos,
				domainCosmeticExceptions = domainEx,
			)
		}

		RuleEngine.compactRuleSets(
			allowExact = allowExact,
			allowZones = allowZones,
			blockExact = blockExact,
			blockZones = blockZones,
			hostRouteBlocks = hostBlocks,
		)

		assertTrue(hostBlocks.containsKey("portal.example.org"))
		assertTrue(hostBlocks.containsKey("doubleclick.net"))
		assertTrue(genericCos.contains(".global-sponsor"))
		assertTrue(domainEx["google.com"]?.contains(".global-sponsor") == true)
		assertTrue(domainEx["sub.news.com"]?.contains(".promo-banner") == true)
		assertTrue(domainEx["blog.com"]?.contains(".global-sponsor") == true)
	}

	@Test
	fun gzipBombGuardStyleEscapePresignedUrlAndHostsMultiDomain() {
		val hugeHtml = "<html><head></head><body>" + "A".repeat(2_100_000) + "</body></html>"
		val gzBomb = ByteArrayOutputStream().use { bos ->
			GZIPOutputStream(bos).use { gz -> gz.write(hugeHtml.toByteArray(Charsets.UTF_8)) }
			bos.toByteArray()
		}
		assertTrue(gzBomb.size < 32_768)
		assertNull(
			PrivacySanitizer.injectCosmeticCssIntoHtml(
				rawBody = gzBomb,
				isGzipEncoded = true,
				cssContent = ".ad{display:none}",
			)
		)

		val smallHtml = "<html><head></head><body>ok</body></html>".toByteArray(Charsets.UTF_8)
		val safeInjected = PrivacySanitizer.injectCosmeticCssIntoHtml(
			rawBody = smallHtml,
			isGzipEncoded = false,
			cssContent = ".ad{display:none}</style><script>evil()</script>",
		)
		assertNotNull(safeInjected)
		val injectedStr = String(safeInjected!!, Charsets.UTF_8)
		assertFalse(injectedStr.contains("</style><script>"))

		val azureSas = "/container/file.zip?sv=2022-11-02&si=readpolicy&sr=b&sig=HmacSignatureValue"
		assertEquals(azureSas, PrivacySanitizer.sanitizePathAndQuery(azureSas, DEFAULT_TRACKING_PARAM_RULES).cleanedPathAndQuery)

		val awsPresigned = "/bucket/doc.pdf?utm_source=keep&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef"
		assertEquals(awsPresigned, PrivacySanitizer.sanitizePathAndQuery(awsPresigned, DEFAULT_TRACKING_PARAM_RULES).cleanedPathAndQuery)

		val encodedParam = PrivacySanitizer.sanitizePathAndQuery("/page?%75tm_source=mail&id=7", DEFAULT_TRACKING_PARAM_RULES)
		assertEquals("/page?id=7", encodedParam.cleanedPathAndQuery)

		val blockExact = HashMap<String, String>()
		RuleEngine.parseLineIntoSets(
			rawLine = "0.0.0.0   ad1.multi.test   ad2.multi.test\t# trailing comment",
			listTitle = "Hosts",
			allowExact = HashMap(),
			allowZones = HashMap(),
			blockExact = blockExact,
			blockZones = HashMap(),
			hostRouteAllows = HashMap(),
			hostRouteBlocks = HashMap(),
			tokenRouteAllows = HashMap(),
			tokenRouteBlocks = HashMap(),
			fallbackRouteBlocks = ArrayList(),
		)
		assertEquals("Hosts", blockExact["ad1.multi.test"])
		assertEquals("Hosts", blockExact["ad2.multi.test"])
		assertEquals("xn--e1afmkfd.xn--p1ai", RuleEngine.normalizeHost("пример.рф."))
		assertEquals("utm\\_source\\%20", escapeSqlLike("utm_source%20"))

		val caPair = CertAuthority.generateRsaPair()
		val caCert = CertAuthority.buildRootCaCertificate(caPair)
		val leafPair = CertAuthority.generateRsaPair()
		val ipv6Cert = CertAuthority.buildLeafCertificate("[2606:4700:4700::1111]", caCert, caPair.private, leafPair)
		ipv6Cert.verify(caCert.publicKey)
	}

	@Test
	fun endToEndSocks5UdpAssociateRelayUdpLeakGuardAndProxyDnsOverTcp() {
		val targetUdpHits = java.util.concurrent.atomic.AtomicInteger(0)
		val targetUdpServer = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
		val targetUdpPort = targetUdpServer.localPort
		val targetThread = Thread {
			targetUdpServer.use { ds ->
				ds.soTimeout = 3000
				val buf = ByteArray(4096)
				while (!Thread.currentThread().isInterrupted) {
					val dp = java.net.DatagramPacket(buf, buf.size)
					try {
						ds.receive(dp)
					} catch (_: Throwable) {
						break
					}
					targetUdpHits.incrementAndGet()
					val echoed = "RELAY_OK:".toByteArray(Charsets.US_ASCII) + dp.data.copyOfRange(0, dp.length)
					ds.send(java.net.DatagramPacket(echoed, echoed.size, dp.address, dp.port))
				}
			}
		}.apply { isDaemon = true; start() }

		val socksUdpRelay = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
		val socksUdpPort = socksUdpRelay.localPort
		val relayThread = Thread {
			socksUdpRelay.use { relay ->
				relay.soTimeout = 3000
				val buf = ByteArray(8192)
				var clientAddr: java.net.InetAddress? = null
				var clientPort = 0
				while (!Thread.currentThread().isInterrupted) {
					val dp = java.net.DatagramPacket(buf, buf.size)
					try {
						relay.receive(dp)
					} catch (_: Throwable) {
						break
					}
					if (dp.port != targetUdpPort) {
						clientAddr = dp.address
						clientPort = dp.port
						val unwrapped = UpstreamProxy.unwrapSocks5UdpPacket(buf, dp.length) ?: continue
						val dst = java.net.InetAddress.getByAddress(unwrapped.srcIp)
						relay.send(java.net.DatagramPacket(unwrapped.payload, unwrapped.payload.size, dst, unwrapped.srcPort))
					} else if (clientAddr != null && clientPort > 0) {
						val wrapped = UpstreamProxy.wrapSocks5UdpPayload(
							dstIp = byteArrayOf(127, 0, 0, 1),
							dstPort = targetUdpPort,
							payload = buf.copyOfRange(0, dp.length),
						)
						relay.send(java.net.DatagramPacket(wrapped, wrapped.size, clientAddr, clientPort))
					}
				}
			}
		}.apply { isDaemon = true; start() }

		val socksTcpServer = java.net.ServerSocket(0, 16, java.net.InetAddress.getByName("127.0.0.1"))
		val socksTcpPort = socksTcpServer.localPort
		val socksCtrlThread = Thread {
			socksTcpServer.use { srv ->
				srv.soTimeout = 3000
				repeat(2) {
					val client = runCatching { srv.accept() }.getOrNull() ?: return@repeat
					Thread {
						client.use { c ->
							val inp = java.io.DataInputStream(c.getInputStream())
							val out = java.io.DataOutputStream(c.getOutputStream())
							val ver = inp.readUnsignedByte()
							val nMethods = inp.readUnsignedByte()
							inp.readFully(ByteArray(nMethods))
							assertEquals(0x05, ver)
							out.write(byteArrayOf(0x05, 0x00))
							out.flush()

							val cmdHead = ByteArray(4)
							inp.readFully(cmdHead)
							val cmd = cmdHead[1].toInt() and 0xFF
							val atyp = cmdHead[3].toInt() and 0xFF
							when (atyp) {
								0x01 -> inp.readFully(ByteArray(6))
								0x03 -> {
									val dLen = inp.readUnsignedByte()
									inp.readFully(ByteArray(dLen + 2))
								}
								0x04 -> inp.readFully(ByteArray(18))
							}

							if (cmd == 0x03) {
								// Return 0.0.0.0 + socksUdpPort to verify RFC 1928 wildcard BND.ADDR resolution to control peer IP
								out.write(
									byteArrayOf(
										0x05,
										0x00,
										0x00,
										0x01,
										0,
										0,
										0,
										0,
										((socksUdpPort ushr 8) and 0xFF).toByte(),
										(socksUdpPort and 0xFF).toByte(),
									)
								)
								out.flush()
								runCatching { inp.read() }
							} else if (cmd == 0x01) {
								out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53))
								out.flush()
								val qLen = inp.readUnsignedShort()
								val rawQ = ByteArray(qLen)
								inp.readFully(rawQ)
								val parsed = DnsWire.parseDnsQuery(rawQ)!!
								val qSec = rawQ.copyOfRange(12, parsed.questionEndOffset)
								val dnsResp = ByteArrayOutputStream().apply {
									write(rawQ[0].toInt())
									write(rawQ[1].toInt())
									write(0x81)
									write(0x80)
									write(byteArrayOf(0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00))
									write(qSec)
									write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04))
									write(byteArrayOf(198.toByte(), 51, 100, 42))
								}.toByteArray()
								out.writeShort(dnsResp.size)
								out.write(dnsResp)
								out.flush()
							}
						}
					}.apply { isDaemon = true; start() }
				}
			}
		}.apply { isDaemon = true; start() }

		val socksProfile = ProxyProfile(
			id = "socks_udp",
			name = "Full SOCKS5",
			isEnabled = true,
			type = "SOCKS5",
			host = "127.0.0.1",
			port = socksTcpPort,
			isRemoteDns = true,
			isUdpRelay = true,
			isBlockUdpFallback = true,
			isAllApps = true,
		)

		val dnsQuery = DnsWire.buildDnsQueryWire("proxied.service.test", DnsWire.TYPE_A)
		val dnsOverProxy = UpstreamProxy.queryDnsOverProxyTcp(
			profile = socksProfile,
			rawQuery = dnsQuery,
			dnsIp = "9.9.9.9",
			timeoutMs = 2500,
			protectSocket = { true },
		)
		assertNotNull("Expected DNS-over-TCP response through SOCKS5 proxy", dnsOverProxy)
		val dnsInsp = DnsWire.inspectDnsAnswer(dnsOverProxy!!, "proxied.service.test")
		assertEquals(listOf("198.51.100.42"), dnsInsp.ipv4Addresses)

		val tunOut = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
		var liveCfg = AppConfig(proxies = listOf(socksProfile))
		val router = TunL3Router(
			_configProvider = { liveCfg },
			_pushTraffic = {},
			_cm = null,
			_pm = null,
			_protectSocket = { true },
			_protectDatagram = { true },
			_transportProvider = { true to false },
			_onBlockedHit = {},
			_writeTunPacket = { pkt -> tunOut.offer(pkt) },
		)

		val clientIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val dstIp = byteArrayOf(127, 0, 0, 1)
		val reqBytes = "STUN_PING".toByteArray(Charsets.US_ASCII)
		val udpPkt = DnsWire.buildIpv4Udp(clientIp, dstIp, 55111, targetUdpPort, reqBytes)
		router.handleIpv4Packet(udpPkt, udpPkt.size)

		val echoedFrame = tunOut.poll(3, java.util.concurrent.TimeUnit.SECONDS)
		assertNotNull("Expected UDP reply relayed via SOCKS5 UDP ASSOCIATE", echoedFrame)
		val parsedEcho = DnsWire.parseIpv4Udp(echoedFrame!!, echoedFrame.size)
		assertNotNull(parsedEcho)
		assertEquals("RELAY_OK:STUN_PING", String(parsedEcho!!.payload, Charsets.US_ASCII))
		assertEquals(1, targetUdpHits.get())

		// Switch to HTTP CONNECT proxy with isBlockUdpFallback=true and verify UDP does NOT leak direct
		val httpProfile = ProxyProfile(
			id = "http_only",
			name = "HTTP Proxy",
			isEnabled = true,
			type = "HTTP",
			host = "127.0.0.1",
			port = socksTcpPort,
			isBlockUdpFallback = true,
			isAllApps = true,
		)
		liveCfg = AppConfig(proxies = listOf(httpProfile))
		val leakAttemptPkt = DnsWire.buildIpv4Udp(clientIp, dstIp, 55112, targetUdpPort, reqBytes)
		router.handleIpv4Packet(leakAttemptPkt, leakAttemptPkt.size)
		val leakedReply = tunOut.poll(250, java.util.concurrent.TimeUnit.MILLISECONDS)
		assertNull("Unproxied UDP must be blocked when HTTP proxy has leak guard enabled", leakedReply)
		assertEquals("Direct UDP server must not receive leaked datagram", 1, targetUdpHits.get())

		router.closeAll()
		runCatching { socksUdpRelay.close() }
		runCatching { targetUdpServer.close() }
		runCatching { socksTcpServer.close() }
		socksCtrlThread.join(1000)
		relayThread.join(1000)
		targetThread.join(1000)
	}

	@Test
	fun customDnsNoHiddenSecondaryLeakAndLightThemeBackupSections() {
		val cfg = AppConfig(
			dnsPresetKey = "custom",
			customDnsIp = "9.9.9.9",
			customSecondaryDnsIp = "",
			isWifiCustomOverride = true,
			wifiDnsIp = "192.168.1.1",
			wifiSecondaryDnsIp = "",
			isWifiUseDoh = true,
			wifiDohUrl = "https://dns.quad9.net/dns-query",
			themeMode = THEME_LIGHT,
		).sanitized()

		assertFalse(cfg.isPureOled)
		assertEquals(THEME_LIGHT, cfg.themeMode)
		assertEquals("9.9.9.9" to "", cfg.activeDnsServers(isOnWifi = false, isOnMobile = false))
		assertEquals("192.168.1.1" to "", cfg.activeDnsServers(isOnWifi = true, isOnMobile = false))
		assertEquals("https://dns.quad9.net/dns-query", cfg.activeDohEndpoint(isOnWifi = true, isOnMobile = false))

		val listsOnly = BackupSections(
			isGeneralConfig = false,
			isDnsAndNetworks = false,
			isAppsAndProxies = false,
			isCustomRules = true,
			isBlocklists = true,
		)
		val emptySections = BackupSections(false, false, false, false, false)
		assertTrue(listsOnly.hasAnySelected)
		assertFalse(emptySections.hasAnySelected)
	}
}
