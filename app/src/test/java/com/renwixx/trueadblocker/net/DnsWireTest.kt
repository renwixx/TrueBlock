package com.renwixx.trueadblocker.net

import com.renwixx.trueadblocker.data.BLOCKED_DNS_NODATA
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NXDOMAIN
import com.renwixx.trueadblocker.data.BLOCKED_DNS_ZERO_IP
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsWireTest {
	@Test
	fun ipHostMappingRespectsPerAppOverrideAndIgnoresSystemDns() {
		DnsWire.recordIpHost("198.51.100.10", "global.example.com")
		assertEquals("global.example.com", DnsWire.lookupHostByIp("198.51.100.10"))
		assertEquals("global.example.com", DnsWire.lookupHostByIp("198.51.100.10", "com.other.app"))

		DnsWire.recordIpHost("198.51.100.10", "app.example.com", "com.target.app")
		assertEquals("app.example.com", DnsWire.lookupHostByIp("198.51.100.10", "com.target.app"))

		DnsWire.recordIpHost("198.51.100.11", "sys.example.com", "System DNS")
		assertEquals("sys.example.com", DnsWire.lookupHostByIp("198.51.100.11"))
		DnsWire.recordIpHost("198.51.100.11", "newer.example.com")
		assertEquals("newer.example.com", DnsWire.lookupHostByIp("198.51.100.11", "System DNS"))

		DnsWire.recordIpHost("", "ignored.com")
		DnsWire.recordIpHost("198.51.100.12", "")
		assertNull(DnsWire.lookupHostByIp("198.51.100.12"))
	}

	@Test
	fun parseIpv4UdpValidatesVersionIhlFragmentationProtocolAndOptions() {
		val srcIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val dstIp = byteArrayOf(10, 111, 222.toByte(), 1)
		val payload = "HELLO_DNS".toByteArray(Charsets.US_ASCII)

		val valid = DnsWire.buildIpv4Udp(srcIp, dstIp, 54321, 53, payload)
		assertEquals(0, DnsWire.ipv4Checksum(valid, 0, 20))
		val parsed = DnsWire.parseIpv4Udp(valid, valid.size)
		assertNotNull(parsed)
		assertArrayEquals(srcIp, parsed!!.srcIp)
		assertArrayEquals(dstIp, parsed.dstIp)
		assertEquals(54321, parsed.srcPort)
		assertEquals(53, parsed.dstPort)
		assertArrayEquals(payload, parsed.payload)

		// Too short
		assertNull(DnsWire.parseIpv4Udp(valid, 20))

		// IPv6 version
		val v6 = valid.copyOf().also { it[0] = 0x60 }
		assertNull(DnsWire.parseIpv4Udp(v6, v6.size))

		// Fragmented packet (MF bit set)
		val mf = valid.copyOf().also { it[6] = 0x20 }
		assertNull(DnsWire.parseIpv4Udp(mf, mf.size))

		// Fragmented packet (non-zero offset)
		val fragOff = valid.copyOf().also { it[7] = 0x08 }
		assertNull(DnsWire.parseIpv4Udp(fragOff, fragOff.size))

		// Non-UDP (TCP = 6)
		val tcp = valid.copyOf().also { it[9] = 6 }
		assertNull(DnsWire.parseIpv4Udp(tcp, tcp.size))

		// Empty UDP payload (udpLen == 8)
		val emptyUdp = valid.copyOf().also {
			it[24] = 0
			it[25] = 8
		}
		assertNull(DnsWire.parseIpv4Udp(emptyUdp, emptyUdp.size))

		// IPv4 header with 4-byte option (IHL = 6 -> 24 bytes)
		val withOpts = ByteArray(24 + 8 + payload.size)
		withOpts[0] = 0x46
		withOpts[9] = 17
		System.arraycopy(srcIp, 0, withOpts, 12, 4)
		System.arraycopy(dstIp, 0, withOpts, 16, 4)
		withOpts[24] = 0x10
		withOpts[25] = 0x00
		withOpts[26] = 0x00
		withOpts[27] = 53
		val uLen = 8 + payload.size
		withOpts[28] = (uLen ushr 8).toByte()
		withOpts[29] = uLen.toByte()
		System.arraycopy(payload, 0, withOpts, 32, payload.size)
		val parsedOpts = DnsWire.parseIpv4Udp(withOpts, withOpts.size)
		assertNotNull(parsedOpts)
		assertArrayEquals(payload, parsedOpts!!.payload)
	}

	@Test
	fun ipv4ChecksumHandlesOddLengthBuffer() {
		val buf = byteArrayOf(0x45, 0x00, 0x01)
		val csum = DnsWire.ipv4Checksum(buf, 0, buf.size)
		assertTrue(csum in 0..0xFFFF)
	}

	@Test
	fun parseDnsQueryHandlesCompressionPointersLoopsAndInvalidPackets() {
		assertNull(DnsWire.parseDnsQuery(ByteArray(11)))

		// QR = 1 (response, not query)
		val respHeader = ByteArray(20).also { it[2] = 0x80.toByte(); it[5] = 1 }
		assertNull(DnsWire.parseDnsQuery(respHeader))

		// QDCOUNT = 0
		val noQ = ByteArray(20)
		assertNull(DnsWire.parseDnsQuery(noQ))

		// Self-referencing pointer loop at offset 12 -> 0xC00C
		val loopPkt = ByteArray(20).also {
			it[5] = 1
			it[12] = 0xC0.toByte()
			it[13] = 0x0C
		}
		assertNull(DnsWire.parseDnsQuery(loopPkt))

		// Truncated label
		val truncLabel = ByteArray(16).also {
			it[5] = 1
			it[12] = 10
		}
		assertNull(DnsWire.parseDnsQuery(truncLabel))

		// Valid IDN query built with buildDnsQueryWire
		val idnWire = DnsWire.buildDnsQueryWire("Пример.РФ", DnsWire.TYPE_AAAA)
		val parsedIdn = DnsWire.parseDnsQuery(idnWire)
		assertNotNull(parsedIdn)
		assertEquals("xn--e1afmkfd.xn--p1ai", parsedIdn!!.qname)
		assertEquals(DnsWire.TYPE_AAAA, parsedIdn.qtype)
		assertEquals(1, parsedIdn.qclass)
	}

	@Test
	fun buildBlockedDnsReplyCoversZeroIpNxDomainAndNoDataForAllRecordTypes() {
		val queryA = DnsWire.buildDnsQueryWire("ads.example.com", DnsWire.TYPE_A).also {
			it[0] = 0x12
			it[1] = 0x34
			it[2] = 0x01 // RD=1
			it[3] = 0x10 // CD=1
		}
		val parsedA = DnsWire.parseDnsQuery(queryA)!!

		val zeroA = DnsWire.buildBlockedDnsReply(queryA, parsedA, BLOCKED_DNS_ZERO_IP)
		assertEquals(0x12.toByte(), zeroA[0])
		assertEquals(0x34.toByte(), zeroA[1])
		assertEquals(0x81.toByte(), zeroA[2]) // QR=1, RD=1
		assertEquals(0x90.toByte(), zeroA[3]) // RA=1, CD=1, RCODE=0
		assertEquals(1, ((zeroA[6].toInt() and 0xFF) shl 8) or (zeroA[7].toInt() and 0xFF))
		val inspZeroA = DnsWire.inspectDnsAnswer(zeroA, "ads.example.com", isRecordIpMapping = true)
		assertEquals(listOf("0.0.0.0"), inspZeroA.ipv4Addresses)
		assertNull("0.0.0.0 must never be recorded into IP->host map", DnsWire.lookupHostByIp("0.0.0.0"))

		val queryAaaa = DnsWire.buildDnsQueryWire("ads.example.com", DnsWire.TYPE_AAAA)
		val parsedAaaa = DnsWire.parseDnsQuery(queryAaaa)!!
		val zeroAaaa = DnsWire.buildBlockedDnsReply(queryAaaa, parsedAaaa, BLOCKED_DNS_ZERO_IP)
		assertEquals(1, ((zeroAaaa[6].toInt() and 0xFF) shl 8) or (zeroAaaa[7].toInt() and 0xFF))
		assertArrayEquals(ByteArray(16), zeroAaaa.copyOfRange(zeroAaaa.size - 16, zeroAaaa.size))

		val queryHttps = DnsWire.buildDnsQueryWire("ads.example.com", DnsWire.TYPE_HTTPS)
		val parsedHttps = DnsWire.parseDnsQuery(queryHttps)!!
		val zeroHttps = DnsWire.buildBlockedDnsReply(queryHttps, parsedHttps, BLOCKED_DNS_ZERO_IP)
		assertEquals(0, ((zeroHttps[6].toInt() and 0xFF) shl 8) or (zeroHttps[7].toInt() and 0xFF))

		val nx = DnsWire.buildBlockedDnsReply(queryA, parsedA, BLOCKED_DNS_NXDOMAIN)
		assertEquals(3, nx[3].toInt() and 0x0F)
		assertEquals(0, ((nx[6].toInt() and 0xFF) shl 8) or (nx[7].toInt() and 0xFF))

		val nodata = DnsWire.buildBlockedDnsReply(queryA, parsedA, BLOCKED_DNS_NODATA)
		assertEquals(0, nodata[3].toInt() and 0x0F)
		assertEquals(0, ((nodata[6].toInt() and 0xFF) shl 8) or (nodata[7].toInt() and 0xFF))
	}

	@Test
	fun inspectDnsAnswerExtractsCnamesIpsMinTtlAndHandlesMalformedInput() {
		assertEquals(DnsAnswerInspection(emptyList(), emptyList(), 0), DnsWire.inspectDnsAnswer(ByteArray(5)))

		val resp = ByteArrayOutputStream().apply {
			write(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0x81.toByte(), 0x80.toByte()))
			write(byteArrayOf(0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00))
			for (lbl in listOf("metrics", "firstparty", "com")) {
				write(lbl.length)
				write(lbl.toByteArray())
			}
			write(0)
			write(byteArrayOf(0x00, 0x01, 0x00, 0x01))

			// Answer 1: CNAME with TTL 120
			write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78))
			val cname1 = ByteArrayOutputStream().apply {
				for (lbl in listOf("tracker", "3rdparty", "io")) {
					write(lbl.length)
					write(lbl.toByteArray())
				}
				write(0)
			}.toByteArray()
			write(0)
			write(cname1.size)
			write(cname1)

			// Answer 2: duplicate CNAME with TTL 45 (should deduplicate but still update minTtl)
			write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2D))
			write(0)
			write(cname1.size)
			write(cname1)

			// Answer 3: A record 198.51.100.55 with TTL 300
			write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04))
			write(byteArrayOf(198.toByte(), 51, 100, 55))
		}.toByteArray()

		val insp = DnsWire.inspectDnsAnswer(resp, queryHost = "metrics.firstparty.com", maxCnames = 8, appPkg = "com.demo")
		assertEquals(listOf("tracker.3rdparty.io"), insp.cnameChain)
		assertEquals(listOf("198.51.100.55"), insp.ipv4Addresses)
		assertEquals(45, insp.minTtlSec)
		assertEquals("metrics.firstparty.com", DnsWire.lookupHostByIp("198.51.100.55", "com.demo"))
	}

	@Test
	fun createProtectedHttpClientResolvesAllBootstrapDohHostsAndIpLiterals() {
		val client = DnsWire.createProtectedHttpClient(
			protectSocket = { true },
			protectDatagram = { true },
		)
		assertTrue(client.dns.lookup("cloudflare-dns.com").map { it.hostAddress }.contains("1.1.1.1"))
		assertTrue(client.dns.lookup("dns.google").map { it.hostAddress }.contains("8.8.8.8"))
		assertTrue(client.dns.lookup("dns.quad9.net").map { it.hostAddress }.contains("9.9.9.9"))
		assertTrue(client.dns.lookup("dns.mullvad.net").map { it.hostAddress }.contains("194.242.2.2"))
		assertEquals(listOf("127.0.0.1"), client.dns.lookup("127.0.0.1").map { it.hostAddress })
		assertFalse(client.dns.lookup("unfiltered.adguard-dns.com").isEmpty())
	}
}
