package com.renwixx.trueadblocker.net

import android.app.Application
import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.AppDatabase
import com.renwixx.trueadblocker.engine.RuleEngine
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
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
class TunL3RouterExtraTest {
	private lateinit var ctx: Context
	private lateinit var db: AppDatabase

	@Before
	fun setUp() {
		ctx = ApplicationProvider.getApplicationContext()
		db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
			.allowMainThreadQueries()
			.build()
	}

	@After
	fun tearDown() {
		db.close()
	}

	@Test
	fun l3RouterBlocksMappedDomainOnTcpAndUdpViaRuleEngine() = runBlocking {
		val engine = RuleEngine(ctx, db)
		engine.importLocalListFile("l3_blk", "L3 Block", "||blocked-l3.example.test^\n")
		DnsWire.recordIpHost("203.0.113.99", "blocked-l3.example.test")

		val tunOut = LinkedBlockingQueue<ByteArray>()
		val blockedHits = AtomicInteger(0)
		val router = TunL3Router(
			_configProvider = { AppConfig() },
			_pushTraffic = {},
			_cm = null,
			_pm = null,
			_protectSocket = { true },
			_protectDatagram = { true },
			_transportProvider = { true to false },
			_onBlockedHit = { blockedHits.incrementAndGet() },
			_writeTunPacket = { pkt -> tunOut.offer(pkt) },
			_engine = engine,
		)

		val clientIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val blockedIp = byteArrayOf(203.toByte(), 0, 113, 99)

		// TCP SYN to blocked domain IP -> immediate RST+ACK
		val syn = TunL3Router.buildIpv4TcpPacket(clientIp, blockedIp, 52000, 443, 100L, 0L, TunL3Router.FLAG_SYN, ByteArray(0))
		router.handleIpv4Packet(syn, syn.size)
		val rst = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(rst)
		assertEquals(TunL3Router.FLAG_RST or TunL3Router.FLAG_ACK, rst!![33].toInt() and 0xFF)
		assertEquals(1, blockedHits.get())

		// UDP to blocked domain IP -> silently dropped + blocked hit incremented
		val udp = DnsWire.buildIpv4Udp(clientIp, blockedIp, 52001, 443, "QUIC".toByteArray())
		router.handleIpv4Packet(udp, udp.size)
		assertNull(tunOut.poll(150, TimeUnit.MILLISECONDS))
		assertEquals(2, blockedHits.get())

		router.closeAll()
	}

	@Test
	fun tcpFastRetransmitDuplicateSynAndInWindowRst() {
		val srv = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
		val srvPort = srv.localPort
		val srvThread = Thread {
			srv.use { s ->
				s.soTimeout = 3000
				s.accept().use { c ->
					c.getOutputStream().write("FAST_RETRANSMIT_DATA".toByteArray(Charsets.US_ASCII))
					c.getOutputStream().flush()
					Thread.sleep(600)
				}
			}
		}.apply { isDaemon = true; start() }

		val tunOut = LinkedBlockingQueue<ByteArray>()
		val router = TunL3Router(
			_configProvider = { AppConfig() },
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
		val loopback = byteArrayOf(127, 0, 0, 1)
		val cPort = 52100
		val initSeq = 5000L

		val syn = TunL3Router.buildIpv4TcpPacket(clientIp, loopback, cPort, srvPort, initSeq, 0L, TunL3Router.FLAG_SYN, ByteArray(0), windowSize = 4096)
		router.handleIpv4Packet(syn, syn.size)

		val synAck1 = tunOut.poll(2, TimeUnit.SECONDS)
		assertNotNull(synAck1)
		val serverDataSeq = (TunL3Router.u32(synAck1!!, 24) + 1L) and 0xFFFFFFFFL

		// Duplicate SYN with same ISN resends SYN-ACK
		router.handleIpv4Packet(syn, syn.size)
		val synAck2 = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(synAck2)
		assertEquals(TunL3Router.FLAG_SYN or TunL3Router.FLAG_ACK, synAck2!![33].toInt() and 0xFF)

		// Wait for server data segment
		var firstDataPkt: ByteArray? = null
		val deadline = System.currentTimeMillis() + 2000L
		while (firstDataPkt == null && System.currentTimeMillis() < deadline) {
			val p = tunOut.poll(100, TimeUnit.MILLISECONDS) ?: continue
			val ihl = (p[0].toInt() and 0x0F) * 4
			val dOff = ((p[ihl + 12].toInt() ushr 4) and 0x0F) * 4
			if (p.size > ihl + dOff)
				firstDataPkt = p
		}
		assertNotNull(firstDataPkt)

		// Send 3 duplicate ACKs acknowledging serverDataSeq (before data) -> triggers Fast Retransmit!
		val dupAck = TunL3Router.buildIpv4TcpPacket(clientIp, loopback, cPort, srvPort, initSeq + 1L, serverDataSeq, TunL3Router.FLAG_ACK, ByteArray(0), windowSize = 4096)
		// First ACK sets clientWindow to 4096; next 3 ACKs with identical window trigger dupAckCount == 3
		repeat(4) { router.handleIpv4Packet(dupAck, dupAck.size) }

		var retransmitted = false
		val rtxDeadline = System.currentTimeMillis() + 500L
		while (!retransmitted && System.currentTimeMillis() < rtxDeadline) {
			val p = tunOut.poll(100, TimeUnit.MILLISECONDS) ?: continue
			val ihl = (p[0].toInt() and 0x0F) * 4
			val dOff = ((p[ihl + 12].toInt() ushr 4) and 0x0F) * 4
			if (p.size > ihl + dOff && TunL3Router.u32(p, ihl + 4) == serverDataSeq)
				retransmitted = true
		}
		assertTrue("Expected Fast Retransmit segment after 3 duplicate ACKs", retransmitted)

		// Send in-window RST to close session
		val rst = TunL3Router.buildIpv4TcpPacket(clientIp, loopback, cPort, srvPort, initSeq + 1L, serverDataSeq, TunL3Router.FLAG_RST, ByteArray(0))
		router.handleIpv4Packet(rst, rst.size)

		// Subsequent ACK on closed flow must get RST back
		tunOut.clear()
		router.handleIpv4Packet(dupAck, dupAck.size)
		val afterCloseRst = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(afterCloseRst)
		assertTrue((afterCloseRst!![33].toInt() and TunL3Router.FLAG_RST) != 0)

		router.closeAll()
		srvThread.join(1500)
	}

	@Test
	fun ipv6SinkholeRepliesImmediatelyWithTcpRstAndIcmpv6Unreachable() {
		val tunOut = LinkedBlockingQueue<ByteArray>()
		val router = TunL3Router(
			_configProvider = { AppConfig() },
			_pushTraffic = {},
			_cm = null,
			_pm = null,
			_protectSocket = { true },
			_protectDatagram = { true },
			_transportProvider = { true to false },
			_onBlockedHit = {},
			_writeTunPacket = { pkt -> tunOut.offer(pkt) },
		)

		val srcV6 = InetAddress.getByName("fd00:1:fd00::2").address
		val tgV6 = InetAddress.getByName("2001:67c:4e8:f002::a").address

		val synV6 = ByteArray(60).apply {
			this[0] = 0x60
			this[5] = 20
			this[6] = 6
			this[7] = 64
			System.arraycopy(srcV6, 0, this, 8, 16)
			System.arraycopy(tgV6, 0, this, 24, 16)
			this[40] = 0xD4.toByte()
			this[41] = 0x31
			this[42] = 0x01
			this[43] = 0xBB.toByte()
			this[47] = 100
			this[52] = 0x50
			this[53] = TunL3Router.FLAG_SYN.toByte()
		}
		router.handleIpv6Packet(synV6, synV6.size)
		val rstV6 = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull("Expected immediate IPv6 TCP RST", rstV6)
		assertEquals(6, rstV6!![6].toInt() and 0xFF)
		assertTrue((rstV6[53].toInt() and TunL3Router.FLAG_RST) != 0)
		assertEquals(0, TunL3Router.ipv6UpperChecksum(tgV6, srcV6, 6, rstV6, 40, 20))

		val udpV6 = ByteArray(56).apply {
			this[0] = 0x60
			this[5] = 16
			this[6] = 17
			this[7] = 64
			System.arraycopy(srcV6, 0, this, 8, 16)
			System.arraycopy(tgV6, 0, this, 24, 16)
		}
		router.handleIpv6Packet(udpV6, udpV6.size)
		val unreach = tunOut.poll(500, TimeUnit.MILLISECONDS)
		router.closeAll()

		assertNotNull("Expected immediate ICMPv6 Destination Unreachable", unreach)
		assertEquals(58, unreach!![6].toInt() and 0xFF)
		assertEquals(1, unreach[40].toInt() and 0xFF)
		assertEquals(1, unreach[41].toInt() and 0xFF)
		assertEquals(0, TunL3Router.ipv6UpperChecksum(tgV6, srcV6, 58, unreach, 40, unreach.size - 40))
	}
}
