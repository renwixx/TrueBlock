package com.renwixx.trueadblocker.net

import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.ProxyProfile
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunL3RouterTest {
	@Test
	fun seqDiffHandles32BitWraparoundAndHelpersParseOptions() {
		assertEquals(10, TunL3Router.seqDiff(110L, 100L))
		assertEquals(-10, TunL3Router.seqDiff(100L, 110L))
		assertEquals(5, TunL3Router.seqDiff(2L, 0xFFFFFFFDL))
		assertEquals(-5, TunL3Router.seqDiff(0xFFFFFFFDL, 2L))

		val srcIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val dstIp = byteArrayOf(157.toByte(), 240.toByte(), 1, 52)
		val synNoWscale = TunL3Router.buildIpv4TcpPacket(srcIp, dstIp, 50000, 443, 1L, 0L, TunL3Router.FLAG_SYN, ByteArray(0), winScale = -1)
		assertEquals(44, synNoWscale.size)
		assertEquals(-1, TunL3Router.parseSynWindowScale(synNoWscale, 20, 24))

		val synWithWscale = TunL3Router.buildIpv4TcpPacket(srcIp, dstIp, 50000, 443, 1L, 0L, TunL3Router.FLAG_SYN, ByteArray(0), winScale = 20)
		assertEquals(48, synWithWscale.size)
		assertEquals(14, TunL3Router.parseSynWindowScale(synWithWscale, 20, 28))
		assertEquals(0, DnsWire.ipv4Checksum(synWithWscale, 0, 20))
		assertEquals(0, TunL3Router.tcpChecksum(srcIp, dstIp, synWithWscale, 20, 28))

		// Odd-length payload checksum verification
		val oddPkt = TunL3Router.buildIpv4TcpPacket(srcIp, dstIp, 50000, 443, 10L, 20L, TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK, byteArrayOf(1, 2, 3))
		assertEquals(0, DnsWire.ipv4Checksum(oddPkt, 0, 20))
		assertEquals(0, TunL3Router.tcpChecksum(srcIp, dstIp, oddPkt, 20, oddPkt.size - 20))
	}

	@Test
	fun largeUdpFragmentationProducesValid8ByteAlignedFrames() {
		val srcIp = byteArrayOf(203.toByte(), 0, 113, 10)
		val dstIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val smallFrames = TunL3Router.buildIpv4UdpFrames(srcIp, dstIp, 1234, 5678, ByteArray(100), 1400, AtomicInteger(1))
		assertEquals(1, smallFrames.size)

		val largePayload = ByteArray(3200) { i -> (i and 0xFF).toByte() }
		val frames = TunL3Router.buildIpv4UdpFrames(srcIp, dstIp, 21116, 54321, largePayload, 1400, AtomicInteger(100))
		assertEquals(3, frames.size)

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
		assertArrayEquals(largePayload, reconstructed.copyOfRange(8, reconstructed.size))
	}

	@Test
	fun unknownFlowForbiddenEndpointsAndDnsDispatchBehaveSafely() {
		val tunOut = LinkedBlockingQueue<ByteArray>()
		val dnsDispatched = LinkedBlockingQueue<IpUdpFrame>()
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
			_localProxyPortProvider = { 18888 },
			_onDnsFrame = { frame -> dnsDispatched.offer(frame) },
		)

		val clientIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val remoteIp = byteArrayOf(149.toByte(), 154.toByte(), 167.toByte(), 51)

		// Unknown flow with ACK -> RST with seq = ackNum
		val staleAck = TunL3Router.buildIpv4TcpPacket(
			clientIp,
			remoteIp,
			54321,
			443,
			900_001L,
			777_123L,
			TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK,
			"PING".toByteArray(),
		)
		router.handleIpv4Packet(staleAck, staleAck.size)
		val rst1 = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(rst1)
		assertEquals(TunL3Router.FLAG_RST, rst1!![33].toInt() and 0xFF)
		assertEquals(777_123L, TunL3Router.u32(rst1, 24))

		// Unknown flow without ACK -> RST+ACK with ack = seq + payloadLen
		val staleNoAck = TunL3Router.buildIpv4TcpPacket(clientIp, remoteIp, 54322, 443, 500L, 0L, TunL3Router.FLAG_PSH, "ABCD".toByteArray())
		router.handleIpv4Packet(staleNoAck, staleNoAck.size)
		val rst2 = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(rst2)
		assertEquals(TunL3Router.FLAG_RST or TunL3Router.FLAG_ACK, rst2!![33].toInt() and 0xFF)
		assertEquals(504L, TunL3Router.u32(rst2, 28))

		// Forbidden endpoint (local MitmProxy port on 127.0.0.1) -> immediate RST+ACK
		val loopSyn = TunL3Router.buildIpv4TcpPacket(clientIp, byteArrayOf(127, 0, 0, 1), 54323, 18888, 100L, 0L, TunL3Router.FLAG_SYN, ByteArray(0))
		router.handleIpv4Packet(loopSyn, loopSyn.size)
		val loopRst = tunOut.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(loopRst)
		assertEquals(TunL3Router.FLAG_RST or TunL3Router.FLAG_ACK, loopRst!![33].toInt() and 0xFF)

		// UDP port 53 dispatched to _onDnsFrame
		val dnsUdp = DnsWire.buildIpv4Udp(clientIp, byteArrayOf(10, 111, 222.toByte(), 1), 53000, 53, DnsWire.buildDnsQueryWire("a.b", DnsWire.TYPE_A))
		router.handleIpv4Packet(dnsUdp, dnsUdp.size)
		val caughtDns = dnsDispatched.poll(500, TimeUnit.MILLISECONDS)
		assertNotNull(caughtDns)
		assertEquals(53, caughtDns!!.dstPort)

		router.closeAll()
	}

	@Test
	fun localDnsOverTcpSessionHandlesFramedQueryAndReply() {
		val tunOut = LinkedBlockingQueue<ByteArray>()
		val router = TunL3Router(
			_configProvider = { AppConfig(vpnDnsIp = "10.111.222.1") },
			_pushTraffic = {},
			_cm = null,
			_pm = null,
			_protectSocket = { true },
			_protectDatagram = { true },
			_transportProvider = { true to false },
			_onBlockedHit = {},
			_writeTunPacket = { pkt -> tunOut.offer(pkt) },
			_localDnsTcpHandler = { rawQ, _ ->
				val parsed = DnsWire.parseDnsQuery(rawQ)!!
				DnsWire.buildSyntheticBlockedDns(rawQ, parsed)
			},
		)

		val clientIp = byteArrayOf(10, 111, 222.toByte(), 2)
		val dnsIp = byteArrayOf(10, 111, 222.toByte(), 1)
		val cPort = 51000
		var cSeq = 1000L

		val syn = TunL3Router.buildIpv4TcpPacket(clientIp, dnsIp, cPort, 53, cSeq, 0L, TunL3Router.FLAG_SYN, ByteArray(0))
		router.handleIpv4Packet(syn, syn.size)
		cSeq++

		val synAck = tunOut.poll(2, TimeUnit.SECONDS)
		assertNotNull(synAck)
		val sSeq = (TunL3Router.u32(synAck!!, 24) + 1L) and 0xFFFFFFFFL

		val rawQuery = DnsWire.buildDnsQueryWire("blocked.test", DnsWire.TYPE_A)
		val framedQ = ByteArray(2 + rawQuery.size).also {
			it[0] = (rawQuery.size ushr 8).toByte()
			it[1] = rawQuery.size.toByte()
			System.arraycopy(rawQuery, 0, it, 2, rawQuery.size)
		}
		val dataPkt = TunL3Router.buildIpv4TcpPacket(clientIp, dnsIp, cPort, 53, cSeq, sSeq, TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK, framedQ)
		router.handleIpv4Packet(dataPkt, dataPkt.size)
		cSeq += framedQ.size

		var dnsReplyPayload: ByteArray? = null
		val deadline = System.currentTimeMillis() + 2500L
		while (dnsReplyPayload == null && System.currentTimeMillis() < deadline) {
			val p = tunOut.poll(200, TimeUnit.MILLISECONDS) ?: continue
			val ihl = (p[0].toInt() and 0x0F) * 4
			val dataOff = ((p[ihl + 12].toInt() ushr 4) and 0x0F) * 4
			if (p.size > ihl + dataOff)
				dnsReplyPayload = p.copyOfRange(ihl + dataOff, p.size)
		}

		assertNotNull("Expected DNS-over-TCP reply segment", dnsReplyPayload)
		val replyLen = ((dnsReplyPayload!![0].toInt() and 0xFF) shl 8) or (dnsReplyPayload[1].toInt() and 0xFF)
		assertEquals(dnsReplyPayload.size - 2, replyLen)
		val dnsWire = dnsReplyPayload.copyOfRange(2, dnsReplyPayload.size)
		assertEquals(rawQuery[0], dnsWire[0])
		assertEquals(rawQuery[1], dnsWire[1])

		val fin = TunL3Router.buildIpv4TcpPacket(clientIp, dnsIp, cPort, 53, cSeq, sSeq + dnsReplyPayload.size, TunL3Router.FLAG_FIN or TunL3Router.FLAG_ACK, ByteArray(0))
		router.handleIpv4Packet(fin, fin.size)
		router.closeAll()
	}

	@Test
	fun endToEndL3TcpOutOfOrderReassemblyLargeTransferAndReverseFragmentedUdp() {
		val serverPayload = ByteArray(120_000) { i -> ((i * 31 + 7) and 0xFF).toByte() }
		val expectedReq = ByteArray(3072) { i -> ((i * 13 + 3) and 0xFF).toByte() }
		val receivedByServer = ByteArrayOutputStream()

		val tcpServer = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
		val srvPort = tcpServer.localPort
		val serverThread = Thread {
			tcpServer.use { srv ->
				srv.accept().use { s ->
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

		val tunOutFrames = LinkedBlockingQueue<ByteArray>()
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

		val synPkt = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq, 0L, TunL3Router.FLAG_SYN, ByteArray(0), 1360, 7, 512)
		router.handleIpv4Packet(synPkt, synPkt.size)
		clientSeq++

		val synAck = tunOutFrames.poll(3, TimeUnit.SECONDS)
		assertNotNull(synAck)
		var expectedServerSeq = (TunL3Router.u32(synAck!!, 24) + 1L) and 0xFFFFFFFFL

		val hsAck = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq, expectedServerSeq, TunL3Router.FLAG_ACK, ByteArray(0), windowSize = 512)
		router.handleIpv4Packet(hsAck, hsAck.size)

		// Send 3 chunks OUT OF ORDER (chunk 2, chunk 3, then chunk 1) + duplicate chunk 1
		val c1 = expectedReq.copyOfRange(0, 1024)
		val c2 = expectedReq.copyOfRange(1024, 2048)
		val c3 = expectedReq.copyOfRange(2048, 3072)
		val p2 = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq + 1024, expectedServerSeq, TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK, c2, windowSize = 512)
		val p3 = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq + 2048, expectedServerSeq, TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK, c3, windowSize = 512)
		val p1 = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq, expectedServerSeq, TunL3Router.FLAG_PSH or TunL3Router.FLAG_ACK, c1, windowSize = 512)
		router.handleIpv4Packet(p2, p2.size)
		router.handleIpv4Packet(p3, p3.size)
		router.handleIpv4Packet(p1, p1.size)
		router.handleIpv4Packet(p1, p1.size) // duplicate must be ignored
		clientSeq += expectedReq.size

		val downloaded = ByteArrayOutputStream()
		val deadline = System.currentTimeMillis() + 5000L
		while (downloaded.size() < serverPayload.size && System.currentTimeMillis() < deadline) {
			val pkt = tunOutFrames.poll(200, TimeUnit.MILLISECONDS) ?: continue
			if ((pkt[9].toInt() and 0xFF) != 6)
				continue
			val ihl = (pkt[0].toInt() and 0x0F) * 4
			val dataOff = ((pkt[ihl + 12].toInt() ushr 4) and 0x0F) * 4
			val pLen = pkt.size - ihl - dataOff
			if (pLen > 0) {
				val seq = TunL3Router.u32(pkt, ihl + 4)
				if (seq == expectedServerSeq) {
					downloaded.write(pkt, ihl + dataOff, pLen)
					expectedServerSeq = (expectedServerSeq + pLen.toLong()) and 0xFFFFFFFFL
					val ack = TunL3Router.buildIpv4TcpPacket(clientIp, loopbackIp, clientPort, srvPort, clientSeq, expectedServerSeq, TunL3Router.FLAG_ACK, ByteArray(0), windowSize = 512)
					router.handleIpv4Packet(ack, ack.size)
				}
			}
		}

		// Reverse-ordered IPv4 UDP fragments reassembly + echo
		val udpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
		val udpPort = udpServer.localPort
		val udpThread = Thread {
			udpServer.use { ds ->
				ds.soTimeout = 3000
				val buf = ByteArray(65535)
				val dp = DatagramPacket(buf, buf.size)
				ds.receive(dp)
				ds.send(DatagramPacket(dp.data, dp.length, dp.address, dp.port))
			}
		}.apply { isDaemon = true; start() }

		tunOutFrames.clear()
		val udpBigMsg = ByteArray(3000) { i -> ((i * 17 + 5) and 0xFF).toByte() }
		val outboundFrags = TunL3Router.buildIpv4UdpFrames(clientIp, loopbackIp, 54321, udpPort, udpBigMsg, 1400, AtomicInteger(777))
		for (frag in outboundFrags.reversed())
			router.handleIpv4Packet(frag, frag.size)

		val udpReplyReconstructed = ByteArray(8 + udpBigMsg.size)
		var gotFinalUdpFrag = false
		val udpDeadline = System.currentTimeMillis() + 3000L
		while (!gotFinalUdpFrag && System.currentTimeMillis() < udpDeadline) {
			val f = tunOutFrames.poll(200, TimeUnit.MILLISECONDS) ?: continue
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

		assertArrayEquals(expectedReq, receivedByServer.toByteArray())
		assertArrayEquals(serverPayload, downloaded.toByteArray())
		assertTrue(gotFinalUdpFrag)
		assertArrayEquals(udpBigMsg, udpReplyReconstructed.copyOfRange(8, udpReplyReconstructed.size))
	}

	@Test
	fun endToEndSocks5UdpAssociateRelayUdpLeakGuardAndProxyDnsOverTcp() {
		val targetUdpHits = AtomicInteger(0)
		val targetUdpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
		val targetUdpPort = targetUdpServer.localPort
		val targetThread = Thread {
			targetUdpServer.use { ds ->
				ds.soTimeout = 3000
				val buf = ByteArray(4096)
				while (!Thread.currentThread().isInterrupted) {
					val dp = DatagramPacket(buf, buf.size)
					try {
						ds.receive(dp)
					} catch (_: Throwable) {
						break
					}
					targetUdpHits.incrementAndGet()
					val echoed = "RELAY_OK:".toByteArray(Charsets.US_ASCII) + dp.data.copyOfRange(0, dp.length)
					ds.send(DatagramPacket(echoed, echoed.size, dp.address, dp.port))
				}
			}
		}.apply { isDaemon = true; start() }

		val socksUdpRelay = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
		val socksUdpPort = socksUdpRelay.localPort
		val relayThread = Thread {
			socksUdpRelay.use { relay ->
				relay.soTimeout = 3000
				val buf = ByteArray(8192)
				var clientAddr: InetAddress? = null
				var clientPort = 0
				while (!Thread.currentThread().isInterrupted) {
					val dp = DatagramPacket(buf, buf.size)
					try {
						relay.receive(dp)
					} catch (_: Throwable) {
						break
					}
					if (dp.port != targetUdpPort) {
						clientAddr = dp.address
						clientPort = dp.port
						val unwrapped = UpstreamProxy.unwrapSocks5UdpPacket(buf, dp.length) ?: continue
						val dst = InetAddress.getByAddress(unwrapped.srcIp)
						relay.send(DatagramPacket(unwrapped.payload, unwrapped.payload.size, dst, unwrapped.srcPort))
					} else if (clientAddr != null && clientPort > 0) {
						val wrapped = UpstreamProxy.wrapSocks5UdpPayload(byteArrayOf(127, 0, 0, 1), targetUdpPort, buf.copyOfRange(0, dp.length))
						relay.send(DatagramPacket(wrapped, wrapped.size, clientAddr, clientPort))
					}
				}
			}
		}.apply { isDaemon = true; start() }

		val socksTcpServer = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
		val socksTcpPort = socksTcpServer.localPort
		val socksCtrlThread = Thread {
			socksTcpServer.use { srv ->
				srv.soTimeout = 3000
				repeat(2) {
					val client = runCatching { srv.accept() }.getOrNull() ?: return@repeat
					Thread {
						client.use { c ->
							val inp = DataInputStream(c.getInputStream())
							val out = DataOutputStream(c.getOutputStream())
							assertEquals(0x05, inp.readUnsignedByte())
							val nMethods = inp.readUnsignedByte()
							inp.readFully(ByteArray(nMethods))
							out.write(byteArrayOf(0x05, 0x00))
							out.flush()

							val cmdHead = ByteArray(4)
							inp.readFully(cmdHead)
							val cmd = cmdHead[1].toInt() and 0xFF
							when (cmdHead[3].toInt() and 0xFF) {
								0x01 -> inp.readFully(ByteArray(6))
								0x03 -> {
									val dLen = inp.readUnsignedByte()
									inp.readFully(ByteArray(dLen + 2))
								}
								0x04 -> inp.readFully(ByteArray(18))
							}

							if (cmd == 0x03) {
								out.write(
									byteArrayOf(
										0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0,
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
		val dnsOverProxy = UpstreamProxy.queryDnsOverProxyTcp(socksProfile, dnsQuery, "9.9.9.9", 2500, { true })
		assertNotNull(dnsOverProxy)
		assertEquals(listOf("198.51.100.42"), DnsWire.inspectDnsAnswer(dnsOverProxy!!, "proxied.service.test").ipv4Addresses)

		val tunOut = LinkedBlockingQueue<ByteArray>()
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

		val echoedFrame = tunOut.poll(3, TimeUnit.SECONDS)
		assertNotNull(echoedFrame)
		val parsedEcho = DnsWire.parseIpv4Udp(echoedFrame!!, echoedFrame.size)
		assertEquals("RELAY_OK:STUN_PING", String(parsedEcho!!.payload, Charsets.US_ASCII))
		assertEquals(1, targetUdpHits.get())

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
		assertNull(tunOut.poll(250, TimeUnit.MILLISECONDS))
		assertEquals(1, targetUdpHits.get())

		router.closeAll()
		runCatching { socksUdpRelay.close() }
		runCatching { targetUdpServer.close() }
		runCatching { socksTcpServer.close() }
		socksCtrlThread.join(1000)
		relayThread.join(1000)
		targetThread.join(1000)
	}
}
