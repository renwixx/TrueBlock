package com.renwixx.trueadblocker.net

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.system.OsConstants
import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.data.TrafficSample
import com.renwixx.trueadblocker.engine.RuleEngine
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.LinkedHashMap
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.abs

class TunL3Router(
	private val _configProvider: () -> AppConfig,
	private val _pushTraffic: (TrafficSample) -> Unit,
	private val _cm: ConnectivityManager?,
	private val _pm: PackageManager?,
	private val _protectSocket: (Socket) -> Boolean,
	private val _protectDatagram: (DatagramSocket) -> Boolean,
	private val _transportProvider: () -> Pair<Boolean, Boolean>,
	private val _onBlockedHit: () -> Unit,
	private val _writeTunPacket: (ByteArray) -> Unit,
	tunMtu: Int = 1500,
	private val _engine: RuleEngine? = null,
	private val _isCaReady: () -> Boolean = { false },
	private val _localProxyPortProvider: () -> Int = { 0 },
	private val _resolveHostIp: ((String) -> InetAddress?)? = null,
	private val _onDnsFrame: ((IpUdpFrame) -> Unit)? = null,
	private val _localDnsTcpHandler: ((ByteArray, String) -> ByteArray?)? = null,
) {
	@Volatile
	private var _isRunning = true

	private val _tunMtu = tunMtu.coerceIn(1280, 9000)
	private val _tcpMss = (_tunMtu - 40).coerceIn(536, DEFAULT_TCP_MSS)
	private val _pool: ExecutorService = ThreadPoolExecutor(
		8,
		2048,
		60L,
		TimeUnit.SECONDS,
		SynchronousQueue(),
	)
	private val _tcpSessions = ConcurrentHashMap<String, TcpFlowSession>(256)
	private val _udpSessions = ConcurrentHashMap<String, UdpNatSession>(128)
	private val _uidPkgCache = boundedMap<String, CachedFlowOwner>(1024)
	private val _blockLogDedup = boundedMap<String, Long>(512)
	private val _proxyUdpUnsupportedUntil = boundedMap<String, Long>(128)
	private val _fragLock = Any()
	private val _fragBuckets = LinkedHashMap<String, Ipv4FragBucket>(32, 0.75f, true)
	private val _ipIdSeq = AtomicInteger(1)
	private val _pktCounter = AtomicInteger(0)

	fun closeAll() {
		_isRunning = false
		for (s in _tcpSessions.values)
			s.closeQuietly()
		_tcpSessions.clear()

		for (u in _udpSessions.values)
			u.closeQuietly()
		_udpSessions.clear()

		synchronized(_fragLock) {
			_fragBuckets.clear()
		}
		_pool.shutdownNow()
	}

	fun handleIpv4Packet(pkt: ByteArray, length: Int) {
		if (!_isRunning || length < 20)
			return

		val ver = (pkt[0].toInt() ushr 4) and 0x0F
		if (ver != 4)
			return

		val ihl = (pkt[0].toInt() and 0x0F) * 4
		val totalLen = u16(pkt, 2)
		val pktEnd = minOf(length, totalLen)
		if (ihl < 20 || pktEnd <= ihl)
			return

		if (_pktCounter.incrementAndGet() % 1024 == 0)
			evictIdleFlows()

		val fragField = u16(pkt, 6)
		val isMoreFrags = (fragField and 0x2000) != 0
		val fragOffBytes = (fragField and 0x1FFF) * 8

		if (!isMoreFrags && fragOffBytes == 0) {
			dispatchCompleteIpv4(pkt, ihl, pktEnd)
			return
		}

		val reassembled = reassembleIpv4Fragment(pkt, ihl, pktEnd, isMoreFrags, fragOffBytes) ?: return
		dispatchCompleteIpv4(reassembled, 20, reassembled.size)
	}

	private fun dispatchCompleteIpv4(pkt: ByteArray, ihl: Int, pktEnd: Int) {
		if (pktEnd < ihl + 8)
			return

		val proto = pkt[9].toInt() and 0xFF
		if (proto == 6) {
			handleTcpPacket(pkt, ihl, pktEnd)
		} else if (proto == 17) {
			handleUdpPacket(pkt, ihl, pktEnd)
		}
	}

	private fun reassembleIpv4Fragment(
		pkt: ByteArray,
		ihl: Int,
		pktEnd: Int,
		isMoreFrags: Boolean,
		fragOffBytes: Int,
	): ByteArray? {
		val sliceLen = pktEnd - ihl
		if (sliceLen <= 0 || fragOffBytes + sliceLen > 65_515)
			return null

		val key = "${u32(pkt, 12)}:${u32(pkt, 16)}:${pkt[9].toInt() and 0xFF}:${u16(pkt, 4)}"
		val slice = pkt.copyOfRange(ihl, pktEnd)
		val now = System.currentTimeMillis()

		synchronized(_fragLock) {
			if (_fragBuckets.size >= 64) {
				val it = _fragBuckets.entries.iterator()
				while (it.hasNext()) {
					val entry = it.next()
					if (now - entry.value.createdAtMs > 5000L || _fragBuckets.size >= 64)
						it.remove()
					else
						break
				}
			}

			val bucket = _fragBuckets.getOrPut(key) { Ipv4FragBucket(now) }
			if (fragOffBytes == 0 && bucket.header20 == null)
				bucket.header20 = pkt.copyOfRange(0, 20)

			bucket.parts[fragOffBytes] = slice
			if (!isMoreFrags)
				bucket.totalPayloadLen = fragOffBytes + sliceLen

			val expected = bucket.totalPayloadLen
			val hdr = bucket.header20
			if (expected <= 0 || hdr == null)
				return null

			var cursor = 0
			for ((off, part) in bucket.parts) {
				if (off > cursor)
					return null
				val end = off + part.size
				if (end > cursor)
					cursor = end
			}
			if (cursor < expected)
				return null

			_fragBuckets.remove(key)
			val fullLen = 20 + expected
			val full = ByteArray(fullLen)
			System.arraycopy(hdr, 0, full, 0, 20)
			full[0] = 0x45
			full[2] = ((fullLen ushr 8) and 0xFF).toByte()
			full[3] = (fullLen and 0xFF).toByte()
			full[6] = 0x00
			full[7] = 0x00
			full[10] = 0x00
			full[11] = 0x00

			var writtenCursor = 0
			for ((off, part) in bucket.parts) {
				val end = minOf(off + part.size, expected)
				if (end <= writtenCursor)
					continue
				val srcSkip = (writtenCursor - off).coerceAtLeast(0)
				val dstStart = maxOf(off, writtenCursor)
				val copyLen = end - dstStart
				if (copyLen > 0) {
					System.arraycopy(part, srcSkip, full, 20 + dstStart, copyLen)
					writtenCursor = dstStart + copyLen
				}
			}

			val csum = DnsWire.ipv4Checksum(full, 0, 20)
			full[10] = ((csum ushr 8) and 0xFF).toByte()
			full[11] = (csum and 0xFF).toByte()

			return full
		}
	}

	private fun isForbiddenRoutedEndpoint(dstIpStr: String, dstPort: Int, cfg: AppConfig): Boolean {
		if (dstIpStr == "0.0.0.0" || dstIpStr == cfg.vpnClientIp.trim() || dstIpStr == cfg.vpnDnsIp.trim())
			return true
		val ownProxyPort = _localProxyPortProvider()
		if (ownProxyPort > 0 && dstPort == ownProxyPort && dstIpStr.startsWith("127."))
			return true

		return false
	}

	private fun handleUdpPacket(pkt: ByteArray, ihl: Int, pktEnd: Int) {
		val srcIp = pkt.copyOfRange(12, 16)
		val dstIp = pkt.copyOfRange(16, 20)
		val srcPort = u16(pkt, ihl)
		val dstPort = u16(pkt, ihl + 2)
		val udpLen = u16(pkt, ihl + 4)
		val payloadLen = (udpLen - 8).coerceAtMost(pktEnd - ihl - 8)
		if (payloadLen <= 0)
			return

		val payload = pkt.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
		if (dstPort == 53) {
			_onDnsFrame?.invoke(IpUdpFrame(srcIp, dstIp, srcPort, dstPort, payload))
			return
		}

		val cfg = _configProvider()
		val srcIpStr = formatIpv4(srcIp)
		val dstIpStr = formatIpv4(dstIp)
		if (isForbiddenRoutedEndpoint(dstIpStr, dstPort, cfg))
			return

		val natKey = "$srcIpStr:$srcPort"
		val appPkg = resolveFlowOwner(OsConstants.IPPROTO_UDP, natKey, srcIp, srcPort, dstIp, dstPort, cfg.bypassedApps)
		val isBypassed = cfg.isAppBypassed(appPkg)
		val host = DnsWire.lookupHostByIp(dstIpStr, appPkg) ?: dstIpStr

		if (!isBypassed) {
			val (isWifi, isMobile) = _transportProvider()
			if (cfg.isAppFirewalled(appPkg, isWifi, isMobile)) {
				logBlockedThrottled("$appPkg|$host|UDP_FW", host, "UDP", appPkg, "Per-App Firewall")
				return
			}

			if (_engine != null && host != dstIpStr) {
				val dv = _engine.matchDns(host)
				if (dv.isBlocked) {
					logBlockedThrottled("$appPkg|$host|UDP_DNS", host, "UDP", appPkg, dv.summaryText())
					return
				}
			}

			val isMitmInspected = dstPort == 443 && cfg.isHttpsFiltering && _isCaReady() && appPkg.isNotEmpty() && cfg.httpsInspectedApps.contains(appPkg)
			if (isMitmInspected)
				return

			val matchedProxy = UpstreamProxy.selectProxy(cfg.proxies, appPkg, host, dstPort, cfg.bypassedApps)
			if (matchedProxy != null) {
				if (matchedProxy.type.equals("SOCKS5", ignoreCase = true) && matchedProxy.isUdpRelay) {
					val proxySession = getOrCreateSocks5UdpSession(natKey, matchedProxy, srcIp, srcPort, cfg.proxyConnectTimeoutMs)
					if (proxySession != null) {
						val socks5 = proxySession.socks5 ?: return
						proxySession.lastActiveMs = System.currentTimeMillis()
						logProxyUdpSampleThrottled(appPkg, host, matchedProxy.name)
						runCatching {
							val wrapped = UpstreamProxy.wrapSocks5UdpPayload(dstIp, dstPort, payload)
							socks5.udpSocket.send(DatagramPacket(wrapped, wrapped.size, socks5.relayAddress, socks5.relayPort))
						}
						return
					}
				}

				if (dstPort == 443 || matchedProxy.isBlockUdpFallback)
					return
			}
		}

		var session = _udpSessions[natKey]
		if (session == null || session.isClosed)
			session = createFullConeUdpSession(natKey, srcIp, srcPort) ?: return

		session.lastActiveMs = System.currentTimeMillis()
		runCatching {
			val dstAddr = InetAddress.getByAddress(dstIp)
			session.sock.send(DatagramPacket(payload, payload.size, dstAddr, dstPort))
		}
	}

	private fun logProxyUdpSampleThrottled(appPkg: String, host: String, proxyName: String) {
		val dedupKey = "$appPkg|$host|UDP_PROXY|$proxyName"
		val now = System.currentTimeMillis()
		val last = _blockLogDedup[dedupKey] ?: 0L
		if (now - last < 10_000L)
			return
		_blockLogDedup[dedupKey] = now
		_pushTraffic(
			TrafficSample(
				target = host,
				host = host,
				proto = "SOCKS5-UDP",
				isBlocked = false,
				isRoute = false,
				appPkg = appPkg,
				matchedRule = "Proxy: $proxyName",
			)
		)
	}

	private fun getOrCreateSocks5UdpSession(
		natKey: String,
		profile: ProxyProfile,
		clientIp: ByteArray,
		clientPort: Int,
		connectTimeoutMs: Int,
	): UdpNatSession? {
		val sessionKey = "$natKey|proxy:${profile.id}"
		val fast = _udpSessions[sessionKey]
		if (fast != null && !fast.isClosed)
			return fast

		val capKey = "${profile.id}|${profile.host.trim()}:${profile.port}"
		val now = System.currentTimeMillis()
		val unsupportedUntil = _proxyUdpUnsupportedUntil[capKey] ?: 0L
		if (unsupportedUntil > now)
			return null

		if (_udpSessions.size >= MAX_UDP_SESSIONS)
			ensureUdpCapacity()

		synchronized(_udpSessions) {
			val existing = _udpSessions[sessionKey]
			if (existing != null && !existing.isClosed)
				return existing

			val socks5 = UpstreamProxy.openSocks5UdpAssociate(
				profile = profile,
				connectTimeoutMs = connectTimeoutMs,
				idleTimeoutMs = UDP_IDLE_TIMEOUT_MS.toInt(),
				protectSocket = _protectSocket,
				protectDatagram = _protectDatagram,
				resolveHost = _resolveHostIp,
			)
			if (socks5 == null) {
				_proxyUdpUnsupportedUntil[capKey] = System.currentTimeMillis() + 30_000L
				return null
			}

			val created = UdpNatSession(socks5.udpSocket, System.currentTimeMillis(), socks5)
			_udpSessions[sessionKey] = created

			val isStarted = runCatching {
				_pool.execute {
					val recvBuf = ByteArray(65_535)
					try {
						while (_isRunning && !created.isClosed) {
							val dp = DatagramPacket(recvBuf, recvBuf.size)
							try {
								socks5.udpSocket.receive(dp)
							} catch (_: SocketTimeoutException) {
								if (System.currentTimeMillis() - created.lastActiveMs >= UDP_IDLE_TIMEOUT_MS)
									break
								continue
							}
							if (dp.length <= 10)
								continue

							val unwrapped = UpstreamProxy.unwrapSocks5UdpPacket(recvBuf, dp.length) ?: continue
							created.lastActiveMs = System.currentTimeMillis()
							writeUdpToTun(unwrapped.srcIp, clientIp, unwrapped.srcPort, clientPort, unwrapped.payload)
						}
					} catch (_: Throwable) {
					} finally {
						_udpSessions.remove(sessionKey, created)
						created.closeQuietly()
					}
				}
				true
			}.getOrDefault(false)

			if (!isStarted) {
				_udpSessions.remove(sessionKey, created)
				created.closeQuietly()
				return null
			}

			return created
		}
	}

	private fun createFullConeUdpSession(
		natKey: String,
		clientIp: ByteArray,
		clientPort: Int,
	): UdpNatSession? {
		if (_udpSessions.size >= MAX_UDP_SESSIONS)
			ensureUdpCapacity()

		synchronized(_udpSessions) {
			val existing = _udpSessions[natKey]
			if (existing != null && !existing.isClosed)
				return existing

			val dg = runCatching {
				val s = DatagramSocket()
				_protectDatagram(s)
				s.reuseAddress = true
				runCatching {
					s.receiveBufferSize = 512 * 1024
					s.sendBufferSize = 512 * 1024
				}
				s.soTimeout = UDP_IDLE_TIMEOUT_MS.toInt()
				s
			}.getOrNull() ?: return null

			val created = UdpNatSession(dg, System.currentTimeMillis())
			_udpSessions[natKey] = created

			val isStarted = runCatching {
				_pool.execute {
					val recvBuf = ByteArray(65_535)
					try {
						while (_isRunning && !dg.isClosed) {
							val dp = DatagramPacket(recvBuf, recvBuf.size)
							try {
								dg.receive(dp)
							} catch (_: SocketTimeoutException) {
								if (System.currentTimeMillis() - created.lastActiveMs >= UDP_IDLE_TIMEOUT_MS)
									break
								continue
							}
							if (dp.length <= 0)
								continue

							val peerIp = dp.address?.address ?: continue
							if (peerIp.size != 4)
								continue

							created.lastActiveMs = System.currentTimeMillis()
							val respPayload = recvBuf.copyOf(dp.length)
							writeUdpToTun(peerIp, clientIp, dp.port, clientPort, respPayload)
						}
					} catch (_: Throwable) {
					} finally {
						_udpSessions.remove(natKey, created)
						created.closeQuietly()
					}
				}
				true
			}.getOrDefault(false)

			if (!isStarted) {
				_udpSessions.remove(natKey, created)
				created.closeQuietly()
				return null
			}

			return created
		}
	}

	private fun writeUdpToTun(
		srcIp: ByteArray,
		dstIp: ByteArray,
		srcPort: Int,
		dstPort: Int,
		payload: ByteArray,
	) {
		for (frame in buildIpv4UdpFrames(srcIp, dstIp, srcPort, dstPort, payload, _tunMtu, _ipIdSeq))
			_writeTunPacket(frame)
	}

	private fun handleTcpPacket(pkt: ByteArray, ihl: Int, pktEnd: Int) {
		if (pktEnd < ihl + 20)
			return

		val srcIp = pkt.copyOfRange(12, 16)
		val dstIp = pkt.copyOfRange(16, 20)
		val srcPort = u16(pkt, ihl)
		val dstPort = u16(pkt, ihl + 2)
		val seqNum = u32(pkt, ihl + 4)
		val ackNum = u32(pkt, ihl + 8)
		val dataOff = ((pkt[ihl + 12].toInt() ushr 4) and 0x0F) * 4
		if (dataOff < 20 || pktEnd < ihl + dataOff)
			return

		val flags = pkt[ihl + 13].toInt() and 0xFF
		val rawWin = u16(pkt, ihl + 14)
		val isSyn = (flags and FLAG_SYN) != 0
		val isAck = (flags and FLAG_ACK) != 0
		val isFin = (flags and FLAG_FIN) != 0
		val isRst = (flags and FLAG_RST) != 0

		val srcIpStr = formatIpv4(srcIp)
		val dstIpStr = formatIpv4(dstIp)
		val flowKey = "$srcIpStr:$srcPort->$dstIpStr:$dstPort"

		if (isRst) {
			val existing = _tcpSessions[flowKey] ?: return
			val isSeqInWindow = synchronized(existing) {
				abs(seqDiff(seqNum, existing.clientNextSeq)) <= MAX_IN_FLIGHT_BYTES * 2
			}
			if (isSeqInWindow)
				_tcpSessions.remove(flowKey, existing).also { if (it) existing.closeQuietly() }
			return
		}

		if (isSyn && !isAck) {
			val cur = _tcpSessions[flowKey]
			if (cur != null && !cur.isClosed) {
				if (cur.initialClientSeq == seqNum) {
					val resendSynAck = synchronized(cur) { cur.synAckPacket }
					if (resendSynAck != null)
						_writeTunPacket(resendSynAck)
					return
				}
				_tcpSessions.remove(flowKey, cur)
				cur.closeQuietly()
			}

			val cfg = _configProvider()
			val isLocalDnsTcp = dstPort == 53 && dstIpStr == cfg.vpnDnsIp.trim() && _localDnsTcpHandler != null
			if (!isLocalDnsTcp && isForbiddenRoutedEndpoint(dstIpStr, dstPort, cfg)) {
				val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, 0L, (seqNum + 1L) and 0xFFFFFFFFL, FLAG_RST or FLAG_ACK, ByteArray(0))
				_writeTunPacket(rst)
				return
			}

			val appPkg = resolveFlowOwner(OsConstants.IPPROTO_TCP, flowKey, srcIp, srcPort, dstIp, dstPort, cfg.bypassedApps)
			val isBypassed = cfg.isAppBypassed(appPkg)
			val host = DnsWire.lookupHostByIp(dstIpStr, appPkg) ?: dstIpStr

			if (!isBypassed && !isLocalDnsTcp) {
				val (isWifi, isMobile) = _transportProvider()
				if (cfg.isAppFirewalled(appPkg, isWifi, isMobile)) {
					logBlockedThrottled("$appPkg|$host|TCP_FW", host, "TCP", appPkg, "Per-App Firewall")
					val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, 0L, (seqNum + 1L) and 0xFFFFFFFFL, FLAG_RST or FLAG_ACK, ByteArray(0))
					_writeTunPacket(rst)
					return
				}

				if (_engine != null && host != dstIpStr) {
					val dv = _engine.matchDns(host)
					if (dv.isBlocked) {
						logBlockedThrottled("$appPkg|$host|TCP_DNS", host, "TCP", appPkg, dv.summaryText())
						val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, 0L, (seqNum + 1L) and 0xFFFFFFFFL, FLAG_RST or FLAG_ACK, ByteArray(0))
						_writeTunPacket(rst)
						return
					}
				}
			}

			if (_tcpSessions.size >= MAX_TCP_SESSIONS)
				ensureTcpCapacity()

			val matchedProxy = if (isBypassed || isLocalDnsTcp) {
				null
			} else {
				UpstreamProxy.selectProxy(cfg.proxies, appPkg, host, dstPort, cfg.bypassedApps)
			}

			if (matchedProxy != null) {
				_pushTraffic(
					TrafficSample(
						target = host,
						host = host,
						proto = matchedProxy.type.uppercase(),
						isBlocked = false,
						isRoute = false,
						appPkg = appPkg,
						matchedRule = "Proxy: ${matchedProxy.name}",
					)
				)
			}

			val parsedWinShift = parseSynWindowScale(pkt, ihl, dataOff)
			val clientShift = if (parsedWinShift >= 0) parsedWinShift else 0
			val serverShift = if (parsedWinShift >= 0) SERVER_WIN_SCALE else -1
			val initServerSeq = (System.nanoTime() xor flowKey.hashCode().toLong()) and 0x7FFFFFFFL

			val session = TcpFlowSession(
				key = flowKey,
				clientIp = srcIp,
				serverIp = dstIp,
				clientPort = srcPort,
				serverPort = dstPort,
				initialClientSeq = seqNum,
				clientNextSeq = (seqNum + 1L) and 0xFFFFFFFFL,
				serverNextSeq = initServerSeq,
				clientLastAck = (initServerSeq + 1L) and 0xFFFFFFFFL,
				clientWinShift = clientShift,
				clientWindow = rawWin.coerceAtLeast(_tcpMss * 4),
			)
			_tcpSessions[flowKey] = session

			val isDispatched = runCatching {
				_pool.execute {
					if (isLocalDnsTcp) {
						runLocalDnsTcpSession(session, appPkg, dstIp, dstPort, srcIp, srcPort, serverShift)
					} else {
						runTcpSession(
							session = session,
							matchedProxy = matchedProxy,
							host = host,
							dstIp = dstIp,
							dstIpStr = dstIpStr,
							dstPort = dstPort,
							srcIp = srcIp,
							srcPort = srcPort,
							serverWinShift = serverShift,
							connectTimeoutMs = cfg.proxyConnectTimeoutMs,
							readTimeoutMs = cfg.proxyReadTimeoutMs,
						)
					}
				}
				true
			}.getOrDefault(false)

			if (!isDispatched) {
				_tcpSessions.remove(flowKey, session)
				session.closeQuietly()
				val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, 0L, (seqNum + 1L) and 0xFFFFFFFFL, FLAG_RST or FLAG_ACK, ByteArray(0))
				_writeTunPacket(rst)
			}
			return
		}

		val payloadOff = ihl + dataOff
		val payloadLen = pktEnd - payloadOff
		val session = _tcpSessions[flowKey]
		if (session == null || session.isClosed) {
			// RFC 9293 section 3.5.2: send RST for segments targeting closed/evicted flows so client reconnects immediately
			val rstSeq = if (isAck) ackNum else 0L
			val rstFlags = if (isAck) FLAG_RST else (FLAG_RST or FLAG_ACK)
			val rstAck = if (isAck) 0L else ((seqNum + payloadLen.toLong() + (if (isFin) 1L else 0L)) and 0xFFFFFFFFL)
			val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, rstSeq, rstAck, rstFlags, ByteArray(0))
			_writeTunPacket(rst)
			return
		}
		val payload = if (payloadLen > 0) pkt.copyOfRange(payloadOff, pktEnd) else ByteArray(0)

		var ackReplyPkt: ByteArray? = null
		var fastRetransmitPkt: ByteArray? = null

		synchronized(session) {
			if (session.isClosed)
				return
			session.lastActiveMs = System.currentTimeMillis()

			if (isAck) {
				val prevWin = session.clientWindow
				val newWin = (rawWin shl session.clientWinShift).coerceAtLeast(0)
				session.clientWindow = newWin
				if (session.isConnected) {
					val adv = seqDiff(ackNum, session.clientLastAck)
					if (adv > 0) {
						session.clientLastAck = ackNum
						session.dupAckCount = 0
						val it = session.unacked.entries.iterator()
						while (it.hasNext()) {
							val seg = it.next().value
							val segEnd = (seg.seq + seg.data.size.toLong()) and 0xFFFFFFFFL
							if (seqDiff(segEnd, ackNum) <= 0)
								it.remove()
							else
								break
						}
					} else if (adv == 0 && newWin == prevWin && payload.isEmpty() && !isFin && !isSyn && session.unacked.isNotEmpty()) {
						session.dupAckCount++
						if (session.dupAckCount == 3) {
							val missing = session.unacked.values.firstOrNull()
							if (missing != null) {
								missing.sentAtMs = System.currentTimeMillis()
								fastRetransmitPkt = buildIpv4TcpPacket(
									session.serverIp,
									session.clientIp,
									session.serverPort,
									session.clientPort,
									missing.seq,
									session.clientNextSeq,
									FLAG_PSH or FLAG_ACK,
									missing.data,
								)
							}
						}
					}
					if (adv > 0 || newWin > prevWin)
						(session as Object).notifyAll()
				}
			}

			if (payload.isNotEmpty()) {
				val diff = seqDiff(seqNum, session.clientNextSeq)
				if (diff <= 0) {
					val overlap = -diff
					if (overlap < payload.size) {
						val fresh = if (overlap == 0) payload else payload.copyOfRange(overlap, payload.size)
						session.clientNextSeq = (session.clientNextSeq + fresh.size.toLong()) and 0xFFFFFFFFL
						val combined = drainOutOfOrder(session, fresh)
						session.outQueue.offer(TcpOutItem.Data(combined))
					}
					ackReplyPkt = buildIpv4TcpPacket(
						session.serverIp,
						session.clientIp,
						session.serverPort,
						session.clientPort,
						session.serverNextSeq,
						session.clientNextSeq,
						FLAG_ACK,
						ByteArray(0),
					)
				} else if (diff <= 524_288 && session.outOfOrder.size < 64) {
					session.outOfOrder[seqNum] = payload
					ackReplyPkt = buildIpv4TcpPacket(
						session.serverIp,
						session.clientIp,
						session.serverPort,
						session.clientPort,
						session.serverNextSeq,
						session.clientNextSeq,
						FLAG_ACK,
						ByteArray(0),
					)
				}
			}

			if (isFin) {
				if (!session.isClientFinReceived) {
					session.isClientFinReceived = true
					session.clientNextSeq = (session.clientNextSeq + 1L) and 0xFFFFFFFFL
					session.outQueue.offer(TcpOutItem.Fin)
					(session as Object).notifyAll()
				}
				ackReplyPkt = buildIpv4TcpPacket(
					session.serverIp,
					session.clientIp,
					session.serverPort,
					session.clientPort,
					session.serverNextSeq,
					session.clientNextSeq,
					FLAG_ACK,
					ByteArray(0),
				)
			}
		}

		if (ackReplyPkt != null)
			_writeTunPacket(ackReplyPkt!!)
		if (fastRetransmitPkt != null)
			_writeTunPacket(fastRetransmitPkt!!)
	}

	private fun runLocalDnsTcpSession(
		session: TcpFlowSession,
		appPkg: String,
		dstIp: ByteArray,
		dstPort: Int,
		srcIp: ByteArray,
		srcPort: Int,
		serverWinShift: Int,
	) {
		val handler = _localDnsTcpHandler ?: return
		try {
			val synAck: ByteArray
			synchronized(session) {
				val sSeq = session.serverNextSeq
				session.serverNextSeq = (sSeq + 1L) and 0xFFFFFFFFL
				session.clientLastAck = session.serverNextSeq
				session.isConnected = true
				session.lastActiveMs = System.currentTimeMillis()
				synAck = buildIpv4TcpPacket(
					dstIp,
					srcIp,
					dstPort,
					srcPort,
					sSeq,
					session.clientNextSeq,
					FLAG_SYN or FLAG_ACK,
					ByteArray(0),
					tcpMss = _tcpMss,
					winScale = serverWinShift,
					windowSize = 0xFFFF,
				)
				session.synAckPacket = synAck
			}
			_writeTunPacket(synAck)

			val acc = ByteArrayOutputStream(512)
			while (_isRunning && !session.isClosed) {
				val item = session.outQueue.poll(4000, TimeUnit.MILLISECONDS) ?: break
				when (item) {
					is TcpOutItem.Data -> {
						acc.write(item.bytes)
						val raw = acc.toByteArray()
						var off = 0
						while (off + 2 <= raw.size) {
							val msgLen = ((raw[off].toInt() and 0xFF) shl 8) or (raw[off + 1].toInt() and 0xFF)
							if (msgLen <= 0 || msgLen > 65_535)
								return
							if (off + 2 + msgLen > raw.size)
								break
							val queryPayload = raw.copyOfRange(off + 2, off + 2 + msgLen)
							off += 2 + msgLen
							val replyPayload = handler(queryPayload, appPkg) ?: continue
							val framed = ByteArray(2 + replyPayload.size)
							framed[0] = ((replyPayload.size ushr 8) and 0xFF).toByte()
							framed[1] = (replyPayload.size and 0xFF).toByte()
							System.arraycopy(replyPayload, 0, framed, 2, replyPayload.size)
							sendSegmentChunksToTun(session, dstIp, srcIp, dstPort, srcPort, framed)
						}
						if (off > 0) {
							acc.reset()
							if (off < raw.size)
								acc.write(raw, off, raw.size - off)
						}
					}
					TcpOutItem.Fin, TcpOutItem.Close -> break
				}
			}

			finishServerFinHandshake(session, dstIp, srcIp, dstPort, srcPort)
		} catch (_: Throwable) {
			if (!session.isClosed)
				sendSessionRst(session)
		} finally {
			_tcpSessions.remove(session.key, session)
			session.closeQuietly()
		}
	}

	private fun sendSegmentChunksToTun(
		session: TcpFlowSession,
		dstIp: ByteArray,
		srcIp: ByteArray,
		dstPort: Int,
		srcPort: Int,
		bytes: ByteArray,
	) {
		var pos = 0
		while (pos < bytes.size && _isRunning && !session.isClosed) {
			val slice = bytes.copyOfRange(pos, minOf(pos + _tcpMss, bytes.size))
			val pkt: ByteArray
			synchronized(session) {
				val now = System.currentTimeMillis()
				session.lastActiveMs = now
				val sSeq = session.serverNextSeq
				session.serverNextSeq = (sSeq + slice.size.toLong()) and 0xFFFFFFFFL
				session.unacked[sSeq] = SentTcpSegment(sSeq, slice, now)
				pkt = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, sSeq, session.clientNextSeq, FLAG_PSH or FLAG_ACK, slice)
			}
			_writeTunPacket(pkt)
			pos += slice.size
		}
	}

	private fun runTcpSession(
		session: TcpFlowSession,
		matchedProxy: ProxyProfile?,
		host: String,
		dstIp: ByteArray,
		dstIpStr: String,
		dstPort: Int,
		srcIp: ByteArray,
		srcPort: Int,
		serverWinShift: Int,
		connectTimeoutMs: Int,
		readTimeoutMs: Int,
	) {
		val up = if (matchedProxy == null) {
			connectDirectByIp(dstIp, dstPort, connectTimeoutMs)
		} else {
			val proxyTarget = if (matchedProxy.isRemoteDns) host else dstIpStr
			UpstreamProxy.connectSocket(
				profile = matchedProxy,
				targetHost = proxyTarget,
				targetPort = dstPort,
				connectTimeoutMs = connectTimeoutMs,
				readTimeoutMs = readTimeoutMs,
				protectSocket = _protectSocket,
				resolveHost = _resolveHostIp,
			)
		}

		if (up == null || !_isRunning || session.isClosed) {
			up?.let { runCatching { it.close() } }
			_tcpSessions.remove(session.key, session)
			val rst = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, 0L, session.clientNextSeq, FLAG_RST or FLAG_ACK, ByteArray(0))
			_writeTunPacket(rst)
			session.closeQuietly()
			return
		}

		val synAck: ByteArray
		synchronized(session) {
			runCatching {
				up.tcpNoDelay = true
				up.keepAlive = true
				up.soTimeout = TCP_READ_TICK_MS
			}
			session.upstream = up
			val sSeq = session.serverNextSeq
			session.serverNextSeq = (sSeq + 1L) and 0xFFFFFFFFL
			session.clientLastAck = session.serverNextSeq
			session.isConnected = true
			session.lastActiveMs = System.currentTimeMillis()
			synAck = buildIpv4TcpPacket(
				dstIp,
				srcIp,
				dstPort,
				srcPort,
				sSeq,
				session.clientNextSeq,
				FLAG_SYN or FLAG_ACK,
				ByteArray(0),
				tcpMss = _tcpMss,
				winScale = serverWinShift,
				windowSize = 0xFFFF,
			)
			session.synAckPacket = synAck
		}
		_writeTunPacket(synAck)

		// Dedicated per-session FIFO writer guarantees strict TCP segment ordering to upstream socket
		val isWriterStarted = runCatching {
			_pool.execute {
				try {
					val out = up.getOutputStream()
					while (_isRunning && !session.isClosed) {
						val item = session.outQueue.take()
						when (item) {
							is TcpOutItem.Data -> {
								out.write(item.bytes)
								if (session.outQueue.isEmpty())
									out.flush()
							}
							TcpOutItem.Fin -> {
								runCatching { out.flush() }
								runCatching { up.shutdownOutput() }
								break
							}
							TcpOutItem.Close -> break
						}
					}
				} catch (_: Throwable) {
					if (_tcpSessions.remove(session.key, session))
						sendSessionRst(session)
					session.closeQuietly()
				}
			}
			true
		}.getOrDefault(false)

		if (!isWriterStarted) {
			if (_tcpSessions.remove(session.key, session))
				sendSessionRst(session)
			session.closeQuietly()
			return
		}

		try {
			val inp = up.getInputStream()
			val readBuf = ByteArray(_tcpMss)
			var lastZeroWinProbeMs = 0L

			while (_isRunning && !session.isClosed) {
				var rtoPkt: ByteArray? = null
				var maxToRead = _tcpMss
				var isZeroWindowProbe = false

				synchronized(session) {
					while (_isRunning && !session.isClosed) {
						val inFlight = seqDiff(session.serverNextSeq, session.clientLastAck).coerceAtLeast(0)
						val advWin = session.clientWindow.coerceIn(0, MAX_IN_FLIGHT_BYTES)
						val avail = advWin - inFlight
						if (avail > 0) {
							maxToRead = minOf(_tcpMss, avail)
							break
						}

						val now = System.currentTimeMillis()
						val oldest = session.unacked.values.firstOrNull()
						if (oldest != null && now - oldest.sentAtMs >= TCP_RTO_MS) {
							oldest.sentAtMs = now
							rtoPkt = buildIpv4TcpPacket(
								dstIp,
								srcIp,
								dstPort,
								srcPort,
								oldest.seq,
								session.clientNextSeq,
								FLAG_PSH or FLAG_ACK,
								oldest.data,
							)
							break
						}

						// RFC 9293 section 3.8.6.1 1-byte Zero-Window Probe when peer advertises win == 0
						if (advWin == 0 && inFlight == 0 && now - lastZeroWinProbeMs >= TCP_RTO_MS) {
							lastZeroWinProbeMs = now
							maxToRead = 1
							isZeroWindowProbe = true
							break
						}

						runCatching { (session as Object).wait(40L) }
					}
				}
				if (rtoPkt != null) {
					_writeTunPacket(rtoPkt!!)
					continue
				}
				if (!_isRunning || session.isClosed)
					break

				val n = try {
					inp.read(readBuf, 0, if (isZeroWindowProbe) 1 else maxToRead)
				} catch (_: SocketTimeoutException) {
					var idleRto: ByteArray? = null
					synchronized(session) {
						val now = System.currentTimeMillis()
						val oldest = session.unacked.values.firstOrNull()
						if (oldest != null && now - oldest.sentAtMs >= TCP_RTO_MS) {
							oldest.sentAtMs = now
							idleRto = buildIpv4TcpPacket(
								dstIp,
								srcIp,
								dstPort,
								srcPort,
								oldest.seq,
								session.clientNextSeq,
								FLAG_PSH or FLAG_ACK,
								oldest.data,
							)
						}
					}
					if (idleRto != null)
						_writeTunPacket(idleRto!!)
					continue
				}

				if (n < 0)
					break
				if (n == 0)
					continue

				val chunk = readBuf.copyOf(n)
				val dataPkt: ByteArray
				synchronized(session) {
					val now = System.currentTimeMillis()
					session.lastActiveMs = now
					val sSeq = session.serverNextSeq
					session.serverNextSeq = (sSeq + n.toLong()) and 0xFFFFFFFFL
					session.unacked[sSeq] = SentTcpSegment(sSeq, chunk, now)
					dataPkt = buildIpv4TcpPacket(
						dstIp,
						srcIp,
						dstPort,
						srcPort,
						sSeq,
						session.clientNextSeq,
						FLAG_PSH or FLAG_ACK,
						chunk,
					)
				}
				_writeTunPacket(dataPkt)
			}

			val drainDeadline = System.currentTimeMillis() + 1500L
			while (_isRunning && !session.isClosed && System.currentTimeMillis() < drainDeadline) {
				var isDrained = false
				var tailRetransmit: ByteArray? = null
				synchronized(session) {
					if (session.unacked.isEmpty()) {
						isDrained = true
					} else {
						val now = System.currentTimeMillis()
						val oldest = session.unacked.values.firstOrNull()
						if (oldest != null && now - oldest.sentAtMs >= TCP_RTO_MS) {
							oldest.sentAtMs = now
							tailRetransmit = buildIpv4TcpPacket(
								dstIp,
								srcIp,
								dstPort,
								srcPort,
								oldest.seq,
								session.clientNextSeq,
								FLAG_PSH or FLAG_ACK,
								oldest.data,
							)
						} else {
							runCatching { (session as Object).wait(50L) }
						}
					}
				}
				if (isDrained)
					break
				if (tailRetransmit != null)
					_writeTunPacket(tailRetransmit!!)
			}

			finishServerFinHandshake(session, dstIp, srcIp, dstPort, srcPort)
		} catch (_: Throwable) {
			if (!session.isClosed)
				sendSessionRst(session)
		} finally {
			_tcpSessions.remove(session.key, session)
			session.closeQuietly()
		}
	}

	private fun sendSessionRst(session: TcpFlowSession) {
		val sSeq: Long
		val cSeq: Long
		synchronized(session) {
			sSeq = session.serverNextSeq
			cSeq = session.clientNextSeq
		}
		val rst = buildIpv4TcpPacket(
			session.serverIp,
			session.clientIp,
			session.serverPort,
			session.clientPort,
			sSeq,
			cSeq,
			FLAG_RST or FLAG_ACK,
			ByteArray(0),
		)
		_writeTunPacket(rst)
	}

	private fun finishServerFinHandshake(
		session: TcpFlowSession,
		dstIp: ByteArray,
		srcIp: ByteArray,
		dstPort: Int,
		srcPort: Int,
	) {
		if (session.isClosed)
			return

		val finSeq: Long
		val expectedFinAck: Long
		var finPkt: ByteArray
		var lastFinSentMs = System.currentTimeMillis()

		synchronized(session) {
			finSeq = session.serverNextSeq
			expectedFinAck = (finSeq + 1L) and 0xFFFFFFFFL
			session.serverNextSeq = expectedFinAck
			finPkt = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, finSeq, session.clientNextSeq, FLAG_FIN or FLAG_ACK, ByteArray(0))
		}
		_writeTunPacket(finPkt)

		val finWaitDeadline = System.currentTimeMillis() + 1200L
		while (_isRunning && !session.isClosed && System.currentTimeMillis() < finWaitDeadline) {
			var retransmitFin: ByteArray? = null
			var isDone = false
			synchronized(session) {
				val isFinAcked = seqDiff(session.clientLastAck, expectedFinAck) >= 0
				if (session.isClientFinReceived && isFinAcked) {
					isDone = true
				} else {
					val now = System.currentTimeMillis()
					if (!isFinAcked && now - lastFinSentMs >= TCP_RTO_MS) {
						lastFinSentMs = now
						retransmitFin = buildIpv4TcpPacket(dstIp, srcIp, dstPort, srcPort, finSeq, session.clientNextSeq, FLAG_FIN or FLAG_ACK, ByteArray(0))
					} else {
						val rem = (finWaitDeadline - now).coerceIn(1L, 80L)
						runCatching { (session as Object).wait(rem) }
					}
				}
			}
			if (isDone)
				break
			if (retransmitFin != null)
				_writeTunPacket(retransmitFin!!)
		}
	}

	private fun connectDirectByIp(dstIp: ByteArray, dstPort: Int, connectTimeoutMs: Int): Socket? {
		return runCatching {
			val raw = Socket()
			_protectSocket(raw)
			raw.tcpNoDelay = true
			raw.keepAlive = true
			runCatching {
				raw.receiveBufferSize = 256 * 1024
				raw.sendBufferSize = 256 * 1024
			}
			raw.connect(InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort), connectTimeoutMs)
			raw
		}.getOrNull()
	}

	private fun drainOutOfOrder(session: TcpFlowSession, firstChunk: ByteArray): ByteArray {
		if (session.outOfOrder.isEmpty())
			return firstChunk

		val chunks = ArrayList<ByteArray>(4)
		chunks.add(firstChunk)
		while (session.outOfOrder.isNotEmpty()) {
			val nextBytes = session.outOfOrder.remove(session.clientNextSeq) ?: break
			chunks.add(nextBytes)
			session.clientNextSeq = (session.clientNextSeq + nextBytes.size.toLong()) and 0xFFFFFFFFL
		}
		if (chunks.size == 1)
			return firstChunk

		val merged = ByteArray(chunks.sumOf { it.size })
		var off = 0
		for (c in chunks) {
			System.arraycopy(c, 0, merged, off, c.size)
			off += c.size
		}

		return merged
	}

	private fun resolveFlowOwner(
		proto: Int,
		cacheKey: String,
		srcIp: ByteArray,
		srcPort: Int,
		dstIp: ByteArray,
		dstPort: Int,
		bypassedApps: Set<String>,
	): String {
		val now = System.currentTimeMillis()
		_uidPkgCache.get(cacheKey)?.let { hit ->
			if (hit.expiresAt > now)
				return hit.pkg
		}

		val cm = _cm ?: return ""
		val pm = _pm ?: return ""
		val pkg = runCatching {
			val srcAddr = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
			val dstAddr = InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
			val uid = cm.getConnectionOwnerUid(proto, srcAddr, dstAddr)
			if (uid <= 0) {
				""
			} else {
				val pkgs = pm.getPackagesForUid(uid)
				pkgs?.firstOrNull { bypassedApps.contains(it) } ?: pkgs?.firstOrNull() ?: ""
			}
		}.getOrDefault("")

		val ttl = if (pkg.isNotEmpty()) 30_000L else 250L
		_uidPkgCache[cacheKey] = CachedFlowOwner(pkg, now + ttl)

		return pkg
	}

	private fun logBlockedThrottled(
		dedupKey: String,
		host: String,
		proto: String,
		appPkg: String,
		ruleText: String,
	) {
		val now = System.currentTimeMillis()
		val last = _blockLogDedup[dedupKey] ?: 0L
		if (now - last < 2500L)
			return

		_blockLogDedup[dedupKey] = now
		_onBlockedHit()
		_pushTraffic(
			TrafficSample(
				target = host,
				host = host,
				proto = proto,
				isBlocked = true,
				isRoute = false,
				appPkg = appPkg,
				matchedRule = ruleText,
			)
		)
	}

	private fun ensureTcpCapacity() {
		evictIdleFlows()
		if (_tcpSessions.size < MAX_TCP_SESSIONS)
			return
		val oldest = _tcpSessions.entries.minByOrNull { it.value.lastActiveMs } ?: return
		if (_tcpSessions.remove(oldest.key, oldest.value)) {
			sendSessionRst(oldest.value)
			oldest.value.closeQuietly()
		}
	}

	private fun ensureUdpCapacity() {
		evictIdleFlows()
		if (_udpSessions.size < MAX_UDP_SESSIONS)
			return
		val oldest = _udpSessions.entries.minByOrNull { it.value.lastActiveMs } ?: return
		if (_udpSessions.remove(oldest.key, oldest.value))
			oldest.value.closeQuietly()
	}

	private fun evictIdleFlows() {
		val now = System.currentTimeMillis()
		val tcpIt = _tcpSessions.entries.iterator()
		while (tcpIt.hasNext()) {
			val s = tcpIt.next().value
			val limitMs = if (s.isClientFinReceived) TCP_HALF_CLOSED_TIMEOUT_MS else TCP_IDLE_TIMEOUT_MS
			if (s.isClosed || now - s.lastActiveMs > limitMs) {
				tcpIt.remove()
				if (!s.isClosed)
					sendSessionRst(s)
				s.closeQuietly()
			}
		}

		val udpIt = _udpSessions.entries.iterator()
		while (udpIt.hasNext()) {
			val u = udpIt.next().value
			if (u.isClosed || now - u.lastActiveMs > UDP_IDLE_TIMEOUT_MS) {
				udpIt.remove()
				u.closeQuietly()
			}
		}
	}

	companion object {
		const val FLAG_FIN = 0x01
		const val FLAG_SYN = 0x02
		const val FLAG_RST = 0x04
		const val FLAG_PSH = 0x08
		const val FLAG_ACK = 0x10

		private const val DEFAULT_TCP_MSS = 1360
		private const val SERVER_WIN_SCALE = 7
		private const val MAX_IN_FLIGHT_BYTES = 262_144
		private const val TCP_READ_TICK_MS = 250
		private const val TCP_RTO_MS = 300L
		private const val TCP_HALF_CLOSED_TIMEOUT_MS = 15_000L
		private const val TCP_IDLE_TIMEOUT_MS = 900_000L
		private const val UDP_IDLE_TIMEOUT_MS = 180_000L
		private const val MAX_TCP_SESSIONS = 768
		private const val MAX_UDP_SESSIONS = 384

		internal fun parseSynWindowScale(pkt: ByteArray, ihl: Int, tcpHeaderLen: Int): Int {
			var pos = ihl + 20
			val end = ihl + tcpHeaderLen
			while (pos < end) {
				val kind = pkt[pos].toInt() and 0xFF
				if (kind == 0)
					break
				if (kind == 1) {
					pos++
					continue
				}
				if (pos + 1 >= end)
					break
				val optLen = pkt[pos + 1].toInt() and 0xFF
				if (optLen < 2 || pos + optLen > end)
					break
				if (kind == 3 && optLen == 3)
					return (pkt[pos + 2].toInt() and 0xFF).coerceIn(0, 14)
				pos += optLen
			}

			return -1
		}

		internal fun buildIpv4UdpFrames(
			srcIp: ByteArray,
			dstIp: ByteArray,
			srcPort: Int,
			dstPort: Int,
			payload: ByteArray,
			mtu: Int,
			ipIdGen: AtomicInteger,
		): List<ByteArray> {
			val udpTotal = 8 + payload.size
			if (20 + udpTotal <= mtu)
				return listOf(DnsWire.buildIpv4Udp(srcIp, dstIp, srcPort, dstPort, payload))

			val udpSegment = ByteArray(udpTotal)
			udpSegment[0] = ((srcPort ushr 8) and 0xFF).toByte()
			udpSegment[1] = (srcPort and 0xFF).toByte()
			udpSegment[2] = ((dstPort ushr 8) and 0xFF).toByte()
			udpSegment[3] = (dstPort and 0xFF).toByte()
			udpSegment[4] = ((udpTotal ushr 8) and 0xFF).toByte()
			udpSegment[5] = (udpTotal and 0xFF).toByte()
			udpSegment[6] = 0x00
			udpSegment[7] = 0x00
			System.arraycopy(payload, 0, udpSegment, 8, payload.size)

			// RFC 791 fragment payload sizes before the final fragment must be multiples of 8 octets
			val maxChunk = ((mtu - 20) and 0xFFF8).coerceAtLeast(64)
			val ipId = ipIdGen.incrementAndGet() and 0xFFFF
			val frames = ArrayList<ByteArray>((udpTotal / maxChunk) + 1)
			var off = 0

			while (off < udpTotal) {
				val rem = udpTotal - off
				val isLast = rem <= maxChunk
				val chunkLen = if (isLast) rem else maxChunk
				val totalLen = 20 + chunkLen
				val frame = ByteArray(totalLen)

				frame[0] = 0x45
				frame[1] = 0x00
				frame[2] = ((totalLen ushr 8) and 0xFF).toByte()
				frame[3] = (totalLen and 0xFF).toByte()
				frame[4] = ((ipId ushr 8) and 0xFF).toByte()
				frame[5] = (ipId and 0xFF).toByte()

				val fragField = (if (isLast) 0 else 0x2000) or ((off / 8) and 0x1FFF)
				frame[6] = ((fragField ushr 8) and 0xFF).toByte()
				frame[7] = (fragField and 0xFF).toByte()
				frame[8] = 64
				frame[9] = 17
				System.arraycopy(srcIp, 0, frame, 12, 4)
				System.arraycopy(dstIp, 0, frame, 16, 4)

				val ipCsum = DnsWire.ipv4Checksum(frame, 0, 20)
				frame[10] = ((ipCsum ushr 8) and 0xFF).toByte()
				frame[11] = (ipCsum and 0xFF).toByte()

				System.arraycopy(udpSegment, off, frame, 20, chunkLen)
				frames.add(frame)
				off += chunkLen
			}

			return frames
		}

		internal fun buildIpv4TcpPacket(
			srcIp: ByteArray,
			dstIp: ByteArray,
			srcPort: Int,
			dstPort: Int,
			seqNum: Long,
			ackNum: Long,
			flags: Int,
			payload: ByteArray,
			tcpMss: Int = DEFAULT_TCP_MSS,
			winScale: Int = -1,
			windowSize: Int = 0xFFFF,
		): ByteArray {
			val isSyn = (flags and FLAG_SYN) != 0
			val tcpHeaderLen = when {
				isSyn && winScale >= 0 -> 28
				isSyn -> 24
				else -> 20
			}
			val tcpTotalLen = tcpHeaderLen + payload.size
			val totalLen = 20 + tcpTotalLen
			val out = ByteArray(totalLen)

			out[0] = 0x45
			out[1] = 0x00
			out[2] = ((totalLen ushr 8) and 0xFF).toByte()
			out[3] = (totalLen and 0xFF).toByte()
			out[4] = 0x00
			out[5] = 0x00
			out[6] = 0x40
			out[7] = 0x00
			out[8] = 64
			out[9] = 6
			System.arraycopy(srcIp, 0, out, 12, 4)
			System.arraycopy(dstIp, 0, out, 16, 4)

			val ipCsum = DnsWire.ipv4Checksum(out, 0, 20)
			out[10] = ((ipCsum ushr 8) and 0xFF).toByte()
			out[11] = (ipCsum and 0xFF).toByte()

			out[20] = ((srcPort ushr 8) and 0xFF).toByte()
			out[21] = (srcPort and 0xFF).toByte()
			out[22] = ((dstPort ushr 8) and 0xFF).toByte()
			out[23] = (dstPort and 0xFF).toByte()

			writeU32(out, 24, seqNum)
			writeU32(out, 28, ackNum)

			out[32] = ((tcpHeaderLen / 4) shl 4).toByte()
			out[33] = (flags and 0xFF).toByte()
			out[34] = ((windowSize ushr 8) and 0xFF).toByte()
			out[35] = (windowSize and 0xFF).toByte()
			out[36] = 0x00
			out[37] = 0x00
			out[38] = 0x00
			out[39] = 0x00

			if (isSyn) {
				out[40] = 0x02
				out[41] = 0x04
				out[42] = ((tcpMss ushr 8) and 0xFF).toByte()
				out[43] = (tcpMss and 0xFF).toByte()
				if (winScale >= 0) {
					out[44] = 0x01
					out[45] = 0x03
					out[46] = 0x03
					out[47] = (winScale and 0xFF).toByte()
				}
			}

			if (payload.isNotEmpty())
				System.arraycopy(payload, 0, out, 20 + tcpHeaderLen, payload.size)

			val tcpCsum = tcpChecksum(srcIp, dstIp, out, 20, tcpTotalLen)
			out[36] = ((tcpCsum ushr 8) and 0xFF).toByte()
			out[37] = (tcpCsum and 0xFF).toByte()

			return out
		}

		// RFC 793 one's complement sum over 12-byte IPv4 pseudo-header + TCP segment
		internal fun tcpChecksum(
			srcIp: ByteArray,
			dstIp: ByteArray,
			buf: ByteArray,
			tcpOffset: Int,
			tcpLen: Int,
		): Int {
			var sum = 0
			sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
			sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
			sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
			sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
			sum += 6
			sum += tcpLen

			var i = tcpOffset
			val end = tcpOffset + tcpLen
			while (i < end - 1) {
				sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
				i += 2
			}
			if (i < end)
				sum += (buf[i].toInt() and 0xFF) shl 8

			while ((sum ushr 16) != 0)
				sum = (sum and 0xFFFF) + (sum ushr 16)

			return sum.inv() and 0xFFFF
		}

		internal fun u16(b: ByteArray, off: Int): Int {
			return ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
		}

		internal fun u32(b: ByteArray, off: Int): Long {
			return ((b[off].toLong() and 0xFFL) shl 24) or
				((b[off + 1].toLong() and 0xFFL) shl 16) or
				((b[off + 2].toLong() and 0xFFL) shl 8) or
				(b[off + 3].toLong() and 0xFFL)
		}

		private fun writeU32(b: ByteArray, off: Int, v: Long) {
			b[off] = ((v ushr 24) and 0xFFL).toByte()
			b[off + 1] = ((v ushr 16) and 0xFFL).toByte()
			b[off + 2] = ((v ushr 8) and 0xFFL).toByte()
			b[off + 3] = (v and 0xFFL).toByte()
		}

		internal fun seqDiff(a: Long, b: Long): Int = a.toInt() - b.toInt()

		private fun formatIpv4(ip: ByteArray): String {
			return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
		}
	}
}

private fun <K, V> boundedMap(maxEntries: Int): MutableMap<K, V> {
	return Collections.synchronizedMap(
		object : LinkedHashMap<K, V>(64, 0.75f, true) {
			override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean = size > maxEntries
		}
	)
}

private class Ipv4FragBucket(
	val createdAtMs: Long,
) {
	var header20: ByteArray? = null
	var totalPayloadLen: Int = -1
	val parts = TreeMap<Int, ByteArray>()
}

private class CachedFlowOwner(
	val pkg: String,
	val expiresAt: Long,
)

private class UdpNatSession(
	val sock: DatagramSocket,
	@Volatile var lastActiveMs: Long,
	val socks5: Socks5UdpSession? = null,
) {
	val isClosed: Boolean
		get() = sock.isClosed || (socks5?.isClosed == true)

	fun closeQuietly() {
		socks5?.closeQuietly()
		runCatching { sock.close() }
	}
}

private sealed interface TcpOutItem {
	class Data(val bytes: ByteArray) : TcpOutItem
	data object Fin : TcpOutItem
	data object Close : TcpOutItem
}

private class SentTcpSegment(
	val seq: Long,
	val data: ByteArray,
	var sentAtMs: Long,
)

private class TcpFlowSession(
	val key: String,
	val clientIp: ByteArray,
	val serverIp: ByteArray,
	val clientPort: Int,
	val serverPort: Int,
	val initialClientSeq: Long,
	var clientNextSeq: Long,
	var serverNextSeq: Long,
	var clientLastAck: Long,
	val clientWinShift: Int,
	var clientWindow: Int,
) {
	@Volatile
	var isClosed: Boolean = false

	@Volatile
	var isConnected: Boolean = false

	@Volatile
	var isClientFinReceived: Boolean = false

	@Volatile
	var lastActiveMs: Long = System.currentTimeMillis()

	var dupAckCount: Int = 0
	var synAckPacket: ByteArray? = null
	var upstream: Socket? = null
	val outQueue = LinkedBlockingQueue<TcpOutItem>()
	val outOfOrder = HashMap<Long, ByteArray>()
	val unacked = LinkedHashMap<Long, SentTcpSegment>(64)

	fun closeQuietly() {
		if (isClosed)
			return
		isClosed = true
		outQueue.clear()
		outQueue.offer(TcpOutItem.Close)
		runCatching { upstream?.close() }
		upstream = null
		synchronized(this) {
			outOfOrder.clear()
			unacked.clear()
			runCatching { (this as Object).notifyAll() }
		}
	}
}
