package com.renwixx.trueadblocker.net

import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.engine.RuleEngine
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64

class Socks5UdpSession(
	val controlSocket: Socket,
	val udpSocket: DatagramSocket,
	val relayAddress: InetAddress,
	val relayPort: Int,
) {
	val isClosed: Boolean
		get() = controlSocket.isClosed || udpSocket.isClosed

	fun closeQuietly() {
		runCatching { udpSocket.close() }
		runCatching { controlSocket.close() }
	}
}

class UnwrappedSocks5Udp(
	val srcIp: ByteArray,
	val srcPort: Int,
	val payload: ByteArray,
)

object UpstreamProxy {
	fun selectProxy(
		profiles: List<ProxyProfile>,
		appPkg: String,
		host: String,
		port: Int,
		bypassedApps: Set<String> = emptySet(),
	): ProxyProfile? {
		if (profiles.isEmpty())
			return null
		if (appPkg.isNotEmpty() && bypassedApps.contains(appPkg))
			return null

		val normHost = RuleEngine.normalizeHost(host)
		for (p in profiles) {
			if (!p.isEnabled || p.host.isBlank() || p.port !in 1..65535)
				continue
			val isAppMatch = p.isAllApps || (appPkg.isNotEmpty() && p.appPackages.contains(appPkg))
			if (!isAppMatch)
				continue
			if (!matchesHostFilter(normHost, p.hostFilter))
				continue
			if (!matchesPortFilter(port, p.portFilter))
				continue

			return p
		}

		return null
	}

	fun matchesHostFilter(host: String, filterText: String): Boolean {
		val clean = filterText.trim()
		if (clean.isEmpty() || clean == "*")
			return true

		for (tok in clean.split(',', ';', ' ')) {
			val pat = tok.trim().lowercase()
			if (pat.isEmpty())
				continue
			if (pat == "*" || RuleEngine.globMatch(host, pat))
				return true
		}

		return false
	}

	fun matchesPortFilter(port: Int, filterText: String): Boolean {
		val clean = filterText.trim()
		if (clean.isEmpty() || clean == "*")
			return true

		for (tok in clean.split(',', ';', ' ')) {
			val part = tok.trim()
			if (part.isEmpty())
				continue
			if (part == "*")
				return true
			val dash = part.indexOf('-')
			if (dash > 0) {
				val lo = part.substring(0, dash).toIntOrNull() ?: continue
				val hi = part.substring(dash + 1).toIntOrNull() ?: continue
				if (port in lo..hi)
					return true
			} else if (part.toIntOrNull() == port) {
				return true
			}
		}

		return false
	}

	fun connectSocket(
		profile: ProxyProfile?,
		targetHost: String,
		targetPort: Int,
		connectTimeoutMs: Int,
		readTimeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)? = null,
	): Socket? {
		val cleanTarget = RuleEngine.normalizeHost(targetHost)
		if (profile == null) {
			return runCatching {
				val raw = Socket()
				protectSocket?.invoke(raw)
				raw.tcpNoDelay = true
				raw.keepAlive = true
				raw.soTimeout = readTimeoutMs
				val resolved = resolveHost?.invoke(cleanTarget)
				val endpoint = if (resolved != null) InetSocketAddress(resolved, targetPort) else InetSocketAddress(cleanTarget, targetPort)
				raw.connect(endpoint, connectTimeoutMs)
				raw
			}.getOrNull()
		}

		if (profile.type.equals("HTTP", ignoreCase = true))
			return connectHttpProxy(profile, cleanTarget, targetPort, connectTimeoutMs, readTimeoutMs, protectSocket, resolveHost)

		return connectSocks5Proxy(profile, cleanTarget, targetPort, connectTimeoutMs, readTimeoutMs, protectSocket, resolveHost)
	}

	fun openRawHttpProxyServerSocket(
		profile: ProxyProfile,
		connectTimeoutMs: Int,
		readTimeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)? = null,
	): Socket? {
		return runCatching {
			val sock = Socket()
			protectSocket?.invoke(sock)
			sock.tcpNoDelay = true
			sock.keepAlive = true
			sock.soTimeout = readTimeoutMs
			val proxyHost = profile.host.trim()
			val resolvedProxy = resolveHost?.invoke(proxyHost)
			val endpoint = if (resolvedProxy != null) InetSocketAddress(resolvedProxy, profile.port) else InetSocketAddress(proxyHost, profile.port)
			sock.connect(endpoint, connectTimeoutMs)
			sock
		}.getOrNull()
	}

	fun buildBasicProxyAuthHeader(profile: ProxyProfile): String {
		if (profile.username.isEmpty())
			return ""
		val creds = "${profile.username}:${profile.password}".toByteArray(Charsets.UTF_8)

		return "Basic ${Base64.getEncoder().encodeToString(creds)}"
	}

	fun testProxyLatency(
		profile: ProxyProfile,
		protectSocket: ((Socket) -> Boolean)? = null,
	): Result<Long> {
		if (profile.host.isBlank() || profile.port !in 1..65535)
			return Result.failure(IllegalArgumentException("Invalid proxy host or port"))

		return runCatching {
			val t0 = System.nanoTime()
			val sock = Socket()
			try {
				protectSocket?.invoke(sock)
				sock.tcpNoDelay = true
				sock.soTimeout = 6000
				sock.connect(InetSocketAddress(profile.host.trim(), profile.port), 6000)

				if (!profile.type.equals("HTTP", ignoreCase = true))
					performSocks5GreetingAndAuth(sock, profile)

				(System.nanoTime() - t0) / 1_000_000L
			} finally {
				runCatching { sock.close() }
			}
		}
	}

	// RFC 1928 section 7 UDP ASSOCIATE keeps TCP control socket open for the lifetime of the UDP relay binding
	fun openSocks5UdpAssociate(
		profile: ProxyProfile,
		connectTimeoutMs: Int,
		idleTimeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		protectDatagram: ((DatagramSocket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)? = null,
	): Socks5UdpSession? {
		if (!profile.type.equals("SOCKS5", ignoreCase = true))
			return null

		val ctrl = Socket()
		var dg: DatagramSocket? = null
		return try {
			protectSocket?.invoke(ctrl)
			ctrl.tcpNoDelay = true
			ctrl.keepAlive = true
			ctrl.soTimeout = connectTimeoutMs.coerceIn(1500, 30_000)
			val proxyHost = profile.host.trim()
			val resolvedProxy = if (CertAuthority.isIpLiteral(proxyHost)) {
				InetAddress.getByName(proxyHost)
			} else {
				resolveHost?.invoke(proxyHost)
			}
			val endpoint = if (resolvedProxy != null) InetSocketAddress(resolvedProxy, profile.port) else InetSocketAddress(proxyHost, profile.port)
			ctrl.connect(endpoint, connectTimeoutMs)

			performSocks5GreetingAndAuth(ctrl, profile)

			val inp = ctrl.getInputStream()
			val out = ctrl.getOutputStream()
			out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
			out.flush()

			val replyHead = ByteArray(4)
			readExact(inp, replyHead, 4)
			if (replyHead[0].toInt() != 0x05 || replyHead[1].toInt() != 0x00) {
				runCatching { ctrl.close() }
				return null
			}

			val bndAddr: InetAddress
			val bndPort: Int
			when (replyHead[3].toInt() and 0xFF) {
				0x01 -> {
					val tail = ByteArray(6)
					readExact(inp, tail, 6)
					bndAddr = InetAddress.getByAddress(tail.copyOfRange(0, 4))
					bndPort = ((tail[4].toInt() and 0xFF) shl 8) or (tail[5].toInt() and 0xFF)
				}
				0x04 -> {
					val tail = ByteArray(18)
					readExact(inp, tail, 18)
					bndAddr = InetAddress.getByAddress(tail.copyOfRange(0, 16))
					bndPort = ((tail[16].toInt() and 0xFF) shl 8) or (tail[17].toInt() and 0xFF)
				}
				0x03 -> {
					val domLen = inp.read()
					if (domLen <= 0)
						throw EOFException()
					val tail = ByteArray(domLen + 2)
					readExact(inp, tail, domLen + 2)
					val dom = String(tail, 0, domLen, Charsets.ISO_8859_1)
					bndAddr = resolveHost?.invoke(dom) ?: InetAddress.getByName(dom)
					bndPort = ((tail[domLen].toInt() and 0xFF) shl 8) or (tail[domLen + 1].toInt() and 0xFF)
				}
				else -> throw IllegalStateException("Unknown SOCKS5 UDP ATYP")
			}

			if (bndPort !in 1..65535) {
				runCatching { ctrl.close() }
				return null
			}

			val ctrlPeer = ctrl.inetAddress
			val relayAddr = if (bndAddr.isAnyLocalAddress || (bndAddr.isLoopbackAddress && !ctrlPeer.isLoopbackAddress)) {
				ctrlPeer
			} else {
				bndAddr
			}

			ctrl.soTimeout = 0
			val udp = DatagramSocket()
			dg = udp
			protectDatagram?.invoke(udp)
			udp.reuseAddress = true
			runCatching {
				udp.receiveBufferSize = 512 * 1024
				udp.sendBufferSize = 512 * 1024
			}
			udp.soTimeout = idleTimeoutMs

			Socks5UdpSession(ctrl, udp, relayAddr, bndPort)
		} catch (_: Throwable) {
			runCatching { dg?.close() }
			runCatching { ctrl.close() }
			null
		}
	}

	fun wrapSocks5UdpPayload(dstIp: ByteArray, dstPort: Int, payload: ByteArray): ByteArray {
		val out = ByteArray(10 + payload.size)
		out[3] = 0x01
		System.arraycopy(dstIp, 0, out, 4, 4)
		out[8] = ((dstPort ushr 8) and 0xFF).toByte()
		out[9] = (dstPort and 0xFF).toByte()
		System.arraycopy(payload, 0, out, 10, payload.size)

		return out
	}

	fun unwrapSocks5UdpPacket(buf: ByteArray, len: Int): UnwrappedSocks5Udp? {
		if (len <= 10 || buf[2].toInt() != 0)
			return null

		return when (buf[3].toInt() and 0xFF) {
			0x01 -> {
				val srcIp = buf.copyOfRange(4, 8)
				val srcPort = ((buf[8].toInt() and 0xFF) shl 8) or (buf[9].toInt() and 0xFF)
				val payload = buf.copyOfRange(10, len)
				UnwrappedSocks5Udp(srcIp, srcPort, payload)
			}
			0x03 -> {
				val domLen = buf[4].toInt() and 0xFF
				val hdrLen = 5 + domLen + 2
				if (domLen <= 0 || len <= hdrLen)
					return null
				val dom = String(buf, 5, domLen, Charsets.ISO_8859_1)
				if (!CertAuthority.isIpv4Literal(dom))
					return null
				val srcIp = runCatching { InetAddress.getByName(dom).address }.getOrNull() ?: return null
				if (srcIp.size != 4)
					return null
				val srcPort = ((buf[5 + domLen].toInt() and 0xFF) shl 8) or (buf[6 + domLen].toInt() and 0xFF)
				val payload = buf.copyOfRange(hdrLen, len)
				UnwrappedSocks5Udp(srcIp, srcPort, payload)
			}
			else -> null
		}
	}

	fun queryDnsOverProxyTcp(
		profile: ProxyProfile,
		rawQuery: ByteArray,
		dnsIp: String,
		timeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)? = null,
	): ByteArray? {
		if (rawQuery.size < 12 || dnsIp.isBlank())
			return null
		val clamped = timeoutMs.coerceIn(800, 15_000)
		val sock = connectSocket(profile, dnsIp.trim(), 53, clamped, clamped, protectSocket, resolveHost) ?: return null

		return runCatching {
			sock.use { s ->
				val out = DataOutputStream(s.getOutputStream())
				out.writeShort(rawQuery.size)
				out.write(rawQuery)
				out.flush()

				val inp = DataInputStream(s.getInputStream())
				val respLen = inp.readUnsignedShort()
				if (respLen !in 12..65_535)
					return null
				val resp = ByteArray(respLen)
				inp.readFully(resp)
				if (resp[0] == rawQuery[0] && resp[1] == rawQuery[1]) resp else null
			}
		}.getOrNull()
	}

	private fun connectHttpProxy(
		profile: ProxyProfile,
		targetHost: String,
		targetPort: Int,
		connectTimeoutMs: Int,
		readTimeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)?,
	): Socket? {
		val sock = openRawHttpProxyServerSocket(profile, connectTimeoutMs, readTimeoutMs, protectSocket, resolveHost) ?: return null
		return try {
			val hostPart = if (targetHost.contains(':') && !targetHost.startsWith('[')) "[$targetHost]" else targetHost
			val authority = "$hostPart:$targetPort"
			val authVal = buildBasicProxyAuthHeader(profile)
			val req = buildString(192) {
				append("CONNECT ").append(authority).append(" HTTP/1.1\r\n")
				append("Host: ").append(authority).append("\r\n")
				if (authVal.isNotEmpty())
					append("Proxy-Authorization: ").append(authVal).append("\r\n")
				append("Proxy-Connection: keep-alive\r\n\r\n")
			}

			val out = sock.getOutputStream()
			out.write(req.toByteArray(Charsets.ISO_8859_1))
			out.flush()

			val statusLine = readHeaderBlockStatus(sock.getInputStream())
			val statusCode = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
			if (statusCode !in 200..299) {
				runCatching { sock.close() }
				return null
			}
			sock
		} catch (_: Throwable) {
			runCatching { sock.close() }
			null
		}
	}

	// RFC 1928 SOCKS5 + RFC 1929 Username/Password subnegotiation
	private fun connectSocks5Proxy(
		profile: ProxyProfile,
		targetHost: String,
		targetPort: Int,
		connectTimeoutMs: Int,
		readTimeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
		resolveHost: ((String) -> InetAddress?)?,
	): Socket? {
		val sock = Socket()
		return try {
			protectSocket?.invoke(sock)
			sock.tcpNoDelay = true
			sock.keepAlive = true
			sock.soTimeout = readTimeoutMs
			val proxyHost = profile.host.trim()
			val resolvedProxy = resolveHost?.invoke(proxyHost)
			val endpoint = if (resolvedProxy != null) InetSocketAddress(resolvedProxy, profile.port) else InetSocketAddress(proxyHost, profile.port)
			sock.connect(endpoint, connectTimeoutMs)

			performSocks5GreetingAndAuth(sock, profile)

			val inp = sock.getInputStream()
			val out = sock.getOutputStream()
			val isIpLit = CertAuthority.isIpLiteral(targetHost)

			val reqBytes = if (!isIpLit && profile.isRemoteDns) {
				val domBytes = targetHost.toByteArray(Charsets.ISO_8859_1)
				if (domBytes.isEmpty() || domBytes.size > 255)
					throw IllegalArgumentException("Invalid SOCKS5 domain length")
				ByteArray(7 + domBytes.size).also { b ->
					b[0] = 0x05
					b[1] = 0x01
					b[2] = 0x00
					b[3] = 0x03
					b[4] = domBytes.size.toByte()
					System.arraycopy(domBytes, 0, b, 5, domBytes.size)
					b[5 + domBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
					b[6 + domBytes.size] = (targetPort and 0xFF).toByte()
				}
			} else {
				val resolved = if (isIpLit) {
					InetAddress.getByName(targetHost)
				} else {
					resolveHost?.invoke(targetHost) ?: InetAddress.getByName(targetHost)
				}
				val addrBytes = resolved.address
				val atyp: Byte = when (resolved) {
					is Inet4Address -> 0x01
					is Inet6Address -> 0x04
					else -> throw IllegalStateException("Unsupported address family")
				}
				ByteArray(6 + addrBytes.size).also { b ->
					b[0] = 0x05
					b[1] = 0x01
					b[2] = 0x00
					b[3] = atyp
					System.arraycopy(addrBytes, 0, b, 4, addrBytes.size)
					b[4 + addrBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
					b[5 + addrBytes.size] = (targetPort and 0xFF).toByte()
				}
			}

			out.write(reqBytes)
			out.flush()

			val replyHead = ByteArray(4)
			readExact(inp, replyHead, 4)
			if (replyHead[0].toInt() != 0x05 || replyHead[1].toInt() != 0x00) {
				runCatching { sock.close() }
				return null
			}

			val boundTailLen = when (replyHead[3].toInt() and 0xFF) {
				0x01 -> 4 + 2
				0x04 -> 16 + 2
				0x03 -> {
					val domLen = inp.read()
					if (domLen < 0)
						throw EOFException()
					domLen + 2
				}
				else -> throw IllegalStateException("Unknown SOCKS5 ATYP")
			}
			readExact(inp, ByteArray(boundTailLen), boundTailLen)
			sock
		} catch (_: Throwable) {
			runCatching { sock.close() }
			null
		}
	}

	private fun performSocks5GreetingAndAuth(sock: Socket, profile: ProxyProfile) {
		val inp = sock.getInputStream()
		val out = sock.getOutputStream()
		val hasAuth = profile.username.isNotEmpty()

		val greeting = if (hasAuth) {
			byteArrayOf(0x05, 0x02, 0x00, 0x02)
		} else {
			byteArrayOf(0x05, 0x01, 0x00)
		}
		out.write(greeting)
		out.flush()

		val choice = ByteArray(2)
		readExact(inp, choice, 2)
		if (choice[0].toInt() != 0x05)
			throw IllegalStateException("Invalid SOCKS5 version ${choice[0]}")

		val method = choice[1].toInt() and 0xFF
		if (method == 0x02) {
			val uBytes = profile.username.toByteArray(Charsets.UTF_8)
			val pBytes = profile.password.toByteArray(Charsets.UTF_8)
			if (uBytes.size > 255 || pBytes.size > 255)
				throw IllegalArgumentException("SOCKS5 credentials exceed 255 bytes")

			val authPkt = ByteArray(3 + uBytes.size + pBytes.size)
			authPkt[0] = 0x01
			authPkt[1] = uBytes.size.toByte()
			System.arraycopy(uBytes, 0, authPkt, 2, uBytes.size)
			authPkt[2 + uBytes.size] = pBytes.size.toByte()
			System.arraycopy(pBytes, 0, authPkt, 3 + uBytes.size, pBytes.size)
			out.write(authPkt)
			out.flush()

			val authResp = ByteArray(2)
			readExact(inp, authResp, 2)
			if (authResp[1].toInt() != 0x00)
				throw IllegalStateException("SOCKS5 authentication rejected")
		} else if (method != 0x00) {
			throw IllegalStateException("SOCKS5 server rejected auth methods")
		}
	}

	private fun readHeaderBlockStatus(inp: InputStream): String {
		val raw = ByteArrayOutputStream(128)
		var state = 0
		while (raw.size() < 16_384) {
			val b = inp.read()
			if (b < 0)
				break
			raw.write(b)
			state = when {
				state == 0 && b == '\r'.code -> 1
				state == 1 && b == '\n'.code -> 2
				state == 2 && b == '\r'.code -> 3
				state == 3 && b == '\n'.code -> 4
				b == '\r'.code -> 1
				else -> 0
			}
			if (state == 4)
				break
		}
		if (state != 4)
			return ""

		return String(raw.toByteArray(), Charsets.ISO_8859_1).substringBefore("\r\n")
	}

	private fun readExact(inp: InputStream, buf: ByteArray, len: Int) {
		var off = 0
		while (off < len) {
			val n = inp.read(buf, off, len - off)
			if (n <= 0)
				throw EOFException("Unexpected EOF during proxy handshake")
			off += n
		}
	}
}
