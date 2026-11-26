package com.renwixx.trueadblocker.net

import android.util.LruCache
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NODATA
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NXDOMAIN
import com.renwixx.trueadblocker.engine.RuleEngine
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

data class ParsedDnsQuery(
	val txId: Int,
	val qname: String,
	val qtype: Int,
	val qclass: Int,
	val questionEndOffset: Int,
)

data class IpUdpFrame(
	val srcIp: ByteArray,
	val dstIp: ByteArray,
	val srcPort: Int,
	val dstPort: Int,
	val payload: ByteArray,
)

data class DnsAnswerInspection(
	val cnameChain: List<String>,
	val ipv4Addresses: List<String>,
	val minTtlSec: Int = 0,
)

object DnsWire {
	const val TYPE_A = 1
	const val TYPE_CNAME = 5
	const val TYPE_AAAA = 28
	const val TYPE_SVCB = 64
	const val TYPE_HTTPS = 65

	private val DNS_MEDIA_TYPE = "application/dns-message".toMediaType()
	private val _ipToHost: MutableMap<String, String> = Collections.synchronizedMap(
		object : LinkedHashMap<String, String>(256, 0.75f, true) {
			override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > 4096
		}
	)
	private val _appIpToHost: MutableMap<String, String> = Collections.synchronizedMap(
		object : LinkedHashMap<String, String>(128, 0.75f, true) {
			override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > 2048
		}
	)

	private val DOH_BOOTSTRAP_IPS = mapOf(
		"cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
		"one.one.one.one" to listOf("1.1.1.1", "1.0.0.1"),
		"mozilla.cloudflare-dns.com" to listOf("104.16.248.249", "104.16.249.249"),
		"dns.google" to listOf("8.8.8.8", "8.8.4.4"),
		"dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
		"unfiltered.adguard-dns.com" to listOf("94.140.14.140", "94.140.14.141"),
		"dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.15.15"),
		"dns.mullvad.net" to listOf("194.242.2.2", "194.242.2.3"),
	)

	fun lookupHostByIp(ip: String, appPkg: String = ""): String? {
		if (appPkg.isNotEmpty())
			_appIpToHost["$appPkg|$ip"]?.let { return it }

		return _ipToHost[ip]
	}

	fun recordIpHost(ip: String, host: String, appPkg: String = "") {
		if (ip.isEmpty() || host.isEmpty())
			return
		_ipToHost[ip] = host
		if (appPkg.isNotEmpty() && appPkg != "System DNS")
			_appIpToHost["$appPkg|$ip"] = host
	}

	fun parseIpv4Udp(packet: ByteArray, length: Int): IpUdpFrame? {
		if (length < 28)
			return null
		val ver = (packet[0].toInt() ushr 4) and 0x0F
		if (ver != 4)
			return null

		val ihl = (packet[0].toInt() and 0x0F) * 4
		if (ihl < 20 || length < ihl + 8)
			return null

		val fragField = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
		if ((fragField and 0x3FFF) != 0)
			return null

		val proto = packet[9].toInt() and 0xFF
		if (proto != 17)
			return null

		val srcIp = packet.copyOfRange(12, 16)
		val dstIp = packet.copyOfRange(16, 20)
		val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
		val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
		val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
		val payloadLen = (udpLen - 8).coerceAtMost(length - ihl - 8)
		if (payloadLen <= 0)
			return null

		val payload = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLen)

		return IpUdpFrame(srcIp, dstIp, srcPort, dstPort, payload)
	}

	fun buildIpv4Udp(
		srcIp: ByteArray,
		dstIp: ByteArray,
		srcPort: Int,
		dstPort: Int,
		payload: ByteArray,
	): ByteArray {
		val udpLen = 8 + payload.size
		val totalLen = 20 + udpLen
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
		out[9] = 17
		System.arraycopy(srcIp, 0, out, 12, 4)
		System.arraycopy(dstIp, 0, out, 16, 4)

		val ipCsum = ipv4Checksum(out, 0, 20)
		out[10] = ((ipCsum ushr 8) and 0xFF).toByte()
		out[11] = (ipCsum and 0xFF).toByte()

		out[20] = ((srcPort ushr 8) and 0xFF).toByte()
		out[21] = (srcPort and 0xFF).toByte()
		out[22] = ((dstPort ushr 8) and 0xFF).toByte()
		out[23] = (dstPort and 0xFF).toByte()
		out[24] = ((udpLen ushr 8) and 0xFF).toByte()
		out[25] = (udpLen and 0xFF).toByte()
		out[26] = 0x00
		out[27] = 0x00
		System.arraycopy(payload, 0, out, 28, payload.size)

		return out
	}

	internal fun ipv4Checksum(buf: ByteArray, offset: Int, len: Int): Int {
		var sum = 0
		var i = offset
		val end = offset + len
		while (i < end - 1) {
			val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
			sum += word
			i += 2
		}
		if (i < end)
			sum += (buf[i].toInt() and 0xFF) shl 8

		while ((sum ushr 16) != 0)
			sum = (sum and 0xFFFF) + (sum ushr 16)

		return sum.inv() and 0xFFFF
	}

	fun parseDnsQuery(dns: ByteArray): ParsedDnsQuery? {
		if (dns.size < 12)
			return null

		val flags = ((dns[2].toInt() and 0xFF) shl 8) or (dns[3].toInt() and 0xFF)
		if ((flags and 0x8000) != 0)
			return null

		val qdCount = ((dns[4].toInt() and 0xFF) shl 8) or (dns[5].toInt() and 0xFF)
		if (qdCount < 1)
			return null

		val txId = ((dns[0].toInt() and 0xFF) shl 8) or (dns[1].toInt() and 0xFF)
		val sb = StringBuilder(64)
		var pos = 12
		var jumps = 0
		var endPos = -1

		while (pos < dns.size) {
			val len = dns[pos].toInt() and 0xFF
			if (len == 0) {
				if (endPos == -1)
					endPos = pos + 1
				break
			}
			// RFC 1035 section 4.1.4 label pointer compression (top two bits 11)
			if ((len and 0xC0) == 0xC0) {
				if (pos + 1 >= dns.size || ++jumps > 10)
					return null
				if (endPos == -1)
					endPos = pos + 2
				pos = ((len and 0x3F) shl 8) or (dns[pos + 1].toInt() and 0xFF)
				continue
			}
			pos++
			if (pos + len > dns.size)
				return null
			if (sb.isNotEmpty())
				sb.append('.')
			for (k in 0 until len)
				sb.append((dns[pos + k].toInt() and 0xFF).toChar())
			pos += len
		}

		if (endPos < 0 || endPos + 4 > dns.size)
			return null

		val qtype = ((dns[endPos].toInt() and 0xFF) shl 8) or (dns[endPos + 1].toInt() and 0xFF)
		val qclass = ((dns[endPos + 2].toInt() and 0xFF) shl 8) or (dns[endPos + 3].toInt() and 0xFF)

		return ParsedDnsQuery(
			txId = txId,
			qname = sb.toString().lowercase(),
			qtype = qtype,
			qclass = qclass,
			questionEndOffset = endPos + 4,
		)
	}

	fun buildSyntheticBlockedDns(query: ByteArray, parsed: ParsedDnsQuery): ByteArray {
		val qSection = query.copyOfRange(12, parsed.questionEndOffset)
		val out = ByteArrayOutputStream(parsed.questionEndOffset + 32)
		val rdBit = query[2].toInt() and 0x01
		val cdBit = query[3].toInt() and 0x10

		out.write(query[0].toInt())
		out.write(query[1].toInt())
		out.write(0x80 or rdBit)
		out.write(0x80 or cdBit)
		out.write(0x00)
		out.write(0x01)

		val isAddressRecord = parsed.qtype == TYPE_A || parsed.qtype == TYPE_AAAA
		out.write(0x00)
		out.write(if (isAddressRecord) 0x01 else 0x00)
		out.write(0x00)
		out.write(0x00)
		out.write(0x00)
		out.write(0x00)
		out.write(qSection)

		if (parsed.qtype == TYPE_A) {
			out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0, 0, 0, 0))
		} else if (parsed.qtype == TYPE_AAAA) {
			out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10))
			out.write(ByteArray(16))
		}

		return out.toByteArray()
	}

	fun buildBlockedDnsReply(query: ByteArray, parsed: ParsedDnsQuery, mode: Int): ByteArray {
		return when (mode) {
			BLOCKED_DNS_NXDOMAIN -> buildNxDomainDns(query, parsed)
			BLOCKED_DNS_NODATA -> buildEmptyNoDataDns(query, parsed)
			else -> buildSyntheticBlockedDns(query, parsed)
		}
	}

	fun buildNxDomainDns(query: ByteArray, parsed: ParsedDnsQuery): ByteArray {
		val qSection = query.copyOfRange(12, parsed.questionEndOffset)
		val out = ByteArrayOutputStream(parsed.questionEndOffset + 4)
		val rdBit = query[2].toInt() and 0x01
		val cdBit = query[3].toInt() and 0x10

		out.write(query[0].toInt())
		out.write(query[1].toInt())
		out.write(0x80 or rdBit)
		out.write(0x83 or cdBit)
		out.write(0x00)
		out.write(0x01)
		out.write(ByteArray(6))
		out.write(qSection)

		return out.toByteArray()
	}

	fun inspectDnsAnswer(
		dns: ByteArray,
		queryHost: String = "",
		maxCnames: Int = 8,
		isRecordIpMapping: Boolean = true,
		appPkg: String = "",
	): DnsAnswerInspection {
		if (dns.size < 12)
			return DnsAnswerInspection(emptyList(), emptyList(), 0)

		val qdCount = ((dns[4].toInt() and 0xFF) shl 8) or (dns[5].toInt() and 0xFF)
		val anCount = ((dns[6].toInt() and 0xFF) shl 8) or (dns[7].toInt() and 0xFF)
		if (anCount <= 0)
			return DnsAnswerInspection(emptyList(), emptyList(), 0)

		var pos = 12
		repeat(qdCount) {
			pos = skipDnsName(dns, pos)
			if (pos < 0 || pos + 4 > dns.size)
				return DnsAnswerInspection(emptyList(), emptyList(), 0)
			pos += 4
		}

		val cnames = ArrayList<String>(4)
		val ips = ArrayList<String>(4)
		val normQueryHost = RuleEngine.normalizeHost(queryHost)
		var minTtl = Int.MAX_VALUE

		repeat(anCount) {
			pos = skipDnsName(dns, pos)
			if (pos < 0 || pos + 10 > dns.size)
				return DnsAnswerInspection(cnames, ips, if (minTtl == Int.MAX_VALUE) 0 else minTtl)

			val rtype = ((dns[pos].toInt() and 0xFF) shl 8) or (dns[pos + 1].toInt() and 0xFF)
			val ttl = (((dns[pos + 4].toLong() and 0xFFL) shl 24) or
				((dns[pos + 5].toLong() and 0xFFL) shl 16) or
				((dns[pos + 6].toLong() and 0xFFL) shl 8) or
				(dns[pos + 7].toLong() and 0xFFL)).coerceIn(0L, 86_400L).toInt()
			if (ttl < minTtl)
				minTtl = ttl

			val rdLen = ((dns[pos + 8].toInt() and 0xFF) shl 8) or (dns[pos + 9].toInt() and 0xFF)
			val rdataPos = pos + 10
			if (rdLen < 0 || rdataPos + rdLen > dns.size)
				return DnsAnswerInspection(cnames, ips, if (minTtl == Int.MAX_VALUE) 0 else minTtl)

			if (rtype == TYPE_CNAME && cnames.size < maxCnames) {
				val target = readDnsName(dns, rdataPos)
				if (target.isNotEmpty() && !cnames.contains(target))
					cnames.add(target)
			} else if (rtype == TYPE_A && rdLen == 4) {
				val ip = "${dns[rdataPos].toInt() and 0xFF}.${dns[rdataPos + 1].toInt() and 0xFF}." +
					"${dns[rdataPos + 2].toInt() and 0xFF}.${dns[rdataPos + 3].toInt() and 0xFF}"
				ips.add(ip)
				if (isRecordIpMapping && normQueryHost.isNotEmpty() && ip != "0.0.0.0")
					recordIpHost(ip, normQueryHost, appPkg)
			}

			pos = rdataPos + rdLen
		}

		return DnsAnswerInspection(cnames, ips, if (minTtl == Int.MAX_VALUE) 0 else minTtl)
	}

	private fun skipDnsName(dns: ByteArray, startPos: Int): Int {
		var pos = startPos
		while (pos < dns.size) {
			val len = dns[pos].toInt() and 0xFF
			if (len == 0)
				return pos + 1
			if ((len and 0xC0) == 0xC0)
				return if (pos + 1 < dns.size) pos + 2 else -1
			pos += 1 + len
		}

		return -1
	}

	private fun readDnsName(dns: ByteArray, startPos: Int): String {
		val sb = StringBuilder(64)
		var pos = startPos
		var jumps = 0
		while (pos < dns.size) {
			val len = dns[pos].toInt() and 0xFF
			if (len == 0)
				break
			if ((len and 0xC0) == 0xC0) {
				if (pos + 1 >= dns.size || ++jumps > 12)
					return ""
				pos = ((len and 0x3F) shl 8) or (dns[pos + 1].toInt() and 0xFF)
				continue
			}
			pos++
			if (pos + len > dns.size)
				return ""
			if (sb.isNotEmpty())
				sb.append('.')
			for (k in 0 until len)
				sb.append((dns[pos + k].toInt() and 0xFF).toChar())
			pos += len
		}

		return sb.toString().lowercase().trimEnd('.')
	}

	fun buildEmptyNoDataDns(query: ByteArray, parsed: ParsedDnsQuery): ByteArray {
		val qSection = query.copyOfRange(12, parsed.questionEndOffset)
		val out = ByteArrayOutputStream(parsed.questionEndOffset + 4)
		val rdBit = query[2].toInt() and 0x01
		val cdBit = query[3].toInt() and 0x10

		out.write(query[0].toInt())
		out.write(query[1].toInt())
		out.write(0x80 or rdBit)
		out.write(0x80 or cdBit)
		out.write(0x00)
		out.write(0x01)
		out.write(ByteArray(6))
		out.write(qSection)

		return out.toByteArray()
	}

	fun createProtectedHttpClient(
		protectSocket: (Socket) -> Boolean,
		protectDatagram: ((DatagramSocket) -> Boolean)? = null,
	): OkHttpClient {
		val factory = object : SocketFactory() {
			private val _delegate = getDefault()

			override fun createSocket(): Socket {
				return _delegate.createSocket().also { protectSocket(it) }
			}

			override fun createSocket(host: String, port: Int): Socket {
				return _delegate.createSocket().also {
					protectSocket(it)
					it.connect(InetSocketAddress(host, port), 8000)
				}
			}

			override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
				return _delegate.createSocket().also {
					protectSocket(it)
					it.bind(InetSocketAddress(localHost, localPort))
					it.connect(InetSocketAddress(host, port), 8000)
				}
			}

			override fun createSocket(host: InetAddress, port: Int): Socket {
				return _delegate.createSocket().also {
					protectSocket(it)
					it.connect(InetSocketAddress(host, port), 8000)
				}
			}

			override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
				return _delegate.createSocket().also {
					protectSocket(it)
					it.bind(InetSocketAddress(localAddress, localPort))
					it.connect(InetSocketAddress(address, port), 8000)
				}
			}
		}

		// Bypass Android netd/VPN DNS for DoH endpoint hostnames to prevent recursive lookup deadlock
		val bootstrapDns = object : Dns {
			override fun lookup(hostname: String): List<InetAddress> {
				val clean = RuleEngine.normalizeHost(hostname)
				DOH_BOOTSTRAP_IPS[clean]?.let { ips ->
					return ips.map { InetAddress.getByName(it) }
				}
				if (CertAuthority.isIpLiteral(clean))
					return listOf(InetAddress.getByName(clean))

				if (protectDatagram != null) {
					val resolved = resolveIpv4ViaProtectedUdp(clean, "1.1.1.1", 2500, protectDatagram, protectSocket)
						.ifEmpty { resolveIpv4ViaProtectedUdp(clean, "8.8.8.8", 2500, protectDatagram, protectSocket) }
					if (resolved.isNotEmpty())
						return resolved
				}

				return Dns.SYSTEM.lookup(clean)
			}
		}

		return OkHttpClient.Builder()
			.socketFactory(factory)
			.dns(bootstrapDns)
			.connectTimeout(3500, TimeUnit.MILLISECONDS)
			.readTimeout(3500, TimeUnit.MILLISECONDS)
			.build()
	}

	fun resolveHostForProxy(
		host: String,
		primaryDns: String,
		secondaryDns: String,
		dohUrl: String?,
		dohClient: OkHttpClient,
		protectDatagram: (DatagramSocket) -> Boolean,
		cache: LruCache<String, CachedDns>,
		timeoutMs: Int,
		cacheTtlSec: Int,
		protectSocket: ((Socket) -> Boolean)? = null,
		isStrictDoh: Boolean = false,
	): InetAddress? {
		val clean = RuleEngine.normalizeHost(host)
		if (clean.isEmpty())
			return null
		if (CertAuthority.isIpLiteral(clean))
			return runCatching { InetAddress.getByName(clean) }.getOrNull()

		val queryWire = buildDnsQueryWire(clean, TYPE_A)
		val parsed = parseDnsQuery(queryWire) ?: return null
		val resp = resolveUpstream(
			rawQuery = queryWire,
			parsed = parsed,
			primaryDns = primaryDns,
			secondaryDns = secondaryDns,
			dohUrl = dohUrl,
			dohClient = dohClient,
			protectDatagram = protectDatagram,
			cache = cache,
			timeoutMs = timeoutMs,
			cacheTtlSec = cacheTtlSec,
			protectSocket = protectSocket,
			isStrictDoh = isStrictDoh,
		) ?: return null

		val insp = inspectDnsAnswer(resp, clean, 8)
		val firstIp = insp.ipv4Addresses.firstOrNull() ?: return null
		val addrBytes = parseIpv4Bytes(firstIp) ?: return null

		return runCatching { InetAddress.getByAddress(clean, addrBytes) }.getOrNull()
	}

	internal fun buildDnsQueryWire(host: String, qtype: Int): ByteArray {
		val asciiHost = RuleEngine.normalizeHost(host)
		val out = ByteArrayOutputStream(asciiHost.length + 20)
		val txId = (System.nanoTime() and 0xFFFFL).toInt()
		out.write((txId ushr 8) and 0xFF)
		out.write(txId and 0xFF)
		out.write(0x01)
		out.write(0x00)
		out.write(0x00)
		out.write(0x01)
		out.write(ByteArray(6))

		for (lbl in asciiHost.split('.')) {
			if (lbl.isEmpty())
				continue
			val bytes = lbl.toByteArray(Charsets.ISO_8859_1)
			out.write(bytes.size.coerceAtMost(63))
			out.write(bytes, 0, bytes.size.coerceAtMost(63))
		}
		out.write(0x00)
		out.write((qtype ushr 8) and 0xFF)
		out.write(qtype and 0xFF)
		out.write(0x00)
		out.write(0x01)

		return out.toByteArray()
	}

	private fun resolveIpv4ViaProtectedUdp(
		host: String,
		dnsIp: String,
		timeoutMs: Int,
		protectDatagram: (DatagramSocket) -> Boolean,
		protectSocket: ((Socket) -> Boolean)? = null,
	): List<InetAddress> {
		val q = buildDnsQueryWire(host, TYPE_A)
		val resp = queryDnsSingle(q, dnsIp, timeoutMs, protectDatagram, protectSocket) ?: return emptyList()
		val insp = inspectDnsAnswer(resp, host, 4)

		return insp.ipv4Addresses.mapNotNull { ip ->
			val b = parseIpv4Bytes(ip) ?: return@mapNotNull null
			runCatching { InetAddress.getByAddress(host, b) }.getOrNull()
		}
	}

	private fun parseIpv4Bytes(ip: String): ByteArray? {
		val parts = ip.split('.')
		if (parts.size != 4)
			return null
		val out = ByteArray(4)
		for (i in 0..3) {
			val v = parts[i].toIntOrNull() ?: return null
			if (v !in 0..255)
				return null
			out[i] = v.toByte()
		}

		return out
	}

	fun resolveUpstream(
		rawQuery: ByteArray,
		parsed: ParsedDnsQuery,
		primaryDns: String,
		secondaryDns: String,
		dohUrl: String?,
		dohClient: OkHttpClient,
		protectDatagram: (DatagramSocket) -> Boolean,
		cache: LruCache<String, CachedDns>,
		timeoutMs: Int = 3500,
		cacheTtlSec: Int = 90,
		protectSocket: ((Socket) -> Boolean)? = null,
		isStrictDoh: Boolean = false,
	): ByteArray? {
		val cacheKey = "${parsed.qname}:${parsed.qtype}:${parsed.qclass}"
		val now = System.currentTimeMillis()
		getCachedDnsWire(cache, cacheKey, rawQuery, now)?.let { return it }

		var resp: ByteArray? = null
		if (dohUrl != null) {
			resp = runCatching {
				val req = Request.Builder()
					.url(dohUrl)
					.header("Accept", "application/dns-message")
					.post(rawQuery.toRequestBody(DNS_MEDIA_TYPE))
					.build()
				dohClient.newCall(req).execute().use { r ->
					if (r.isSuccessful) r.body?.bytes() else null
				}
			}.getOrNull()
			if (resp == null && isStrictDoh)
				return null
		}

		val clampedTimeout = timeoutMs.coerceIn(500, 15_000)
		if (resp == null && primaryDns.isNotBlank())
			resp = queryDnsSingle(rawQuery, primaryDns, clampedTimeout, protectDatagram, protectSocket)
		if (resp == null && secondaryDns.isNotBlank() && secondaryDns != primaryDns)
			resp = queryDnsSingle(rawQuery, secondaryDns, clampedTimeout, protectDatagram, protectSocket)

		if (resp != null)
			storeDnsCacheEntry(cache, cacheKey, resp, now, cacheTtlSec)

		return resp
	}

	internal fun getCachedDnsWire(
		cache: LruCache<String, CachedDns>,
		cacheKey: String,
		rawQuery: ByteArray,
		now: Long = System.currentTimeMillis(),
	): ByteArray? {
		val hit = cache.get(cacheKey) ?: return null
		if (hit.expiresAt <= now || hit.wire.size < 12)
			return null

		val copy = hit.wire.copyOf()
		copy[0] = rawQuery[0]
		copy[1] = rawQuery[1]

		return copy
	}

	internal fun storeDnsCacheEntry(
		cache: LruCache<String, CachedDns>,
		cacheKey: String,
		resp: ByteArray,
		now: Long = System.currentTimeMillis(),
		cacheTtlSec: Int = 90,
	) {
		if (resp.size < 12)
			return
		val rcode = resp[3].toInt() and 0x0F
		if (rcode != 0 && rcode != 3)
			return

		val maxCfgSec = cacheTtlSec.coerceIn(5, 3600)
		val effectiveSec = if (rcode == 3) {
			minOf(30, maxCfgSec)
		} else {
			val ans = inspectDnsAnswer(resp, maxCnames = 0, isRecordIpMapping = false)
			if (ans.minTtlSec > 0) minOf(ans.minTtlSec.coerceAtLeast(5), maxCfgSec) else maxCfgSec
		}
		cache.put(cacheKey, CachedDns(resp.copyOf(), now + effectiveSec * 1000L))
	}

	private fun queryDnsSingle(
		rawQuery: ByteArray,
		dnsIp: String,
		timeoutMs: Int,
		protectDatagram: (DatagramSocket) -> Boolean,
		protectSocket: ((Socket) -> Boolean)?,
	): ByteArray? {
		if (rawQuery.size < 12)
			return null
		val udpResp = queryUdpSingle(rawQuery, dnsIp, timeoutMs, protectDatagram)
		if (udpResp != null && udpResp.size >= 12) {
			val isTruncated = (udpResp[2].toInt() and 0x02) != 0
			if (!isTruncated)
				return udpResp
			val tcpFull = queryTcpSingle(rawQuery, dnsIp, timeoutMs, protectSocket)
			return tcpFull ?: udpResp
		}

		return queryTcpSingle(rawQuery, dnsIp, timeoutMs, protectSocket)
	}

	private fun queryUdpSingle(
		rawQuery: ByteArray,
		dnsIp: String,
		timeoutMs: Int,
		protectDatagram: (DatagramSocket) -> Boolean,
	): ByteArray? {
		return runCatching {
			DatagramSocket().use { sock ->
				protectDatagram(sock)
				val dst = InetAddress.getByName(dnsIp)
				sock.connect(dst, 53)
				val deadline = System.currentTimeMillis() + timeoutMs
				sock.send(DatagramPacket(rawQuery, rawQuery.size, dst, 53))
				val buf = ByteArray(4096)
				val pkt = DatagramPacket(buf, buf.size)
				while (true) {
					val rem = (deadline - System.currentTimeMillis()).toInt()
					if (rem <= 0)
						return null
					sock.soTimeout = rem
					try {
						sock.receive(pkt)
					} catch (_: SocketTimeoutException) {
						return null
					}
					if (pkt.length >= 12 && buf[0] == rawQuery[0] && buf[1] == rawQuery[1])
						return buf.copyOf(pkt.length)
				}
				@Suppress("UNREACHABLE_CODE")
				null
			}
		}.getOrNull()
	}

	// RFC 1035 section 4.2.2 DNS-over-TCP 2-byte big-endian message length framing
	private fun queryTcpSingle(
		rawQuery: ByteArray,
		dnsIp: String,
		timeoutMs: Int,
		protectSocket: ((Socket) -> Boolean)?,
	): ByteArray? {
		if (protectSocket == null)
			return null

		return runCatching {
			Socket().use { sock ->
				protectSocket(sock)
				sock.tcpNoDelay = true
				sock.soTimeout = timeoutMs
				sock.connect(InetSocketAddress(InetAddress.getByName(dnsIp), 53), timeoutMs)
				val out = DataOutputStream(sock.getOutputStream())
				out.writeShort(rawQuery.size)
				out.write(rawQuery)
				out.flush()

				val inp = DataInputStream(sock.getInputStream())
				val respLen = inp.readUnsignedShort()
				if (respLen !in 12..65_535)
					return null
				val resp = ByteArray(respLen)
				inp.readFully(resp)
				if (resp[0] == rawQuery[0] && resp[1] == rawQuery[1]) resp else null
			}
		}.getOrNull()
	}
}

data class CachedDns(
	val wire: ByteArray,
	val expiresAt: Long,
)
