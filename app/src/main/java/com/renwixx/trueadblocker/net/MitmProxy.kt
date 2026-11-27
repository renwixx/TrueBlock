package com.renwixx.trueadblocker.net

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.system.OsConstants
import com.renwixx.trueadblocker.data.AppConfig
import com.renwixx.trueadblocker.data.AppPrefs
import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.data.TrafficPipeline
import com.renwixx.trueadblocker.data.TrafficSample
import com.renwixx.trueadblocker.engine.PrivacySanitizer
import com.renwixx.trueadblocker.engine.RuleEngine
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.Charset
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private class PinnedHostEntry(
	val host: String,
	var failCount: Int,
	var bypassUntilMs: Long,
)

class MitmProxy(
	private val _engine: RuleEngine,
	private val _ca: CertAuthority,
	private val _prefs: AppPrefs,
	private val _traffic: TrafficPipeline,
	private val _cm: ConnectivityManager?,
	private val _pm: PackageManager?,
	private val _protectSocket: (Socket) -> Boolean,
	private val _transportProvider: () -> Pair<Boolean, Boolean> = { false to false },
	private val _onBlockedHit: () -> Unit = {},
	private val _resolveHostIp: ((String) -> InetAddress?)? = null,
) {
	@Volatile
	private var _serverSocket: ServerSocket? = null

	@Volatile
	private var _isRunning = false

	private var _pool: ExecutorService? = null
	private val _pinnedBypassMap: MutableMap<String, PinnedHostEntry> = Collections.synchronizedMap(
		object : LinkedHashMap<String, PinnedHostEntry>(64, 0.75f, true) {
			override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, PinnedHostEntry>?): Boolean = size > 1024
		}
	)

	val port: Int
		get() = _serverSocket?.localPort ?: 0

	fun pinnedHostsSnapshot(): Set<String> {
		val now = System.currentTimeMillis()
		val out = LinkedHashSet<String>()
		synchronized(_pinnedBypassMap) {
			val it = _pinnedBypassMap.values.iterator()
			while (it.hasNext()) {
				val entry = it.next()
				if (entry.bypassUntilMs > now)
					out.add(entry.host)
				else if (entry.bypassUntilMs > 0L)
					it.remove()
			}
		}

		return out
	}

	fun clearPinnedHosts() {
		_pinnedBypassMap.clear()
	}

	private fun isHostPinnedForApp(appPkg: String, host: String): Boolean {
		val key = "$appPkg|$host"
		val now = System.currentTimeMillis()
		synchronized(_pinnedBypassMap) {
			val entry = _pinnedBypassMap[key] ?: return false
			if (entry.bypassUntilMs > now)
				return true
			if (entry.bypassUntilMs > 0L)
				_pinnedBypassMap.remove(key)
		}

		return false
	}

	private fun recordTlsHandshakeFailure(appPkg: String, host: String, err: SSLException) {
		if (!_ca.status.value.isInstalledInSystem)
			return
		val msg = (err.message ?: "").lowercase()
		val isTransientIo = msg.contains("closed") ||
			msg.contains("broken pipe") ||
			msg.contains("reset") ||
			msg.contains("timed out") ||
			msg.contains("eof")
		if (isTransientIo && err !is SSLHandshakeException)
			return

		val key = "$appPkg|$host"
		val now = System.currentTimeMillis()
		synchronized(_pinnedBypassMap) {
			val entry = _pinnedBypassMap.getOrPut(key) { PinnedHostEntry(host, 0, 0L) }
			entry.failCount++
			if (entry.failCount >= 2)
				entry.bypassUntilMs = now + PINNED_BYPASS_TTL_MS
		}
	}

	private fun clearTlsHandshakeFailures(appPkg: String, host: String) {
		_pinnedBypassMap.remove("$appPkg|$host")
	}

	@Synchronized
	fun start(): Int {
		if (_isRunning && _serverSocket != null)
			return port

		val srv = ServerSocket(0, 256, InetAddress.getByName("127.0.0.1"))
		_serverSocket = srv
		_isRunning = true

		val exec = ThreadPoolExecutor(
			4,
			384,
			60L,
			TimeUnit.SECONDS,
			SynchronousQueue(),
		)
		_pool = exec
		exec.execute {
			while (_isRunning) {
				val client = runCatching { srv.accept() }.getOrNull() ?: break
				val isSubmitted = runCatching {
					exec.execute {
						runCatching { handleClient(client) }
						runCatching { client.close() }
					}
					true
				}.getOrDefault(false)
				if (!isSubmitted)
					runCatching { client.close() }
			}
		}

		return srv.localPort
	}

	@Synchronized
	fun stop() {
		_isRunning = false
		runCatching { _serverSocket?.close() }
		_serverSocket = null
		_pool?.shutdownNow()
		_pool = null
	}

	private fun resolveOwnerPkg(client: Socket, bypassedApps: Set<String>): String {
		val cm = _cm ?: return ""
		val pm = _pm ?: return ""
		val localPort = _serverSocket?.localPort ?: return ""
		return runCatching {
			val clientSide = InetSocketAddress("127.0.0.1", client.port)
			val serverSide = InetSocketAddress("127.0.0.1", localPort)
			val uid = cm.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, clientSide, serverSide)
			if (uid <= 0)
				return ""
			val pkgs = pm.getPackagesForUid(uid) ?: return ""
			pkgs.firstOrNull { bypassedApps.contains(it) } ?: pkgs.firstOrNull() ?: ""
		}.getOrDefault("")
	}

	private fun isForbiddenTarget(host: String, targetPort: Int, cfg: AppConfig): Boolean {
		if (host.isEmpty() || targetPort !in 1..65535)
			return true
		if (host == "localhost" || host == "0.0.0.0" || host == "::1" || host == "::" || host.startsWith("127."))
			return true
		if (host == cfg.vpnClientIp.trim() || host == cfg.vpnDnsIp.trim())
			return true
		val ownPort = port
		if (ownPort > 0 && targetPort == ownPort && (host == "127.0.0.1" || host == "localhost"))
			return true

		return false
	}

	private fun handleClient(client: Socket) {
		val cfg = _prefs.state.value
		client.soTimeout = cfg.proxyReadTimeoutMs
		client.tcpNoDelay = true
		client.keepAlive = true
		val appPkg = resolveOwnerPkg(client, cfg.bypassedApps)
		val input = client.getInputStream()
		val output = BufferedOutputStream(client.getOutputStream(), 16 * 1024)

		val firstHead = readHttpHeaderBlock(input) ?: return
		if (cfg.isAppBypassed(appPkg)) {
			handleBypassedClient(client, firstHead, BufferedInputStream(input, 16 * 1024), output, cfg)
			return
		}

		if (firstHead.method.equals("CONNECT", ignoreCase = true)) {
			handleConnect(client, firstHead, appPkg, output)
		} else {
			handleHttpSession(
				clientSocket = client,
				firstReq = firstHead,
				clientIn = BufferedInputStream(input, 16 * 1024),
				clientOut = output,
				isTls = false,
				fixedHost = "",
				fixedPort = 80,
				appPkg = appPkg,
			)
		}
	}

	private fun handleBypassedClient(
		client: Socket,
		firstHead: ParsedHttpHead,
		clientIn: InputStream,
		clientOut: BufferedOutputStream,
		cfg: AppConfig,
	) {
		if (firstHead.method.equals("CONNECT", ignoreCase = true)) {
			val hp = parseHostPort(firstHead.target, 443)
			val host = RuleEngine.normalizeHost(hp.first)
			if (isForbiddenTarget(host, hp.second, cfg))
				return
			val upstream = openOutboundSocket(null, host, hp.second, cfg) ?: return
			upstream.use { up ->
				clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
				clientOut.flush()
				pipeBidirectional(client, up)
			}
			return
		}

		var currentReq: ParsedHttpHead? = firstHead
		var upstreamSock: Socket? = null
		var upIn: InputStream? = null
		var upOut: BufferedOutputStream? = null
		var upstreamKey = ""
		try {
			while (currentReq != null) {
				val req = currentReq
				val parsedTarget = extractHostAndPath(req.target, req.header("host"), "", 80, false)
				val host = parsedTarget.host
				val dstPort = parsedTarget.port
				if (isForbiddenTarget(host, dstPort, cfg))
					break

				val nextKey = "$host:$dstPort"
				if (upstreamSock == null || upstreamSock.isClosed || !upstreamSock.isConnected || upstreamKey != nextKey) {
					runCatching { upstreamSock?.close() }
					upstreamSock = openOutboundSocket(null, host, dstPort, cfg)
					upIn = upstreamSock?.getInputStream()?.let { BufferedInputStream(it, 16 * 1024) }
					upOut = upstreamSock?.getOutputStream()?.let { BufferedOutputStream(it, 16 * 1024) }
					upstreamKey = nextKey
				}

				val up = upstreamSock ?: break
				val curUpIn = upIn ?: break
				val curUpOut = upOut ?: break

				writeForwardedRequestHead(
					req = req,
					pathAndQuery = parsedTarget.pathAndQuery,
					host = host,
					port = dstPort,
					isTls = false,
					isForceGzipOnly = false,
					isForwardHttpProxy = false,
					proxyAuthHeader = "",
					upOut = curUpOut,
				)
				if (!forwardRequestBody(req, clientIn, curUpOut))
					break
				curUpOut.flush()

				var respHead = readHttpHeaderBlock(curUpIn) ?: break
				while (respHead.statusCode in 100..199 && respHead.statusCode != 101) {
					clientOut.write(respHead.rawBytes)
					clientOut.flush()
					respHead = readHttpHeaderBlock(curUpIn) ?: return
				}

				if (req.header("upgrade").equals("websocket", ignoreCase = true) && respHead.statusCode == 101) {
					clientOut.write(respHead.rawBytes)
					clientOut.flush()
					runCatching {
						client.soTimeout = 0
						up.soTimeout = 0
					}
					pipeStreamsBidirectional(clientIn, clientOut, curUpIn, curUpOut)
					break
				}

				clientOut.write(respHead.rawBytes)
				clientOut.flush()
				val isRespKeepAlive = forwardResponseBody(req.method, respHead, curUpIn, clientOut)
				clientOut.flush()

				if (!isRespKeepAlive || req.header("connection").contains("close", ignoreCase = true))
					break

				currentReq = readHttpHeaderBlock(clientIn)
			}
		} finally {
			runCatching { upstreamSock?.close() }
		}
	}

	private fun handleConnect(
		client: Socket,
		connectReq: ParsedHttpHead,
		appPkg: String,
		clientOut: BufferedOutputStream,
	) {
		val hostPort = parseHostPort(connectReq.target, 443)
		val host = RuleEngine.normalizeHost(hostPort.first)
		val dstPort = hostPort.second
		val cfg = _prefs.state.value
		if (isForbiddenTarget(host, dstPort, cfg)) {
			clientOut.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray())
			clientOut.flush()
			return
		}

		val (isWifi, isMobile) = _transportProvider()
		if (cfg.isAppFirewalled(appPkg, isWifi, isMobile)) {
			_onBlockedHit()
			_traffic.push(
				TrafficSample(
					target = host,
					host = host,
					proto = "HTTPS",
					isBlocked = true,
					isRoute = false,
					appPkg = appPkg,
					matchedRule = "Per-App Firewall",
				)
			)
			clientOut.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray())
			clientOut.flush()
			return
		}

		val domainVerdict = _engine.matchDns(host)
		if (domainVerdict.isBlocked) {
			_onBlockedHit()
			_traffic.push(
				TrafficSample(
					target = host,
					host = host,
					proto = "HTTPS",
					isBlocked = true,
					isRoute = false,
					appPkg = appPkg,
					matchedRule = domainVerdict.summaryText(),
				)
			)
			clientOut.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray())
			clientOut.flush()
			return
		}

		val isAppSelected = appPkg.isNotEmpty() && cfg.httpsInspectedApps.contains(appPkg)
		val isShouldMitm = cfg.isHttpsFiltering &&
			_ca.isReady &&
			dstPort == 443 &&
			isAppSelected &&
			!isHostPinnedForApp(appPkg, host)

		if (!isShouldMitm) {
			val matchedProxy = UpstreamProxy.selectProxy(cfg.proxies, appPkg, host, dstPort, cfg.bypassedApps)
			val ruleLabel = if (matchedProxy != null) "Proxy: ${matchedProxy.name}" else domainVerdict.summaryText()
			_traffic.push(
				TrafficSample(
					target = host,
					host = host,
					proto = "HTTPS",
					isBlocked = false,
					isRoute = false,
					appPkg = appPkg,
					matchedRule = ruleLabel,
				)
			)
			val upstream = openOutboundSocket(matchedProxy, host, dstPort, cfg) ?: return
			upstream.use { up ->
				clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
				clientOut.flush()
				pipeBidirectional(client, up)
			}
			return
		}

		clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
		clientOut.flush()

		val sslCtx = runCatching { _ca.sslContextForHost(host, cfg.leafCertValidityDays) }.getOrNull() ?: return
		val tlsServer = sslCtx.socketFactory.createSocket(
			client,
			host,
			client.port,
			true,
		) as SSLSocket

		tlsServer.useClientMode = false
		tlsServer.sslParameters = tlsServer.sslParameters.apply {
			applicationProtocols = arrayOf("http/1.1")
		}

		try {
			tlsServer.startHandshake()
			clearTlsHandshakeFailures(appPkg, host)
		} catch (sslErr: SSLException) {
			recordTlsHandshakeFailure(appPkg, host, sslErr)
			return
		}

		val tlsIn = BufferedInputStream(tlsServer.inputStream, 16 * 1024)
		val tlsOut = BufferedOutputStream(tlsServer.outputStream, 16 * 1024)
		val firstInner = readHttpHeaderBlock(tlsIn) ?: return

		handleHttpSession(
			clientSocket = tlsServer,
			firstReq = firstInner,
			clientIn = tlsIn,
			clientOut = tlsOut,
			isTls = true,
			fixedHost = host,
			fixedPort = dstPort,
			appPkg = appPkg,
		)
	}

	private fun handleHttpSession(
		clientSocket: Socket,
		firstReq: ParsedHttpHead,
		clientIn: InputStream,
		clientOut: BufferedOutputStream,
		isTls: Boolean,
		fixedHost: String,
		fixedPort: Int,
		appPkg: String,
	) {
		var currentReq: ParsedHttpHead? = firstReq
		var upstreamSock: Socket? = null
		var upIn: InputStream? = null
		var upOut: BufferedOutputStream? = null
		var upstreamKey = ""
		var isUpstreamForwardHttpProxy = false

		try {
			while (currentReq != null) {
				val req = currentReq
				val hostHeader = req.header("host")
				val parsedTarget = extractHostAndPath(req.target, hostHeader, fixedHost, fixedPort, isTls)
				val host = parsedTarget.host
				val dstPort = parsedTarget.port
				val rawPathAndQuery = parsedTarget.pathAndQuery
				val cfg = _prefs.state.value
				if (isForbiddenTarget(host, dstPort, cfg))
					break

				val (isWifi, isMobile) = _transportProvider()
				val isWs = req.header("upgrade").equals("websocket", ignoreCase = true)
				val scheme = when {
					isWs && isTls -> "wss"
					isWs -> "ws"
					isTls -> "https"
					else -> "http"
				}
				val protoLabel = scheme.uppercase()

				if (cfg.isAppFirewalled(appPkg, isWifi, isMobile)) {
					_onBlockedHit()
					_traffic.push(
						TrafficSample(
							target = host,
							host = host,
							proto = protoLabel,
							isBlocked = true,
							isRoute = false,
							appPkg = appPkg,
							matchedRule = "Per-App Firewall",
						)
					)
					clientOut.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray())
					clientOut.flush()
					break
				}

				val fullUrl = "$scheme://$host$rawPathAndQuery"
				val reqTypeMask = RuleEngine.classifyRequestTypeMask(
					method = req.method,
					pathAndQuery = rawPathAndQuery,
					acceptHeader = req.header("accept"),
					secDest = req.header("sec-fetch-dest"),
					isWebSocket = isWs,
				)
				val isThirdParty = detectIsThirdParty(req, host)
				val verdict = _engine.matchUrl(fullUrl, host, rawPathAndQuery, isWs, reqTypeMask, isThirdParty)

				var effectivePath = rawPathAndQuery
				var sanitizedNote = ""
				if (!verdict.isBlocked && !isWs && cfg.isRemoveTrackParams && rawPathAndQuery.contains('?')) {
					val san = PrivacySanitizer.sanitizePathAndQuery(
						pathAndQuery = rawPathAndQuery,
						userRulesText = cfg.trackedParamRules,
						extraExactParams = _engine.listRemoveParams(),
					)
					if (san.removedParams.isNotEmpty()) {
						effectivePath = san.cleanedPathAndQuery
						_traffic.pushRemovedParams(host, san.removedParams)
						sanitizedNote = "Stripped: ${san.removedParams.joinToString(", ")}"
					}
				}

				val matchedProxy = if (!verdict.isBlocked) UpstreamProxy.selectProxy(cfg.proxies, appPkg, host, dstPort, cfg.bypassedApps) else null
				val ruleInfo = when {
					verdict.summaryText().isNotEmpty() -> verdict.summaryText()
					matchedProxy != null && sanitizedNote.isNotEmpty() -> "Proxy: ${matchedProxy.name} • $sanitizedNote"
					matchedProxy != null -> "Proxy: ${matchedProxy.name}"
					else -> sanitizedNote
				}

				val logTarget = if (effectivePath == "/" || effectivePath.isEmpty()) host else "$host${effectivePath.take(320)}"
				val isRouteTarget = effectivePath.length > 1 || rawPathAndQuery.length > 1
				if (verdict.isBlocked) {
					_onBlockedHit()
					val (blkCat, blkExt) = classifyResponseType(
						pathAndQuery = effectivePath,
						contentTypeHeader = "",
						contentDisposition = "",
						secDest = req.header("sec-fetch-dest"),
						acceptHeader = req.header("accept"),
					)
					_traffic.push(
						TrafficSample(
							target = logTarget,
							host = host,
							proto = protoLabel,
							isBlocked = true,
							isRoute = isRouteTarget,
							appPkg = appPkg,
							matchedRule = ruleInfo,
							contentType = blkCat,
							fileExt = blkExt,
						)
					)
					if (isWs) {
						writeNoopWebSocketTermination(req, clientOut)
						break
					}
					val isDrained = drainSmallRequestBodyIfPresent(req, clientIn)
					writeNoopHttpStub(req, rawPathAndQuery, isKeepAlive = isDrained, out = clientOut)
					if (!isDrained)
						break
					currentReq = readHttpHeaderBlock(clientIn)
					continue
				}

				val nextKey = if (!isTls && matchedProxy != null && matchedProxy.type.equals("HTTP", ignoreCase = true) && isUpstreamForwardHttpProxy) {
					"fwd_http:${matchedProxy.id}"
				} else {
					"$host:$dstPort:${matchedProxy?.id ?: "direct"}"
				}

				var isReusedSocket = true
				if (upstreamSock == null || upstreamSock.isClosed || !upstreamSock.isConnected || upstreamKey != nextKey) {
					runCatching { upstreamSock?.close() }
					isUpstreamForwardHttpProxy = false
					upstreamSock = if (isTls) {
						openUpstreamTlsSocket(matchedProxy, host, dstPort, cfg)
					} else {
						val tunneled = openOutboundSocket(matchedProxy, host, dstPort, cfg)
						if (tunneled != null) {
							tunneled
						} else if (matchedProxy != null && matchedProxy.type.equals("HTTP", ignoreCase = true) && !isWs) {
							isUpstreamForwardHttpProxy = true
							UpstreamProxy.openRawHttpProxyServerSocket(
								profile = matchedProxy,
								connectTimeoutMs = cfg.proxyConnectTimeoutMs,
								readTimeoutMs = cfg.proxyReadTimeoutMs,
								protectSocket = _protectSocket,
								resolveHost = _resolveHostIp,
							)
						} else {
							null
						}
					}
					upIn = upstreamSock?.getInputStream()?.let { BufferedInputStream(it, 16 * 1024) }
					upOut = upstreamSock?.getOutputStream()?.let { BufferedOutputStream(it, 16 * 1024) }
					upstreamKey = if (isUpstreamForwardHttpProxy && matchedProxy != null) "fwd_http:${matchedProxy.id}" else "$host:$dstPort:${matchedProxy?.id ?: "direct"}"
					isReusedSocket = false
				}

				var up = upstreamSock ?: break
				var curUpIn = upIn ?: break
				var curUpOut = upOut ?: break

				val cosmeticCss = if (
					cfg.isCosmeticFiltering &&
					!isWs &&
					req.method.equals("GET", ignoreCase = true) &&
					isLikelyHtmlNavigation(req)
				) {
					_engine.cosmeticCssForHost(host, cfg.maxGenericCosmeticSelectors, cfg.customCosmeticCss)
				} else {
					""
				}

				val isForceGzip = cosmeticCss.isNotEmpty() && clientAcceptsGzip(req)
				val isStripAeForCosmetic = cosmeticCss.isNotEmpty() && !isForceGzip
				val proxyAuthVal = if (isUpstreamForwardHttpProxy && matchedProxy != null) UpstreamProxy.buildBasicProxyAuthHeader(matchedProxy) else ""

				writeForwardedRequestHead(
					req = req,
					pathAndQuery = effectivePath,
					host = host,
					port = dstPort,
					isTls = isTls,
					isForceGzipOnly = isForceGzip,
					isStripAcceptEncoding = isStripAeForCosmetic,
					isForwardHttpProxy = isUpstreamForwardHttpProxy,
					proxyAuthHeader = proxyAuthVal,
					upOut = curUpOut,
				)
				if (!forwardRequestBody(req, clientIn, curUpOut))
					break
				curUpOut.flush()

				var respHead = readHttpHeaderBlock(curUpIn)
				val isRetryableNoBody = isReusedSocket &&
					respHead == null &&
					(req.method.equals("GET", ignoreCase = true) || req.method.equals("HEAD", ignoreCase = true)) &&
					(req.header("content-length").toLongOrNull() ?: 0L) == 0L &&
					!req.header("transfer-encoding").contains("chunked", ignoreCase = true)

				if (isRetryableNoBody) {
					runCatching { upstreamSock?.close() }
					isUpstreamForwardHttpProxy = false
					upstreamSock = if (isTls) {
						openUpstreamTlsSocket(matchedProxy, host, dstPort, cfg)
					} else {
						val tunneled = openOutboundSocket(matchedProxy, host, dstPort, cfg)
						if (tunneled != null) {
							tunneled
						} else if (matchedProxy != null && matchedProxy.type.equals("HTTP", ignoreCase = true) && !isWs) {
							isUpstreamForwardHttpProxy = true
							UpstreamProxy.openRawHttpProxyServerSocket(
								profile = matchedProxy,
								connectTimeoutMs = cfg.proxyConnectTimeoutMs,
								readTimeoutMs = cfg.proxyReadTimeoutMs,
								protectSocket = _protectSocket,
								resolveHost = _resolveHostIp,
							)
						} else {
							null
						}
					}
					up = upstreamSock ?: break
					curUpIn = up.getInputStream().let { BufferedInputStream(it, 16 * 1024) }.also { upIn = it }
					curUpOut = up.getOutputStream().let { BufferedOutputStream(it, 16 * 1024) }.also { upOut = it }
					val retryProxyAuth = if (isUpstreamForwardHttpProxy && matchedProxy != null) UpstreamProxy.buildBasicProxyAuthHeader(matchedProxy) else ""
					writeForwardedRequestHead(
						req = req,
						pathAndQuery = effectivePath,
						host = host,
						port = dstPort,
						isTls = isTls,
						isForceGzipOnly = isForceGzip,
						isStripAcceptEncoding = isStripAeForCosmetic,
						isForwardHttpProxy = isUpstreamForwardHttpProxy,
						proxyAuthHeader = retryProxyAuth,
						upOut = curUpOut,
					)
					curUpOut.flush()
					respHead = readHttpHeaderBlock(curUpIn)
				}

				while (respHead != null && respHead.statusCode in 100..199 && respHead.statusCode != 101) {
					clientOut.write(respHead.rawBytes)
					clientOut.flush()
					respHead = readHttpHeaderBlock(curUpIn)
				}

				val finalResp = respHead
				if (finalResp == null) {
					val (fallbackCat, fallbackExt) = classifyResponseType(
						pathAndQuery = effectivePath,
						contentTypeHeader = "",
						contentDisposition = "",
						secDest = req.header("sec-fetch-dest"),
						acceptHeader = req.header("accept"),
					)
					_traffic.push(
						TrafficSample(
							target = logTarget,
							host = host,
							proto = protoLabel,
							isBlocked = false,
							isRoute = isRouteTarget,
							appPkg = appPkg,
							matchedRule = ruleInfo,
							contentType = fallbackCat,
							fileExt = fallbackExt,
						)
					)
					break
				}

				val (respCat, respExt) = classifyResponseType(
					pathAndQuery = effectivePath,
					contentTypeHeader = finalResp.header("content-type"),
					contentDisposition = finalResp.header("content-disposition"),
					secDest = req.header("sec-fetch-dest"),
					acceptHeader = req.header("accept"),
				)
				_traffic.push(
					TrafficSample(
						target = logTarget,
						host = host,
						proto = protoLabel,
						isBlocked = false,
						isRoute = isRouteTarget,
						appPkg = appPkg,
						matchedRule = ruleInfo,
						contentType = respCat,
						fileExt = respExt,
					)
				)

				if (isWs && finalResp.statusCode == 101) {
					clientOut.write(finalResp.rawBytes)
					clientOut.flush()
					runCatching {
						clientSocket.soTimeout = 0
						up.soTimeout = 0
					}
					pipeStreamsBidirectional(clientIn, clientOut, curUpIn, curUpOut)
					break
				}

				val isRespKeepAlive = if (cosmeticCss.isNotEmpty() && isEligibleHtmlResponse(finalResp)) {
					forwardAndInjectHtmlResponse(finalResp, cosmeticCss, curUpIn, clientOut)
				} else {
					clientOut.write(finalResp.rawBytes)
					clientOut.flush()
					forwardResponseBody(req.method, finalResp, curUpIn, clientOut)
				}
				clientOut.flush()

				val clientConn = req.header("connection")
				val isClientClose = clientConn.contains("close", ignoreCase = true)
				if (!isRespKeepAlive || isClientClose)
					break

				currentReq = readHttpHeaderBlock(clientIn)
			}
		} finally {
			runCatching { upstreamSock?.close() }
		}
	}

	private fun openOutboundSocket(
		proxy: ProxyProfile?,
		host: String,
		port: Int,
		cfg: AppConfig,
	): Socket? {
		return UpstreamProxy.connectSocket(
			profile = proxy,
			targetHost = host,
			targetPort = port,
			connectTimeoutMs = cfg.proxyConnectTimeoutMs,
			readTimeoutMs = cfg.proxyReadTimeoutMs,
			protectSocket = _protectSocket,
			resolveHost = _resolveHostIp,
		)
	}

	private fun openUpstreamTlsSocket(
		proxy: ProxyProfile?,
		host: String,
		port: Int,
		cfg: AppConfig,
	): SSLSocket? {
		val plain = openOutboundSocket(proxy, host, port, cfg) ?: return null
		return try {
			val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
			val ssl = factory.createSocket(plain, host, port, true) as SSLSocket
			ssl.sslParameters = ssl.sslParameters.apply {
				endpointIdentificationAlgorithm = "HTTPS"
				if (!CertAuthority.isIpLiteral(host)) {
					runCatching { SNIHostName(host) }.getOrNull()?.let { sni ->
						serverNames = listOf(sni)
					}
				}
				applicationProtocols = arrayOf("http/1.1")
			}
			ssl.startHandshake()
			ssl
		} catch (_: Throwable) {
			runCatching { plain.close() }
			null
		}
	}

	private fun pipeBidirectional(a: Socket, b: Socket) {
		val pool = _pool ?: return
		runCatching {
			a.soTimeout = TUNNEL_IDLE_TIMEOUT_MS
			a.keepAlive = true
			b.soTimeout = TUNNEL_IDLE_TIMEOUT_MS
			b.keepAlive = true
		}
		val future = runCatching {
			pool.submit {
				runCatching {
					a.getInputStream().copyTo(b.getOutputStream(), 16 * 1024)
					b.shutdownOutput()
				}
			}
		}.getOrNull() ?: return

		runCatching {
			b.getInputStream().copyTo(a.getOutputStream(), 16 * 1024)
			a.shutdownOutput()
		}
		runCatching { future.get() }
	}

	private fun pipeStreamsBidirectional(
		clientIn: InputStream,
		clientOut: OutputStream,
		upIn: InputStream,
		upOut: OutputStream,
	) {
		val pool = _pool ?: return
		val f = runCatching {
			pool.submit {
				runCatching {
					val buf = ByteArray(8192)
					while (true) {
						val n = clientIn.read(buf)
						if (n <= 0)
							break
						upOut.write(buf, 0, n)
						upOut.flush()
					}
				}
			}
		}.getOrNull() ?: return

		runCatching {
			val buf = ByteArray(8192)
			while (true) {
				val n = upIn.read(buf)
				if (n <= 0)
					break
				clientOut.write(buf, 0, n)
				clientOut.flush()
			}
		}
		runCatching { f.cancel(true) }
	}

	companion object {
		private const val MAX_COSMETIC_HTML_BYTES = 1_572_864
		private const val TUNNEL_IDLE_TIMEOUT_MS = 300_000
		private const val PINNED_BYPASS_TTL_MS = 6L * 3_600_000L

		// Valid 42-byte 1x1 transparent GIF (uBlock noopimg resource)
		private val TRANSPARENT_GIF_1X1: ByteArray = Base64.getDecoder().decode(
			"R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
		)

		private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

		private val IMAGE_EXTS = setOf("png", "jpg", "jpeg", "webp", "gif", "svg", "ico", "avif", "bmp", "heic", "heif")
		private val VIDEO_EXTS = setOf("mp4", "webm", "m3u8", "ts", "mkv", "mov", "avi", "m4v", "flv", "3gp", "mpd")
		private val AUDIO_EXTS = setOf("mp3", "ogg", "wav", "flac", "m4a", "aac", "opus", "weba", "wma", "mid")
		private val FILE_EXTS = setOf(
			"apk", "aab", "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "pdf", "doc", "docx",
			"xls", "xlsx", "ppt", "pptx", "epub", "exe", "msi", "dmg", "iso", "bin", "deb", "rpm",
			"wasm", "ttf", "otf", "woff", "woff2", "csv", "rtf",
		)

		fun classifyResponseType(
			pathAndQuery: String,
			contentTypeHeader: String,
			contentDisposition: String = "",
			secDest: String = "",
			acceptHeader: String = "",
		): Pair<String, String> {
			val mime = contentTypeHeader.substringBefore(';').trim().lowercase()
			val dispExt = extractDispositionExt(contentDisposition)
			val pathExt = extractUrlExt(pathAndQuery)
			val mimeExt = mimeToExt(mime)
			val ext = dispExt.ifEmpty { pathExt }.ifEmpty { mimeExt }

			val isAttachment = contentDisposition.contains("attachment", ignoreCase = true)
			val category = when {
				mime.startsWith("image/") -> "image"
				mime.startsWith("video/") || mime == "application/vnd.apple.mpegurl" || mime == "application/dash+xml" -> "video"
				mime.startsWith("audio/") -> "audio"
				isAttachment || mime == "application/octet-stream" || mime == "application/pdf" ||
					mime == "application/zip" || mime == "application/x-zip-compressed" ||
					mime == "application/gzip" || mime == "application/x-7z-compressed" ||
					mime == "application/x-rar-compressed" || mime == "application/vnd.android.package-archive" ||
					mime.startsWith("font/") -> "file"
				mime.startsWith("text/") || mime == "application/json" || mime == "application/javascript" ||
					mime == "application/x-javascript" || mime == "application/xml" ||
					mime.endsWith("+json") || mime.endsWith("+xml") || mime == "application/x-www-form-urlencoded" -> "default"
				ext in IMAGE_EXTS -> "image"
				ext in VIDEO_EXTS -> "video"
				ext in AUDIO_EXTS -> "audio"
				ext in FILE_EXTS -> "file"
				secDest.equals("image", ignoreCase = true) -> "image"
				secDest.equals("video", ignoreCase = true) -> "video"
				secDest.equals("audio", ignoreCase = true) -> "audio"
				acceptHeader.startsWith("image/", ignoreCase = true) && !acceptHeader.contains("text/html", ignoreCase = true) -> "image"
				else -> "default"
			}

			return category to ext
		}

		private fun extractDispositionExt(cd: String): String {
			if (cd.isEmpty())
				return ""
			val idx = cd.indexOf("filename=", ignoreCase = true)
			if (idx < 0)
				return ""
			val raw = cd.substring(idx + 9).trim().substringBefore(';').trim('"', '\'', ' ')
			val dot = raw.lastIndexOf('.')
			if (dot < 0 || dot >= raw.lastIndex)
				return ""
			val candidate = raw.substring(dot + 1).lowercase()

			return if (candidate.length in 1..8 && candidate.all { it.isLetterOrDigit() }) candidate else ""
		}

		private fun extractUrlExt(pathAndQuery: String): String {
			val cleanPath = pathAndQuery.substringBefore('?').substringBefore('#')
			val lastSeg = cleanPath.substringAfterLast('/')
			val dot = lastSeg.lastIndexOf('.')
			if (dot <= 0 || dot >= lastSeg.lastIndex)
				return ""
			val candidate = lastSeg.substring(dot + 1).lowercase()

			return if (candidate.length in 1..8 && candidate.all { it.isLetterOrDigit() }) candidate else ""
		}

		private fun mimeToExt(mime: String): String {
			return when (mime) {
				"image/png" -> "png"
				"image/jpeg" -> "jpg"
				"image/webp" -> "webp"
				"image/gif" -> "gif"
				"image/svg+xml" -> "svg"
				"image/avif" -> "avif"
				"image/x-icon", "image/vnd.microsoft.icon" -> "ico"
				"video/mp4" -> "mp4"
				"video/webm" -> "webm"
				"video/mp2t" -> "ts"
				"application/vnd.apple.mpegurl" -> "m3u8"
				"audio/mpeg" -> "mp3"
				"audio/ogg" -> "ogg"
				"audio/wav", "audio/x-wav" -> "wav"
				"audio/aac" -> "aac"
				"audio/mp4" -> "m4a"
				"audio/flac" -> "flac"
				"application/pdf" -> "pdf"
				"application/zip", "application/x-zip-compressed" -> "zip"
				"application/gzip" -> "gz"
				"application/vnd.android.package-archive" -> "apk"
				"application/wasm" -> "wasm"
				"font/woff2" -> "woff2"
				"font/woff" -> "woff"
				"font/ttf" -> "ttf"
				else -> ""
			}
		}

		private fun detectIsThirdParty(req: ParsedHttpHead, reqHost: String): Boolean? {
			val secSite = req.header("sec-fetch-site").trim().lowercase()
			if (secSite == "cross-site")
				return true
			if (secSite == "same-origin" || secSite == "same-site" || secSite == "none")
				return false

			val refUrl = req.header("origin").ifEmpty { req.header("referer") }.trim()
			if (refUrl.isEmpty() || refUrl == "null")
				return null
			val schemeIdx = refUrl.indexOf("://")
			val afterScheme = if (schemeIdx >= 0) refUrl.substring(schemeIdx + 3) else refUrl
			val refHost = parseHostPort(afterScheme.substringBefore('/'), 443).first
			if (refHost.isEmpty())
				return null

			val reqBase = RuleEngine.extractRegistrableDomain(reqHost)
			val refBase = RuleEngine.extractRegistrableDomain(refHost)
			if (reqBase.isEmpty() || refBase.isEmpty())
				return null

			return reqBase != refBase
		}

		private fun clientAcceptsGzip(req: ParsedHttpHead): Boolean {
			val ae = req.header("accept-encoding").trim().lowercase()
			if (ae.isEmpty())
				return false
			if (ae.contains("gzip;q=0") || ae.contains("*;q=0"))
				return false

			return ae.contains("gzip") || ae.contains('*')
		}

		fun computeWebSocketAccept(secWebSocketKey: String): String {
			val sha1 = MessageDigest.getInstance("SHA-1")
				.digest((secWebSocketKey.trim() + WS_GUID).toByteArray(Charsets.ISO_8859_1))

			return Base64.getEncoder().encodeToString(sha1)
		}

		// Completes RFC 6455 handshake then immediately sends clean 1000 Normal Closure frame (uBlock noopws behavior)
		private fun writeNoopWebSocketTermination(req: ParsedHttpHead, out: OutputStream) {
			val key = req.header("sec-websocket-key")
			if (key.isEmpty()) {
				out.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray())
				out.flush()
				return
			}

			val accept = computeWebSocketAccept(key)
			val hs = buildString {
				append("HTTP/1.1 101 Switching Protocols\r\n")
				append("Upgrade: websocket\r\n")
				append("Connection: Upgrade\r\n")
				append("Sec-WebSocket-Accept: ").append(accept).append("\r\n\r\n")
			}
			out.write(hs.toByteArray(Charsets.ISO_8859_1))
			out.write(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
			out.flush()
		}

		fun selectNoopStub(method: String, pathAndQuery: String, acceptHeader: String, secDest: String): Pair<String, ByteArray>? {
			if (method.equals("OPTIONS", ignoreCase = true))
				return "text/plain" to ByteArray(0)

			val cleanPath = pathAndQuery.substringBefore('?').substringBefore('#').lowercase()
			val accept = acceptHeader.lowercase()
			val dest = secDest.lowercase()

			if (cleanPath.endsWith(".js") || cleanPath.endsWith(".mjs") || dest == "script" || accept.contains("javascript"))
				return "application/javascript; charset=utf-8" to ByteArray(0)

			if (cleanPath.endsWith(".css") || dest == "style" || accept.contains("text/css"))
				return "text/css; charset=utf-8" to ByteArray(0)

			if (
				cleanPath.endsWith(".gif") || cleanPath.endsWith(".png") || cleanPath.endsWith(".jpg") ||
				cleanPath.endsWith(".jpeg") || cleanPath.endsWith(".webp") || cleanPath.endsWith(".svg") ||
				cleanPath.endsWith(".ico") || cleanPath.endsWith(".avif") || dest == "image" || accept.startsWith("image/")
			) {
				return "image/gif" to TRANSPARENT_GIF_1X1
			}

			if (cleanPath.endsWith(".json") || accept.contains("application/json"))
				return "application/json; charset=utf-8" to "{}".toByteArray(Charsets.UTF_8)

			if (cleanPath.endsWith(".html") || cleanPath.endsWith(".htm") || dest == "iframe" || dest == "document")
				return "text/html; charset=utf-8" to "<!DOCTYPE html><html><head></head><body></body></html>".toByteArray(Charsets.UTF_8)

			if (cleanPath.endsWith(".xml") || cleanPath.endsWith(".vast"))
				return "application/xml; charset=utf-8" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VAST version=\"3.0\"/>".toByteArray(Charsets.UTF_8)

			return null
		}

		private fun isLikelyHtmlNavigation(req: ParsedHttpHead): Boolean {
			val dest = req.header("sec-fetch-dest")
			if (dest.equals("document", ignoreCase = true) || dest.equals("iframe", ignoreCase = true))
				return true

			return req.header("accept").contains("text/html", ignoreCase = true)
		}

		private fun isEligibleHtmlResponse(resp: ParsedHttpHead): Boolean {
			if (resp.statusCode != 200)
				return false
			if (!resp.header("content-type").contains("text/html", ignoreCase = true))
				return false
			val ce = resp.header("content-encoding").trim().lowercase()

			return ce.isEmpty() || ce == "identity" || ce == "gzip"
		}

		private fun detectHtmlCharset(contentType: String): Charset {
			val idx = contentType.indexOf("charset=", ignoreCase = true)
			if (idx < 0)
				return Charsets.UTF_8

			val rawName = contentType.substring(idx + 8).substringBefore(';').trim().trim('"', '\'')
			return runCatching { Charset.forName(rawName) }.getOrDefault(Charsets.UTF_8)
		}

		private fun forwardAndInjectHtmlResponse(
			respHead: ParsedHttpHead,
			cosmeticCss: String,
			upIn: InputStream,
			clientOut: OutputStream,
		): Boolean {
			val isKeepAlive = !respHead.header("connection").contains("close", ignoreCase = true)
			val ce = respHead.header("content-encoding").trim().lowercase()
			val isGzip = ce == "gzip"
			val isChunked = respHead.header("transfer-encoding").contains("chunked", ignoreCase = true)
			val clStr = respHead.header("content-length")

			if (clStr.isNotEmpty() && !isChunked) {
				val cl = clStr.toLongOrNull() ?: return false
				if (cl < 0L)
					return false
				if (cl == 0L || cl > MAX_COSMETIC_HTML_BYTES) {
					clientOut.write(respHead.rawBytes)
					val isOk = if (cl > 0L) copyExactBytes(upIn, clientOut, cl) else true
					return isOk && isKeepAlive
				}

				val rawBody = ByteArray(cl.toInt())
				if (!readExactInto(upIn, rawBody))
					return false

				val injected = PrivacySanitizer.injectCosmeticCssIntoHtml(
					rawBody = rawBody,
					isGzipEncoded = isGzip,
					cssContent = cosmeticCss,
					charset = detectHtmlCharset(respHead.header("content-type")),
				)
				if (injected != null) {
					writeRebuiltResponseHead(respHead, injected.size, isRemoveContentEncoding = true, clientOut = clientOut)
					clientOut.write(injected)
				} else {
					clientOut.write(respHead.rawBytes)
					clientOut.write(rawBody)
				}
				return isKeepAlive
			}

			if (isChunked) {
				val acc = ByteArrayOutputStream(32 * 1024)
				while (true) {
					val lineBytes = readAsciiLineCrlf(upIn) ?: return false
					val sizeHex = String(lineBytes, Charsets.ISO_8859_1).trim().substringBefore(';')
					val chunkSize = sizeHex.toLongOrNull(16) ?: return false
					if (chunkSize < 0L)
						return false

					if (chunkSize == 0L) {
						while (true) {
							val trailer = readAsciiLineCrlf(upIn) ?: return false
							if (trailer.size == 2 && trailer[0] == '\r'.code.toByte() && trailer[1] == '\n'.code.toByte())
								break
						}
						val rawBody = acc.toByteArray()
						val injected = PrivacySanitizer.injectCosmeticCssIntoHtml(
							rawBody = rawBody,
							isGzipEncoded = isGzip,
							cssContent = cosmeticCss,
							charset = detectHtmlCharset(respHead.header("content-type")),
						)
						if (injected != null) {
							writeRebuiltResponseHead(respHead, injected.size, isRemoveContentEncoding = true, clientOut = clientOut)
							clientOut.write(injected)
						} else {
							writeRebuiltResponseHead(respHead, rawBody.size, isRemoveContentEncoding = false, clientOut = clientOut)
							clientOut.write(rawBody)
						}
						return isKeepAlive
					}

					if (acc.size().toLong() + chunkSize > MAX_COSMETIC_HTML_BYTES) {
						clientOut.write(respHead.rawBytes)
						if (acc.size() > 0) {
							val buffered = acc.toByteArray()
							val chunkPrefix = "${buffered.size.toString(16)}\r\n".toByteArray(Charsets.ISO_8859_1)
							clientOut.write(chunkPrefix)
							clientOut.write(buffered)
							clientOut.write("\r\n".toByteArray(Charsets.ISO_8859_1))
						}
						clientOut.write(lineBytes)
						if (!copyExactBytes(upIn, clientOut, chunkSize + 2L))
							return false
						val isRestOk = relayChunkedBody(upIn, clientOut)
						return isRestOk && isKeepAlive
					}

					val chunkPayload = ByteArray(chunkSize.toInt())
					if (!readExactInto(upIn, chunkPayload))
						return false
					acc.write(chunkPayload)
					val crlf = ByteArray(2)
					if (!readExactInto(upIn, crlf))
						return false
				}
			}

			clientOut.write(respHead.rawBytes)
			val buf = ByteArray(16 * 1024)
			while (true) {
				val n = upIn.read(buf)
				if (n <= 0)
					break
				clientOut.write(buf, 0, n)
			}

			return false
		}

		private fun writeRebuiltResponseHead(
			respHead: ParsedHttpHead,
			newContentLength: Int,
			isRemoveContentEncoding: Boolean,
			clientOut: OutputStream,
		) {
			val firstLine = String(respHead.rawBytes, Charsets.ISO_8859_1).substringBefore("\r\n")
			val sb = StringBuilder(respHead.rawBytes.size + 32)
			sb.append(firstLine).append("\r\n")
			for ((k, v) in respHead.headers) {
				if (k.equals("content-length", ignoreCase = true) || k.equals("transfer-encoding", ignoreCase = true))
					continue
				if (isRemoveContentEncoding && k.equals("content-encoding", ignoreCase = true))
					continue
				sb.append(k).append(": ").append(v).append("\r\n")
			}
			sb.append("Content-Length: ").append(newContentLength).append("\r\n\r\n")
			clientOut.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
		}

		private fun readExactInto(src: InputStream, dst: ByteArray): Boolean {
			var off = 0
			while (off < dst.size) {
				val n = src.read(dst, off, dst.size - off)
				if (n <= 0)
					return false
				off += n
			}

			return true
		}

		private fun sanitizeHeaderToken(raw: String): String {
			return raw.replace("\r", "").replace("\n", "").trim()
		}

		private fun writeNoopHttpStub(
			req: ParsedHttpHead,
			pathAndQuery: String,
			isKeepAlive: Boolean,
			out: OutputStream,
		) {
			val connVal = if (isKeepAlive) "keep-alive" else "close"
			val rawOrigin = sanitizeHeaderToken(req.header("origin"))
			val hasSpecificOrigin = rawOrigin.isNotEmpty() && rawOrigin != "*"
			val allowOriginVal = if (hasSpecificOrigin) rawOrigin else "*"

			if (req.method.equals("OPTIONS", ignoreCase = true)) {
				val reqHeaders = sanitizeHeaderToken(req.header("access-control-request-headers")).ifEmpty { "*" }
				val hdr = buildString {
					append("HTTP/1.1 204 No Content\r\n")
					append("Access-Control-Allow-Origin: ").append(allowOriginVal).append("\r\n")
					append("Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n")
					append("Access-Control-Allow-Headers: ").append(reqHeaders).append("\r\n")
					if (hasSpecificOrigin)
						append("Access-Control-Allow-Credentials: true\r\n")
					append("Connection: ").append(connVal).append("\r\n")
					append("Content-Length: 0\r\n\r\n")
				}
				out.write(hdr.toByteArray(Charsets.ISO_8859_1))
				out.flush()
				return
			}

			val stub = selectNoopStub(
				method = req.method,
				pathAndQuery = pathAndQuery,
				acceptHeader = req.header("accept"),
				secDest = req.header("sec-fetch-dest"),
			)

			if (stub == null) {
				val hdr = buildString {
					append("HTTP/1.1 204 No Content\r\n")
					append("Access-Control-Allow-Origin: ").append(allowOriginVal).append("\r\n")
					if (hasSpecificOrigin)
						append("Access-Control-Allow-Credentials: true\r\n")
					append("Cache-Control: no-store\r\n")
					append("Connection: ").append(connVal).append("\r\n")
					append("Content-Length: 0\r\n\r\n")
				}
				out.write(hdr.toByteArray(Charsets.ISO_8859_1))
				out.flush()
				return
			}

			val body = if (req.method.equals("HEAD", ignoreCase = true)) ByteArray(0) else stub.second
			val hdr = buildString {
				append("HTTP/1.1 200 OK\r\n")
				append("Content-Type: ").append(stub.first).append("\r\n")
				append("Access-Control-Allow-Origin: ").append(allowOriginVal).append("\r\n")
				if (hasSpecificOrigin)
					append("Access-Control-Allow-Credentials: true\r\n")
				append("Cache-Control: no-store\r\n")
				append("Connection: ").append(connVal).append("\r\n")
				append("Content-Length: ").append(stub.second.size).append("\r\n\r\n")
			}
			out.write(hdr.toByteArray(Charsets.ISO_8859_1))
			if (body.isNotEmpty())
				out.write(body)
			out.flush()
		}

		private fun drainSmallRequestBodyIfPresent(req: ParsedHttpHead, input: InputStream): Boolean {
			if (req.header("transfer-encoding").contains("chunked", ignoreCase = true))
				return false
			val clStr = req.header("content-length")
			if (clStr.isEmpty())
				return true
			val cl = clStr.toLongOrNull() ?: return false
			if (cl < 0L || cl > 65_536L)
				return false
			if (cl == 0L)
				return true

			var rem = cl.toInt()
			val skipBuf = ByteArray(4096)
			while (rem > 0) {
				val n = input.read(skipBuf, 0, minOf(rem, skipBuf.size))
				if (n <= 0)
					return false
				rem -= n
			}

			return true
		}

		private fun writeForwardedRequestHead(
			req: ParsedHttpHead,
			pathAndQuery: String,
			host: String,
			port: Int,
			isTls: Boolean,
			isForceGzipOnly: Boolean,
			isStripAcceptEncoding: Boolean = false,
			isForwardHttpProxy: Boolean = false,
			proxyAuthHeader: String = "",
			upOut: OutputStream,
		) {
			val defaultPort = if (isTls) 443 else 80
			val hostAuthority = if (port == defaultPort) host else "$host:$port"
			val targetUri = if (isForwardHttpProxy) "http://$hostAuthority$pathAndQuery" else pathAndQuery

			val sb = StringBuilder(req.rawBytes.size + 64)
			sb.append(req.method).append(' ').append(targetUri).append(' ').append(req.version).append("\r\n")
			var isHostWritten = false
			var isAcceptEncWritten = false
			for ((k, v) in req.headers) {
				if (k.equals("proxy-connection", ignoreCase = true) || k.equals("proxy-authorization", ignoreCase = true))
					continue
				if (k.equals("host", ignoreCase = true))
					isHostWritten = true
				if (k.equals("accept-encoding", ignoreCase = true)) {
					if (isStripAcceptEncoding)
						continue
					if (isForceGzipOnly) {
						if (!isAcceptEncWritten) {
							sb.append("Accept-Encoding: gzip\r\n")
							isAcceptEncWritten = true
						}
						continue
					}
				}
				sb.append(k).append(": ").append(v).append("\r\n")
			}
			if (!isHostWritten)
				sb.append("Host: ").append(hostAuthority).append("\r\n")
			if (isForceGzipOnly && !isAcceptEncWritten)
				sb.append("Accept-Encoding: gzip\r\n")
			if (isForwardHttpProxy && proxyAuthHeader.isNotEmpty())
				sb.append("Proxy-Authorization: ").append(proxyAuthHeader).append("\r\n")
			sb.append("\r\n")
			upOut.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
		}

		private fun forwardRequestBody(req: ParsedHttpHead, clientIn: InputStream, upOut: OutputStream): Boolean {
			val te = req.header("transfer-encoding")
			if (te.isNotEmpty()) {
				if (!te.contains("chunked", ignoreCase = true))
					return false
				return relayChunkedBody(clientIn, upOut)
			}
			val clStr = req.header("content-length")
			if (clStr.isEmpty())
				return true
			val cl = clStr.toLongOrNull() ?: return false
			if (cl < 0L)
				return false
			if (cl == 0L)
				return true

			return copyExactBytes(clientIn, upOut, cl)
		}

		private fun forwardResponseBody(
			reqMethod: String,
			respHead: ParsedHttpHead,
			upIn: InputStream,
			clientOut: OutputStream,
		): Boolean {
			val code = respHead.statusCode
			val isConnClose = respHead.header("connection").contains("close", ignoreCase = true)
			if (reqMethod.equals("HEAD", ignoreCase = true) || code in 100..199 || code == 204 || code == 304)
				return !isConnClose

			val te = respHead.header("transfer-encoding")
			if (te.isNotEmpty()) {
				if (!te.contains("chunked", ignoreCase = true))
					return false
				val isOk = relayChunkedBody(upIn, clientOut)
				return isOk && !isConnClose && respHead.header("content-length").isEmpty()
			}

			val clStr = respHead.header("content-length")
			if (clStr.isNotEmpty()) {
				val cl = clStr.toLongOrNull() ?: return false
				if (cl < 0L)
					return false
				val isOk = copyExactBytes(upIn, clientOut, cl)
				return isOk && !isConnClose
			}

			val buf = ByteArray(16 * 1024)
			while (true) {
				val n = upIn.read(buf)
				if (n <= 0)
					break
				clientOut.write(buf, 0, n)
			}

			return false
		}

		private fun copyExactBytes(src: InputStream, dst: OutputStream, count: Long): Boolean {
			var rem = count
			val buf = ByteArray(16 * 1024)
			while (rem > 0L) {
				val toRead = minOf(rem, buf.size.toLong()).toInt()
				val n = src.read(buf, 0, toRead)
				if (n <= 0)
					return false
				dst.write(buf, 0, n)
				rem -= n
			}

			return true
		}

		private fun relayChunkedBody(src: InputStream, dst: OutputStream): Boolean {
			while (true) {
				val lineBytes = readAsciiLineCrlf(src) ?: return false
				dst.write(lineBytes)
				val sizeHex = String(lineBytes, Charsets.ISO_8859_1).trim().substringBefore(';')
				val chunkSize = sizeHex.toLongOrNull(16) ?: return false
				if (chunkSize < 0L)
					return false
				if (chunkSize == 0L) {
					while (true) {
						val trailer = readAsciiLineCrlf(src) ?: return false
						dst.write(trailer)
						if (trailer.size == 2 && trailer[0] == '\r'.code.toByte() && trailer[1] == '\n'.code.toByte())
							break
					}
					return true
				}
				if (!copyExactBytes(src, dst, chunkSize + 2L))
					return false
			}
		}

		private fun readAsciiLineCrlf(input: InputStream): ByteArray? {
			val out = ByteArrayOutputStream(64)
			var prev = -1
			while (out.size() < 8192) {
				val b = input.read()
				if (b < 0)
					return null
				out.write(b)
				if (prev == '\r'.code && b == '\n'.code)
					return out.toByteArray()
				prev = b
			}

			return null
		}

		private fun readHttpHeaderBlock(input: InputStream): ParsedHttpHead? {
			val raw = ByteArrayOutputStream(512)
			var state = 0
			while (raw.size() < 65_536) {
				val b = input.read()
				if (b < 0)
					return null
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
				return null

			val bytes = raw.toByteArray()
			val text = String(bytes, Charsets.ISO_8859_1)
			val lines = text.split("\r\n")
			if (lines.isEmpty())
				return null

			val firstParts = lines[0].split(' ', limit = 3)
			if (firstParts.size < 2)
				return null

			val headers = ArrayList<Pair<String, String>>(lines.size)
			var seenContentLength: Long? = null
			for (i in 1 until lines.size) {
				val ln = lines[i]
				if (ln.isEmpty())
					break
				val colon = ln.indexOf(':')
				if (colon <= 0)
					continue
				val key = ln.substring(0, colon).trim()
				val value = ln.substring(colon + 1).trim()
				if (key.equals("content-length", ignoreCase = true)) {
					val parsedCl = value.toLongOrNull() ?: return null
					if (parsedCl < 0L)
						return null
					if (seenContentLength != null && seenContentLength != parsedCl)
						return null
					if (seenContentLength != null)
						continue
					seenContentLength = parsedCl
				}
				headers.add(key to value)
			}

			val isResponse = firstParts[0].startsWith("HTTP/", ignoreCase = true)
			val status = if (isResponse) firstParts[1].toIntOrNull() ?: 0 else 0

			return ParsedHttpHead(
				method = if (isResponse) "" else firstParts[0],
				target = if (isResponse) "" else firstParts[1],
				version = if (isResponse) firstParts[0] else (firstParts.getOrNull(2) ?: "HTTP/1.1"),
				statusCode = status,
				headers = headers,
				rawBytes = bytes,
			)
		}

		private fun parseHostPort(input: String, defaultPort: Int): Pair<String, Int> {
			val trimmed = input.trim()
			if (trimmed.startsWith('[')) {
				val closeBracket = trimmed.indexOf(']')
				if (closeBracket > 0) {
					val ipv6 = trimmed.substring(1, closeBracket)
					if (closeBracket + 1 < trimmed.length && trimmed[closeBracket + 1] == ':') {
						val p = trimmed.substring(closeBracket + 2).toIntOrNull()
						if (p != null)
							return ipv6 to p
					}
					return ipv6 to defaultPort
				}
			}
			val colon = trimmed.lastIndexOf(':')
			if (colon > 0 && trimmed.indexOf(':') == colon) {
				val p = trimmed.substring(colon + 1).toIntOrNull()
				if (p != null)
					return trimmed.substring(0, colon) to p
			}

			return trimmed to defaultPort
		}

		private fun extractHostAndPath(
			reqTarget: String,
			hostHeader: String,
			fixedHost: String,
			fixedPort: Int,
			isTls: Boolean,
		): ResolvedTarget {
			val defaultPort = if (isTls) 443 else 80
			if (reqTarget.startsWith("http://", ignoreCase = true) || reqTarget.startsWith("https://", ignoreCase = true)) {
				val afterScheme = reqTarget.substring(reqTarget.indexOf("://") + 3)
				val slash = afterScheme.indexOf('/')
				val authority = if (slash >= 0) afterScheme.substring(0, slash) else afterScheme
				val path = if (slash >= 0) afterScheme.substring(slash) else "/"
				val hp = parseHostPort(authority, defaultPort)
				return ResolvedTarget(RuleEngine.normalizeHost(hp.first), hp.second, path)
			}

			val path = if (reqTarget.startsWith('/')) reqTarget else "/$reqTarget"
			if (fixedHost.isNotEmpty())
				return ResolvedTarget(RuleEngine.normalizeHost(fixedHost), fixedPort, path)

			val hp = parseHostPort(hostHeader, defaultPort)

			return ResolvedTarget(RuleEngine.normalizeHost(hp.first), hp.second, path)
		}
	}
}

class ParsedHttpHead(
	val method: String,
	val target: String,
	val version: String,
	val statusCode: Int,
	val headers: List<Pair<String, String>>,
	val rawBytes: ByteArray,
) {
	fun header(name: String): String {
		var first: String? = null
		var merged: StringBuilder? = null
		for ((k, v) in headers) {
			if (k.equals(name, ignoreCase = true)) {
				if (first == null) {
					first = v
				} else {
					if (merged == null)
						merged = StringBuilder(first.length + v.length + 4).append(first)
					merged.append(", ").append(v)
				}
			}
		}

		return merged?.toString() ?: first ?: ""
	}
}

data class ResolvedTarget(
	val host: String,
	val port: Int,
	val pathAndQuery: String,
)
