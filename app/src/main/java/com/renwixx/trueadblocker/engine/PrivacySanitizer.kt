package com.renwixx.trueadblocker.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.charset.Charset
import java.util.zip.GZIPInputStream

data class SanitizeOutcome(
	val cleanedPathAndQuery: String,
	val removedParams: List<String>,
)

private class CompiledParamMatcher(
	val sourceText: String,
	val exactNames: Set<String>,
	val prefixes: List<String>,
	val wildcards: List<String>,
)

object PrivacySanitizer {
	private const val MAX_HTML_PLAIN_BYTES = 1_572_864

	@Volatile
	private var _cachedMatcher: CompiledParamMatcher? = null

	fun sanitizePathAndQuery(
		pathAndQuery: String,
		userRulesText: String,
		extraExactParams: Set<String> = emptySet(),
	): SanitizeOutcome {
		val qIdx = pathAndQuery.indexOf('?')
		if (qIdx < 0 || qIdx == pathAndQuery.length - 1)
			return SanitizeOutcome(pathAndQuery, emptyList())

		val pathPart = pathAndQuery.substring(0, qIdx)
		val afterQ = pathAndQuery.substring(qIdx + 1)
		val hashIdx = afterQ.indexOf('#')
		val queryStr = if (hashIdx >= 0) afterQ.substring(0, hashIdx) else afterQ
		val fragPart = if (hashIdx >= 0) afterQ.substring(hashIdx) else ""

		if (queryStr.isEmpty() || isCryptographicallySignedQuery(queryStr))
			return SanitizeOutcome(pathAndQuery, emptyList())

		val matcher = getOrCompile(userRulesText)
		var removed: ArrayList<String>? = null
		val keptSegments = ArrayList<String>(8)

		var start = 0
		val qLen = queryStr.length
		while (start <= qLen) {
			val ampIdx = queryStr.indexOf('&', start)
			val end = if (ampIdx >= 0) ampIdx else qLen
			val seg = queryStr.substring(start, end)

			if (seg.isNotEmpty()) {
				val eqIdx = seg.indexOf('=')
				val rawKey = if (eqIdx >= 0) seg.substring(0, eqIdx) else seg
				val decodedKey = if (rawKey.contains('%')) {
					runCatching { URLDecoder.decode(rawKey, "UTF-8") }.getOrDefault(rawKey)
				} else {
					rawKey
				}
				val keyLower = decodedKey.trim().lowercase()

				if (keyLower.isNotEmpty() && isTrackingParam(keyLower, matcher, extraExactParams)) {
					if (removed == null)
						removed = ArrayList(4)
					removed.add(keyLower)
				} else {
					keptSegments.add(seg)
				}
			}

			if (ampIdx < 0)
				break
			start = ampIdx + 1
		}

		val remList = removed ?: return SanitizeOutcome(pathAndQuery, emptyList())
		val rebuilt = buildString(pathAndQuery.length) {
			append(pathPart)
			if (keptSegments.isNotEmpty()) {
				append('?')
				for (i in keptSegments.indices) {
					if (i > 0)
						append('&')
					append(keptSegments[i])
				}
			}
			append(fragPart)
		}

		return SanitizeOutcome(rebuilt, remList)
	}

	// Preserves signed URLs (AWS SigV4/V2, GCS, Azure SAS, CloudFront) where stripping params invalidates HMAC/RSA signatures
	private fun isCryptographicallySignedQuery(queryStr: String): Boolean {
		val lower = queryStr.lowercase()
		if (
			lower.contains("x-amz-signature=") ||
			lower.contains("awsaccesskeyid=") ||
			lower.contains("x-goog-signature=") ||
			lower.contains("googleaccessid=")
		) {
			return true
		}
		if (lower.contains("sig=") && (lower.contains("sv=") || lower.contains("se=") || lower.contains("sp=")))
			return true
		if (lower.contains("signature=") && (lower.contains("key-pair-id=") || lower.contains("expires=")))
			return true

		return false
	}

	private fun isTrackingParam(
		keyLower: String,
		matcher: CompiledParamMatcher,
		extraExact: Set<String>,
	): Boolean {
		if (matcher.exactNames.contains(keyLower) || extraExact.contains(keyLower))
			return true
		for (pref in matcher.prefixes) {
			if (keyLower.startsWith(pref))
				return true
		}
		for (w in matcher.wildcards) {
			if (RuleEngine.globMatch(keyLower, w))
				return true
		}

		return false
	}

	private fun getOrCompile(rulesText: String): CompiledParamMatcher {
		val cur = _cachedMatcher
		if (cur != null && cur.sourceText == rulesText)
			return cur

		val exact = HashSet<String>(64)
		val prefixes = ArrayList<String>(8)
		val wilds = ArrayList<String>(8)

		val tokens = rulesText.split(',', '\n', ';', ' ', '\t')
		for (raw in tokens) {
			val clean = raw.trim().lowercase()
			if (clean.isEmpty())
				continue
			if (!clean.contains('*') && !clean.contains('?')) {
				exact.add(clean)
			} else if (clean.endsWith('*') && clean.indexOf('*') == clean.length - 1 && !clean.contains('?')) {
				val pref = clean.dropLast(1)
				if (pref.isNotEmpty())
					prefixes.add(pref)
			} else {
				wilds.add(clean)
			}
		}

		return CompiledParamMatcher(rulesText, exact, prefixes, wilds).also {
			_cachedMatcher = it
		}
	}

	fun injectCosmeticCssIntoHtml(
		rawBody: ByteArray,
		isGzipEncoded: Boolean,
		cssContent: String,
		charset: Charset = Charsets.UTF_8,
	): ByteArray? {
		if (cssContent.isBlank() || rawBody.isEmpty())
			return null

		val plainBytes = if (isGzipEncoded) {
			decompressGzipBounded(rawBody, MAX_HTML_PLAIN_BYTES) ?: return null
		} else {
			if (rawBody.size > MAX_HTML_PLAIN_BYTES)
				return null
			rawBody
		}

		val safeCss = sanitizeStyleTagPayload(cssContent)
		if (safeCss.isBlank())
			return null

		val html = String(plainBytes, charset)
		val styleTag = "<style id=\"tb-cosmetic\">$safeCss</style>"

		val headClose = html.indexOf("</head>", ignoreCase = true)
		val modified = if (headClose >= 0) {
			StringBuilder(html.length + styleTag.length)
				.append(html, 0, headClose)
				.append(styleTag)
				.append(html, headClose, html.length)
				.toString()
		} else {
			val bodyClose = html.indexOf("</body>", ignoreCase = true)
			if (bodyClose >= 0) {
				StringBuilder(html.length + styleTag.length)
					.append(html, 0, bodyClose)
					.append(styleTag)
					.append(html, bodyClose, html.length)
					.toString()
			} else {
				return null
			}
		}

		return modified.toByteArray(charset)
	}

	private fun decompressGzipBounded(rawBody: ByteArray, maxBytes: Int): ByteArray? {
		return runCatching {
			GZIPInputStream(ByteArrayInputStream(rawBody)).use { gz ->
				val out = ByteArrayOutputStream(minOf(rawBody.size * 3, 262_144).coerceAtLeast(4096))
				val buf = ByteArray(16 * 1024)
				var total = 0
				while (true) {
					val n = gz.read(buf)
					if (n < 0)
						break
					total += n
					if (total > maxBytes)
						return null
					out.write(buf, 0, n)
				}
				out.toByteArray()
			}
		}.getOrNull()
	}

	private fun sanitizeStyleTagPayload(css: String): String {
		if (!css.contains("</", ignoreCase = true) && !css.contains("<!--"))
			return css

		return css
			.replace(Regex("(?i)</\\s*style"), "")
			.replace("</", "<\\/")
			.replace("<!--", "")
	}
}
