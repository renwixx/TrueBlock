package com.renwixx.trueadblocker.engine

import com.renwixx.trueadblocker.data.DEFAULT_TRACKING_PARAM_RULES
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.util.zip.GZIPOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacySanitizerTest {
	@Test
	fun sanitizePathAndQueryHandlesNoQueryTrailingQuestionAndFragment() {
		assertEquals(SanitizeOutcome("/path/only", emptyList()), PrivacySanitizer.sanitizePathAndQuery("/path/only", DEFAULT_TRACKING_PARAM_RULES))
		assertEquals(SanitizeOutcome("/path?", emptyList()), PrivacySanitizer.sanitizePathAndQuery("/path?", DEFAULT_TRACKING_PARAM_RULES))
		assertEquals(SanitizeOutcome("/path?#frag", emptyList()), PrivacySanitizer.sanitizePathAndQuery("/path?#frag", DEFAULT_TRACKING_PARAM_RULES))

		val allStripped = PrivacySanitizer.sanitizePathAndQuery(
			"/article?utm_source=x&fbclid=y#section2",
			DEFAULT_TRACKING_PARAM_RULES,
		)
		assertEquals("/article#section2", allStripped.cleanedPathAndQuery)
		assertEquals(listOf("utm_source", "fbclid"), allStripped.removedParams)
	}

	@Test
	fun sanitizePathAndQuerySupportsExactPrefixWildcardExtraAndPercentEncodedKeys() {
		val outcome = PrivacySanitizer.sanitizePathAndQuery(
			pathAndQuery = "/watch?v=abc&%75tm_medium=social&custom_flag&tr1=9&extra_key=1&%ZZ=keep&ok=2#top",
			userRulesText = "utm_*, tr?, custom_flag",
			extraExactParams = setOf("extra_key"),
		)
		assertEquals("/watch?v=abc&%ZZ=keep&ok=2#top", outcome.cleanedPathAndQuery)
		assertEquals(listOf("utm_medium", "custom_flag", "tr1", "extra_key"), outcome.removedParams)
	}

	@Test
	fun sanitizePathAndQueryPreservesAllCryptographicallySignedUrls() {
		val signedUrls = listOf(
			"/bucket/doc.pdf?utm_source=keep&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
			"/legacy/doc.pdf?fbclid=1&AWSAccessKeyId=AKIA123&Signature=abc",
			"/gcs/file.bin?utm_campaign=a&X-Goog-Signature=hex",
			"/gcs/v2.bin?utm_campaign=a&GoogleAccessId=svc@proj",
			"/azure/blob.zip?utm_source=a&sv=2022-11-02&sig=HmacVal",
			"/azure/blob.zip?utm_source=a&se=2026-01-01&sig=HmacVal",
			"/azure/blob.zip?utm_source=a&sp=r&sig=HmacVal",
			"/cf/vid.mp4?utm_source=a&Signature=abc&Key-Pair-Id=K123",
			"/cf/vid.mp4?utm_source=a&Signature=abc&Expires=999999",
		)
		for (u in signedUrls) {
			val res = PrivacySanitizer.sanitizePathAndQuery(u, DEFAULT_TRACKING_PARAM_RULES)
			assertEquals("Signed URL must remain untouched: $u", u, res.cleanedPathAndQuery)
			assertTrue(res.removedParams.isEmpty())
		}

		// Plain sig= without Azure SAS companion params must still be sanitized
		val notSigned = PrivacySanitizer.sanitizePathAndQuery("/item?sig=foo&utm_source=mail", DEFAULT_TRACKING_PARAM_RULES)
		assertEquals("/item?sig=foo", notSigned.cleanedPathAndQuery)
		assertEquals(listOf("utm_source"), notSigned.removedParams)
	}

	@Test
	fun injectCosmeticCssHandlesHeadBodyGzipCharsetAndSecurityGuards() {
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml(ByteArray(0), false, ".ad{display:none}"))
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml("<head></head>".toByteArray(), false, "   "))
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml("<div>no head or body</div>".toByteArray(), false, ".ad{display:none}"))

		val headHtml = "<!DOCTYPE html><html><HEAD><title>T</title></HEAD><body>ok</body></html>"
		val gzBytes = ByteArrayOutputStream().use { bos ->
			GZIPOutputStream(bos).use { gz -> gz.write(headHtml.toByteArray(Charsets.UTF_8)) }
			bos.toByteArray()
		}
		val fromGzip = PrivacySanitizer.injectCosmeticCssIntoHtml(gzBytes, true, ".ad{display:none}")
		assertNotNull(fromGzip)
		assertTrue(String(fromGzip!!, Charsets.UTF_8).contains("<style id=\"tb-cosmetic\">.ad{display:none}</style></HEAD>"))

		val bodyOnly = "<html><body><p>hi</p></body></html>"
		val intoBody = PrivacySanitizer.injectCosmeticCssIntoHtml(bodyOnly.toByteArray(Charsets.UTF_8), false, ".ad{display:none}")
		assertNotNull(intoBody)
		assertTrue(String(intoBody!!, Charsets.UTF_8).contains("<style id=\"tb-cosmetic\">.ad{display:none}</style></body>"))

		val win1251 = Charset.forName("Windows-1251")
		val cyrHtml = "<html><head></head><body>Привет</body></html>".toByteArray(win1251)
		val injectedCyr = PrivacySanitizer.injectCosmeticCssIntoHtml(cyrHtml, false, ".ad{display:none}", win1251)
		assertNotNull(injectedCyr)
		assertTrue(String(injectedCyr!!, win1251).contains("Привет"))

		// Corrupt gzip returns null
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml(byteArrayOf(1, 2, 3, 4), true, ".ad{display:none}"))

		// Plain HTML > 1.5 MiB returns null
		val oversizedPlain = ByteArray(1_600_000) { 'A'.code.toByte() }
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml(oversizedPlain, false, ".ad{display:none}"))

		// Gzip bomb guard
		val hugeHtml = "<html><head></head><body>" + "A".repeat(2_100_000) + "</body></html>"
		val gzBomb = ByteArrayOutputStream().use { bos ->
			GZIPOutputStream(bos).use { gz -> gz.write(hugeHtml.toByteArray(Charsets.UTF_8)) }
			bos.toByteArray()
		}
		assertTrue(gzBomb.size < 32_768)
		assertNull(PrivacySanitizer.injectCosmeticCssIntoHtml(gzBomb, true, ".ad{display:none}"))

		// XSS / style breakout sanitization
		val xssInjected = PrivacySanitizer.injectCosmeticCssIntoHtml(
			"<html><head></head><body>ok</body></html>".toByteArray(Charsets.UTF_8),
			false,
			".ad{display:none}</style><script>evil()</script><!--comment",
		)
		assertNotNull(xssInjected)
		val xssStr = String(xssInjected!!, Charsets.UTF_8)
		assertFalse(xssStr.contains("</style><script>"))
		assertFalse(xssStr.contains("<!--"))
	}
}
