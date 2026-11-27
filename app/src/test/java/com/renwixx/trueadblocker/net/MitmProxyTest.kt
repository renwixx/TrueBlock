package com.renwixx.trueadblocker.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MitmProxyTest {
	@Test
	fun parsedHttpHeadHeaderMergesDuplicatesCaseInsensitively() {
		val head = ParsedHttpHead(
			method = "GET",
			target = "/index.html",
			version = "HTTP/1.1",
			statusCode = 0,
			headers = listOf(
				"Host" to "example.com",
				"X-Custom" to "one",
				"x-custom" to "two",
			),
			rawBytes = ByteArray(0),
		)
		assertEquals("example.com", head.header("HOST"))
		assertEquals("one, two", head.header("X-Custom"))
		assertEquals("", head.header("Missing-Header"))
	}

	@Test
	fun computeWebSocketAcceptMatchesRfc6455Vector() {
		assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", MitmProxy.computeWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="))
		assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", MitmProxy.computeWebSocketAccept("  dGhlIHNhbXBsZSBub25jZQ==  "))
	}

	@Test
	fun selectNoopStubCoversAllResourceTypes() {
		val opts = MitmProxy.selectNoopStub("OPTIONS", "/api", "*/*", "")
		assertEquals("text/plain", opts?.first)
		assertEquals(0, opts?.second?.size)

		val js = MitmProxy.selectNoopStub("GET", "/ads/sdk.js?v=2", "*/*", "script")
		assertTrue(js!!.first.startsWith("application/javascript"))
		assertEquals(0, js.second.size)

		val css = MitmProxy.selectNoopStub("GET", "/ads/theme.css", "*/*", "style")
		assertTrue(css!!.first.startsWith("text/css"))
		assertEquals(0, css.second.size)

		val img = MitmProxy.selectNoopStub("GET", "/pixel.png", "image/webp,*/*", "image")
		assertEquals("image/gif", img!!.first)
		assertEquals(42, img.second.size)
		assertEquals("GIF89a", String(img.second, 0, 6, Charsets.US_ASCII))

		val json = MitmProxy.selectNoopStub("GET", "/config.json", "application/json", "empty")
		assertTrue(json!!.first.startsWith("application/json"))
		assertEquals("{}", String(json.second, Charsets.UTF_8))

		val html = MitmProxy.selectNoopStub("GET", "/frame.html", "*/*", "iframe")
		assertTrue(html!!.first.startsWith("text/html"))
		assertTrue(String(html.second, Charsets.UTF_8).contains("<!DOCTYPE html>"))

		val vast = MitmProxy.selectNoopStub("GET", "/ads/preroll.vast", "*/*", "")
		assertTrue(vast!!.first.startsWith("application/xml"))
		assertTrue(String(vast.second, Charsets.UTF_8).contains("<VAST"))

		assertNull(MitmProxy.selectNoopStub("POST", "/telemetry/collect", "*/*", "empty"))
	}

	@Test
	fun classifyResponseTypeCoversMimeDispositionUrlExtSecDestAndAccept() {
		assertEquals("image" to "webp", MitmProxy.classifyResponseType("/cdn/photo", "image/webp"))
		assertEquals("image" to "svg", MitmProxy.classifyResponseType("/icon", "image/svg+xml; charset=utf-8"))
		assertEquals("video" to "mp4", MitmProxy.classifyResponseType("/stream/clip.mp4?t=1", "video/mp4"))
		assertEquals("video" to "m3u8", MitmProxy.classifyResponseType("/live/index", "application/vnd.apple.mpegurl"))
		assertEquals("video" to "", MitmProxy.classifyResponseType("/live/manifest", "application/dash+xml"))
		assertEquals("audio" to "mp3", MitmProxy.classifyResponseType("/track.mp3", "audio/mpeg"))
		assertEquals("audio" to "flac", MitmProxy.classifyResponseType("/lossless", "audio/flac"))
		assertEquals(
			"file" to "apk",
			MitmProxy.classifyResponseType("/dl/get", "application/octet-stream", "attachment; filename=\"app-release.apk\""),
		)
		assertEquals("file" to "pdf", MitmProxy.classifyResponseType("/doc", "application/pdf"))
		assertEquals("file" to "woff2", MitmProxy.classifyResponseType("/f", "font/woff2"))
		assertEquals("default" to "", MitmProxy.classifyResponseType("/api/v2/feed", "application/json; charset=utf-8"))
		assertEquals("default" to "", MitmProxy.classifyResponseType("/api/feed", "application/problem+json"))

		// Empty MIME falls back to URL extension
		assertEquals("image" to "avif", MitmProxy.classifyResponseType("/img/hero.avif", ""))
		assertEquals("video" to "mkv", MitmProxy.classifyResponseType("/vid/movie.mkv", ""))
		assertEquals("audio" to "opus", MitmProxy.classifyResponseType("/aud/voice.opus", ""))
		assertEquals("file" to "zip", MitmProxy.classifyResponseType("/dl/archive.zip", ""))

		// Empty MIME & no ext falls back to sec-fetch-dest and Accept
		assertEquals("image" to "", MitmProxy.classifyResponseType("/img/raw", "", secDest = "image"))
		assertEquals("video" to "", MitmProxy.classifyResponseType("/vid/raw", "", secDest = "video"))
		assertEquals("audio" to "", MitmProxy.classifyResponseType("/aud/raw", "", secDest = "audio"))
		assertEquals("image" to "", MitmProxy.classifyResponseType("/img/raw", "", acceptHeader = "image/webp,*/*"))
		assertEquals("default" to "", MitmProxy.classifyResponseType("/page", "", acceptHeader = "image/webp,text/html"))
	}
}
