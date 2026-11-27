package com.renwixx.trueadblocker.net

import com.renwixx.trueadblocker.ui.formatRelativeTime
import com.renwixx.trueadblocker.ui.shortenUrlForDisplay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdaterAndUiHelpersTest {
	@Test
	fun appUpdaterIsRemoteNewerCoversVersionCodesAndCommits() {
		assertTrue(AppUpdater.isRemoteNewer(105, "abc1234", 104, "def5678"))
		assertFalse(AppUpdater.isRemoteNewer(103, "abc1234", 104, "def5678"))
		assertFalse(AppUpdater.isRemoteNewer(104, "abc1234", 104, "abc1234"))
		assertFalse(AppUpdater.isRemoteNewer(104, "ABC1234", 104, "abc1234"))
		assertTrue(AppUpdater.isRemoteNewer(104, "abc1234", 104, "def5678"))
		assertFalse(AppUpdater.isRemoteNewer(104, "abc1234", 104, "local"))
		assertFalse(AppUpdater.isRemoteNewer(104, "", 104, "def5678"))
		assertFalse(AppUpdater.isRemoteNewer(104, "abc1234", 104, ""))
	}

	@Test
	fun shortenUrlForDisplayCompactsPathsAndQueries() {
		assertEquals("example.com", shortenUrlForDisplay("example.com"))
		assertEquals("example.com/", shortenUrlForDisplay("example.com/"))
		assertEquals("example.com/short", shortenUrlForDisplay("example.com/short"))
		assertEquals("example.com/a/b?…", shortenUrlForDisplay("example.com/a/b?k=1"))
		assertEquals(
			"cdn.example.com/api/…/items?…",
			shortenUrlForDisplay("cdn.example.com/api/v2/users/42/items?token=secret&page=3"),
		)

		val longSingleSeg = "example.com/" + "a".repeat(50)
		assertEquals("example.com/" + "a".repeat(28) + "…", shortenUrlForDisplay(longSingleSeg))

		val twoLongSegs = "example.com/" + "x".repeat(25) + "/" + "y".repeat(30)
		assertEquals("example.com/" + "x".repeat(16) + "/" + "y".repeat(24), shortenUrlForDisplay(twoLongSegs))
	}

	@Test
	fun formatRelativeTimeFormatsAllThresholdsAndClampsFuture() {
		val now = 1_700_000_000_000L
		assertEquals("just now", formatRelativeTime(now + 10_000L, now))
		assertEquals("just now", formatRelativeTime(now - 4_000L, now))
		assertEquals("5s ago", formatRelativeTime(now - 5_000L, now))
		assertEquals("59s ago", formatRelativeTime(now - 59_000L, now))
		assertEquals("1m ago", formatRelativeTime(now - 60_000L, now))
		assertEquals("59m ago", formatRelativeTime(now - 3_540_000L, now))
		assertEquals("1h ago", formatRelativeTime(now - 3_600_000L, now))
		assertEquals("23h ago", formatRelativeTime(now - 23L * 3_600_000L, now))
		assertEquals("1d ago", formatRelativeTime(now - 86_400_000L, now))
		assertEquals("5d ago", formatRelativeTime(now - 5L * 86_400_000L, now))
	}
}
