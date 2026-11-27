package com.renwixx.trueadblocker.engine

import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleEngineTest {
	@Test
	fun matchVerdictSummaryTextFormatsAllCombinations() {
		assertEquals("", MatchVerdict.ALLOWED_DEFAULT.summaryText())
		assertEquals("||ads.com^", MatchVerdict(true, "||ads.com^", "").summaryText())
		assertEquals("EasyList", MatchVerdict(true, "", "EasyList").summaryText())
		assertEquals("EasyList • ||ads.com^", MatchVerdict(true, "||ads.com^", "EasyList").summaryText())
	}

	@Test
	fun normalizeHostHandlesCaseBracketsTrailingDotAndIdn() {
		assertEquals("example.com", RuleEngine.normalizeHost("  EXAMPLE.COM.  "))
		assertEquals("2606:4700:4700::1111", RuleEngine.normalizeHost("[2606:4700:4700::1111]"))
		assertEquals("xn--e1afmkfd.xn--p1ai", RuleEngine.normalizeHost("пример.рф."))
		assertEquals("*.пример.рф", RuleEngine.normalizeHost("*.ПРИМЕР.РФ"))
		assertEquals("example.com/path", RuleEngine.normalizeHost("Example.com/Path"))
		assertEquals("", RuleEngine.normalizeHost("   "))
	}

	@Test
	fun extractRegistrableDomainHandlesStandardAndMultipartTlds() {
		assertEquals("example.com", RuleEngine.extractRegistrableDomain("a.b.c.example.com"))
		assertEquals("example.com", RuleEngine.extractRegistrableDomain("example.com"))
		assertEquals("localhost", RuleEngine.extractRegistrableDomain("localhost"))
		assertEquals("bbc.co.uk", RuleEngine.extractRegistrableDomain("news.bbc.co.uk"))
		assertEquals("shop.com.au", RuleEngine.extractRegistrableDomain("cdn.img.shop.com.au"))
		assertEquals("uni.ac.jp", RuleEngine.extractRegistrableDomain("www.uni.ac.jp"))
		assertEquals("co.uk", RuleEngine.extractRegistrableDomain("co.uk"))
	}

	@Test
	fun classifyRequestTypeMaskCoversDestMethodExtensionsAndAccept() {
		assertEquals(RuleEngine.RES_WEBSOCKET, RuleEngine.classifyRequestTypeMask("GET", "/ws", "*/*", "empty", true))
		assertEquals(RuleEngine.RES_SCRIPT, RuleEngine.classifyRequestTypeMask("GET", "/a", "*/*", "script", false))
		assertEquals(RuleEngine.RES_SCRIPT, RuleEngine.classifyRequestTypeMask("GET", "/sw.js", "*/*", "serviceworker", false))
		assertEquals(RuleEngine.RES_IMAGE, RuleEngine.classifyRequestTypeMask("GET", "/p", "*/*", "image", false))
		assertEquals(RuleEngine.RES_STYLESHEET, RuleEngine.classifyRequestTypeMask("GET", "/s", "*/*", "style", false))
		assertEquals(RuleEngine.RES_SUBDOCUMENT, RuleEngine.classifyRequestTypeMask("GET", "/f", "*/*", "iframe", false))
		assertEquals(RuleEngine.RES_DOCUMENT, RuleEngine.classifyRequestTypeMask("GET", "/", "*/*", "document", false))
		assertEquals(RuleEngine.RES_MEDIA, RuleEngine.classifyRequestTypeMask("GET", "/v", "*/*", "video", false))
		assertEquals(RuleEngine.RES_FONT, RuleEngine.classifyRequestTypeMask("GET", "/f", "*/*", "font", false))
		assertEquals(RuleEngine.RES_OTHER, RuleEngine.classifyRequestTypeMask("GET", "/o", "*/*", "object", false))

		assertEquals(
			RuleEngine.RES_XHR or RuleEngine.RES_PING,
			RuleEngine.classifyRequestTypeMask("POST", "/collect", "*/*", "empty", false),
		)

		assertEquals(RuleEngine.RES_SCRIPT, RuleEngine.classifyRequestTypeMask("GET", "/sdk.mjs?v=1", "", "", false))
		assertEquals(RuleEngine.RES_SCRIPT, RuleEngine.classifyRequestTypeMask("GET", "/res", "application/javascript", "", false))
		assertEquals(RuleEngine.RES_STYLESHEET, RuleEngine.classifyRequestTypeMask("GET", "/app.css", "", "", false))
		assertEquals(RuleEngine.RES_IMAGE, RuleEngine.classifyRequestTypeMask("GET", "/pic.avif#top", "", "", false))
		assertEquals(RuleEngine.RES_IMAGE, RuleEngine.classifyRequestTypeMask("GET", "/img", "image/webp", "", false))
		assertEquals(RuleEngine.RES_FONT, RuleEngine.classifyRequestTypeMask("GET", "/font.woff2", "", "", false))
		assertEquals(RuleEngine.RES_MEDIA, RuleEngine.classifyRequestTypeMask("GET", "/live.m3u8", "", "", false))
		assertEquals(RuleEngine.RES_DOCUMENT, RuleEngine.classifyRequestTypeMask("GET", "/home", "text/html,application/xhtml+xml", "", false))
		assertEquals(RuleEngine.RES_XHR, RuleEngine.classifyRequestTypeMask("GET", "/api/data", "application/json", "", false))
		assertEquals(RuleEngine.RES_OTHER, RuleEngine.classifyRequestTypeMask("GET", "/blob", "application/octet-stream", "", false))
	}

	@Test
	fun fastRouteRuleMatchesContextChecksWsPartyAndTypeMask() {
		val wsOnly = FastRouteRule("a*", true, isWebSocketOnly = true, "Src", "r")
		assertTrue(wsOnly.matchesContext(isWebSocket = true, reqTypeMask = 0, isThirdParty = null))
		assertFalse(wsOnly.matchesContext(isWebSocket = false, reqTypeMask = RuleEngine.RES_SCRIPT, isThirdParty = true))

		val thirdOnly = FastRouteRule("a*", true, false, "Src", "r", partyMode = FastRouteRule.PARTY_THIRD_ONLY)
		assertTrue(thirdOnly.matchesContext(false, RuleEngine.RES_SCRIPT, true))
		assertFalse(thirdOnly.matchesContext(false, RuleEngine.RES_SCRIPT, false))
		assertFalse(thirdOnly.matchesContext(false, RuleEngine.RES_SCRIPT, null))

		val firstOnly = FastRouteRule("a*", true, false, "Src", "r", partyMode = FastRouteRule.PARTY_FIRST_ONLY)
		assertTrue(firstOnly.matchesContext(false, RuleEngine.RES_SCRIPT, false))
		assertFalse(firstOnly.matchesContext(false, RuleEngine.RES_SCRIPT, true))
		assertFalse(firstOnly.matchesContext(false, RuleEngine.RES_SCRIPT, null))

		val imgOrScript = FastRouteRule(
			"a*",
			true,
			false,
			"Src",
			"r",
			typeMask = RuleEngine.RES_IMAGE or RuleEngine.RES_SCRIPT,
		)
		assertTrue(imgOrScript.matchesContext(false, RuleEngine.RES_IMAGE, true))
		assertTrue(imgOrScript.matchesContext(false, RuleEngine.RES_SCRIPT, false))
		assertFalse(imgOrScript.matchesContext(false, RuleEngine.RES_STYLESHEET, true))

		val wsOrScript = FastRouteRule(
			"a*",
			true,
			false,
			"Src",
			"r",
			typeMask = RuleEngine.RES_WEBSOCKET or RuleEngine.RES_SCRIPT,
		)
		assertTrue(wsOrScript.matchesContext(isWebSocket = true, reqTypeMask = 0, isThirdParty = null))
	}

	@Test
	fun globMatchHandlesWildcardsSingleCharCaseAndBacktracking() {
		assertTrue(RuleEngine.globMatch("", ""))
		assertTrue(RuleEngine.globMatch("", "***"))
		assertFalse(RuleEngine.globMatch("", "?"))
		assertTrue(RuleEngine.globMatch("AbCdEf", "a?c*f"))
		assertTrue(RuleEngine.globMatch("aaaabbbbcccc", "*a*b*c*"))
		assertFalse(RuleEngine.globMatch("aaaabbbb", "*a*c"))
		assertTrue(RuleEngine.globMatch("banner_123.js", "banner_???.js"))
		assertFalse(RuleEngine.globMatch("banner_12.js", "banner_???.js"))
	}

	@Test
	fun adblockWildcardMatchHandlesSeparatorsEndAnchorAndBacktracking() {
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^*"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad/script.js", "xxx.com/ad^*"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad?slot=1", "xxx.com/ad^*"))
		assertTrue(RuleEngine.adblockWildcardMatch("xxx.com/ad:8080/a", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/admin/panel", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad_1", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad-1", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad.js", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad%20", "xxx.com/ad^*"))
		assertFalse(RuleEngine.adblockWildcardMatch("xxx.com/ad", "xxx.com/ad^more"))
		assertTrue(RuleEngine.adblockWildcardMatch("a/b/c/ad?x=1", "*ad^x=1"))
	}

	@Test
	fun validateRegexAndCompileCustomRuleCoverEdgeCases() {
		assertNull(RuleEngine.validateRegex("^https?://ads\\.example\\.com/.*$"))
		assertNotNull(RuleEngine.validateRegex("[unclosed("))

		assertNull(RuleEngine.compileCustomRule(CustomRule(pattern = "   ", matchMode = MODE_EXACT, isAllow = false, isRoute = false)))
		assertNull(RuleEngine.compileCustomRule(CustomRule(pattern = "[bad", matchMode = MODE_REGEX, isAllow = false, isRoute = false)))

		val strippedDomain = RuleEngine.compileCustomRule(
			CustomRule(pattern = "||ADS.EXAMPLE.COM^", matchMode = MODE_EXACT, isAllow = false, isRoute = false),
		)
		assertNotNull(strippedDomain)
		assertEquals("ads.example.com", strippedDomain!!.normPattern)
		assertFalse(strippedDomain.isSchemeIncluded)

		val idnWildcard = RuleEngine.compileCustomRule(
			CustomRule(pattern = "*.пример.рф", matchMode = MODE_WILDCARD, isAllow = false, isRoute = false),
		)
		assertEquals("*.xn--e1afmkfd.xn--p1ai", idnWildcard!!.normPattern)

		val schemeRoute = RuleEngine.compileCustomRule(
			CustomRule(pattern = "wss://Stream.Example.com/live/*", matchMode = MODE_WILDCARD, isAllow = false, isRoute = true),
		)
		assertTrue(schemeRoute!!.isSchemeIncluded)
		assertEquals("wss://stream.example.com/live/*", schemeRoute.normPattern)
	}

	@Test
	fun testSingleCustomRuleCoversDomainAndRouteModes() {
		val exactDomain = CustomRule(pattern = "ads.example.com", matchMode = MODE_EXACT, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(exactDomain, "https://ads.example.com/pixel.gif"))
		assertFalse(RuleEngine.testSingleCustomRule(exactDomain, "https://sub.ads.example.com/pixel.gif"))
		assertFalse(RuleEngine.testSingleCustomRule(exactDomain, "   "))

		val wildDomain = CustomRule(pattern = "*.doubleclick.net", matchMode = MODE_WILDCARD, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(wildDomain, "googleads.g.doubleclick.net"))
		assertTrue(RuleEngine.testSingleCustomRule(wildDomain, "doubleclick.net"))
		assertFalse(RuleEngine.testSingleCustomRule(wildDomain, "notdoubleclick.net"))

		val globDomain = CustomRule(pattern = "ad?.example.com", matchMode = MODE_WILDCARD, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(globDomain, "ad1.example.com"))
		assertFalse(RuleEngine.testSingleCustomRule(globDomain, "ad12.example.com"))

		val exactRoute = CustomRule(pattern = "xxx.com/ad", matchMode = MODE_EXACT, isAllow = false, isRoute = true)
		assertTrue(RuleEngine.testSingleCustomRule(exactRoute, "https://xxx.com/ad"))
		assertTrue(RuleEngine.testSingleCustomRule(exactRoute, "https://xxx.com/ad/banner.js"))
		assertTrue(RuleEngine.testSingleCustomRule(exactRoute, "https://xxx.com/ad?id=1"))
		assertTrue(RuleEngine.testSingleCustomRule(exactRoute, "https://xxx.com/ad#top"))
		assertFalse(RuleEngine.testSingleCustomRule(exactRoute, "https://xxx.com/admin"))

		val wildRoute = CustomRule(pattern = "xxx.com/ad*", matchMode = MODE_WILDCARD, isAllow = false, isRoute = true)
		assertTrue(RuleEngine.testSingleCustomRule(wildRoute, "https://xxx.com/ad"))
		assertTrue(RuleEngine.testSingleCustomRule(wildRoute, "https://xxx.com/ad/banner.js?id=42"))
		assertFalse(RuleEngine.testSingleCustomRule(wildRoute, "https://xxx.com/content"))

		val regexRoute = CustomRule(
			pattern = """^https?://([a-z0-9-]+\.)?tracker\.io/(collect|beacon).*$""",
			matchMode = MODE_REGEX,
			isAllow = false,
			isRoute = true,
		)
		assertTrue(RuleEngine.testSingleCustomRule(regexRoute, "https://eu.tracker.io/collect?uid=99"))
		assertFalse(RuleEngine.testSingleCustomRule(regexRoute, "https://eu.tracker.io/static/logo.png"))

		val regexDomain = CustomRule(pattern = "^ad[0-9]+\\.site\\.org$", matchMode = MODE_REGEX, isAllow = false, isRoute = false)
		assertTrue(RuleEngine.testSingleCustomRule(regexDomain, "https://ad42.site.org/x"))
		assertFalse(RuleEngine.testSingleCustomRule(regexDomain, "https://cdn.site.org/x"))
	}

	@Test
	fun parseLineIntoSetsCoversAllFormatsModifiersAndRejections() {
		val allowExact = HashMap<String, String>()
		val allowZones = HashMap<String, String>()
		val blockExact = HashMap<String, String>()
		val blockZones = HashMap<String, String>()
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>()
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val tokenAllows = HashMap<String, MutableList<FastRouteRule>>()
		val tokenBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val fallback = ArrayList<FastRouteRule>()
		val genericCos = LinkedHashSet<String>()
		val domainCos = HashMap<String, MutableList<String>>()
		val domainEx = HashMap<String, MutableSet<String>>()
		val removeParams = HashSet<String>()

		val lines = listOf(
			"",
			"! Comment header",
			"[Adblock Plus 2.0]",
			"# Hash comment",
			"0.0.0.0 localhost broadcasthost telemetry.vendor.com ad2.vendor.com # trailing",
			"::1 ipv6host.vendor.com",
			"*.wildtracker.org",
			"address=/dnsmasq-ad.net/",
			"plaindomain.org",
			"notadomain",
			"bad..domain.com",
			"||doubleclick.net^",
			"@@||safe.doubleclick.net^",
			"||news.site.com/ads/banner^",
			"||cdn.site.com^*.gif",
			"||static.site.com/sdk/ad.js|",
			"/pagead/show_ads.js",
			"|https://tracking.example.net/pixel|",
			"||stream.ad.io/socket^\$websocket",
			"||embed.widget.com^\$third-party",
			"||first.only.com^\$1p,script",
			"||neg.types.com^\$~image,~stylesheet",
			"||contradict.com^\$script,~script",
			"||unknownmod.com^\$unknownmodifier",
			"||badf.com^\$badfilter",
			"||popup.com^\$popup",
			"||domscoped.com^\$domain=example.com",
			"@@||cdn.tracker.com^\$image",
			"||adserver.net^\$important",
			"/regex-skipped/",
			"ab",
			"##.banner-ad",
			"*##.star-banner",
			"~google.com##.global-sponsor",
			"news.example.com,blog.example.com,~sub.news.example.com##div > .sponsored-box",
			"blog.com#@#.global-sponsor",
			"example.com##div:has(.procedural)",
			"example.com##+js(set-constant, a, b)",
			"example.com##.bad{display:none}",
			"example.com#?#.extended",
			"*\$removeparam=ttclid",
			"\$removeparam=igshid",
			"||site.example.com^\$removeparam=id",
			"*\$removeparam=/regex/",
			"@@*\$removeparam=ttclid",
		)

		for (ln in lines) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = "TestList",
				allowExact = allowExact,
				allowZones = allowZones,
				blockExact = blockExact,
				blockZones = blockZones,
				hostRouteAllows = hostAllows,
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = tokenAllows,
				tokenRouteBlocks = tokenBlocks,
				fallbackRouteBlocks = fallback,
				genericCosmetics = genericCos,
				domainCosmetics = domainCos,
				domainCosmeticExceptions = domainEx,
				removeParams = removeParams,
			)
		}

		assertEquals("TestList", blockExact["telemetry.vendor.com"])
		assertEquals("TestList", blockExact["ad2.vendor.com"])
		assertEquals("TestList", blockExact["ipv6host.vendor.com"])
		assertFalse(blockExact.containsKey("localhost"))
		assertFalse(blockExact.containsKey("broadcasthost"))

		assertEquals("TestList", blockZones["wildtracker.org"])
		assertEquals("TestList", blockZones["dnsmasq-ad.net"])
		assertEquals("TestList", blockZones["plaindomain.org"])
		assertEquals("TestList", blockZones["doubleclick.net"])
		assertEquals("TestList", blockZones["adserver.net"])
		assertEquals("TestList", allowZones["safe.doubleclick.net"])

		assertFalse(blockZones.containsKey("embed.widget.com"))
		assertFalse(blockZones.containsKey("contradict.com"))
		assertFalse(blockZones.containsKey("unknownmod.com"))
		assertFalse(blockZones.containsKey("badf.com"))
		assertFalse(blockZones.containsKey("popup.com"))
		assertFalse(blockZones.containsKey("domscoped.com"))
		assertFalse(allowZones.containsKey("cdn.tracker.com"))

		val bannerPat = hostBlocks["news.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("news.site.com/ads/banner", bannerPat))
		assertFalse(RuleEngine.adblockWildcardMatch("news.site.com/ads/banner2", bannerPat))

		val gifPat = hostBlocks["cdn.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("cdn.site.com/img/pixel.gif", gifPat))
		assertFalse(RuleEngine.adblockWildcardMatch("cdn.site.com/img/pixel.png", gifPat))

		val exactEndPat = hostBlocks["static.site.com"]!!.first().pattern
		assertTrue(RuleEngine.adblockWildcardMatch("static.site.com/sdk/ad.js", exactEndPat))
		assertFalse(RuleEngine.adblockWildcardMatch("static.site.com/sdk/ad.js?v=2", exactEndPat))

		assertTrue(hostBlocks["stream.ad.io"]!!.first().isWebSocketOnly)
		val firstOnlyRule = hostBlocks["first.only.com"]!!.first()
		assertEquals(FastRouteRule.PARTY_FIRST_ONLY, firstOnlyRule.partyMode)
		assertEquals(RuleEngine.RES_SCRIPT, firstOnlyRule.typeMask)

		val negRule = hostBlocks["neg.types.com"]!!.first()
		assertFalse(negRule.matchesContext(false, RuleEngine.RES_IMAGE, true))
		assertFalse(negRule.matchesContext(false, RuleEngine.RES_STYLESHEET, true))
		assertTrue(negRule.matchesContext(false, RuleEngine.RES_SCRIPT, true))

		assertTrue(hostAllows["cdn.tracker.com"]!!.first().matchesContext(false, RuleEngine.RES_IMAGE, true))
		assertTrue(tokenBlocks.containsKey("pagead"))
		assertTrue(tokenBlocks.containsKey("tracking"))

		assertTrue(genericCos.contains(".banner-ad"))
		assertTrue(genericCos.contains(".star-banner"))
		assertTrue(genericCos.contains(".global-sponsor"))
		assertEquals(listOf("div > .sponsored-box"), domainCos["news.example.com"])
		assertEquals(listOf("div > .sponsored-box"), domainCos["blog.example.com"])
		assertFalse(domainCos.containsKey("example.com"))
		assertTrue(domainEx["google.com"]?.contains(".global-sponsor") == true)
		assertTrue(domainEx["sub.news.example.com"]?.contains("div > .sponsored-box") == true)
		assertTrue(domainEx["blog.com"]?.contains(".global-sponsor") == true)

		assertEquals(setOf("ttclid", "igshid"), removeParams)
	}

	@Test
	fun compactRuleSetsDeduplicatesMergesSourcesAndPreservesAllowExceptions() {
		val allowExact = HashMap<String, String>()
		val allowZones = hashMapOf("cdn.allowed.org" to "Unbreak")
		val blockExact = HashMap<String, String>()
		val blockZones = HashMap<String, String>()
		val hostAllows = HashMap<String, MutableList<FastRouteRule>>()
		val hostBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val tokenAllows = HashMap<String, MutableList<FastRouteRule>>()
		val tokenBlocks = HashMap<String, MutableList<FastRouteRule>>()
		val fallback = ArrayList<FastRouteRule>()
		val seenRoutes = HashSet<String>()
		val pool = HashMap<String, String>()

		val mixed = listOf(
			"List1" to "0.0.0.0 doubleclick.net",
			"List1" to "127.0.0.1 googleads.g.doubleclick.net",
			"List2" to "*.doubleclick.net",
			"List3" to "||doubleclick.net^",
			"List4" to "||doubleclick.net^",
			"List5" to "||doubleclick.net^",
			"List2" to "||sub.doubleclick.net^",
			"List2" to "||doubleclick.net/pagead/ads^",
			"List2" to "||allowed.org^",
			"List2" to "||allowed.org/ads/banner^",
			"List2" to "/pagead/show_ads.js",
			"List3" to "/pagead/show_ads.js",
		)

		for ((src, ln) in mixed) {
			RuleEngine.parseLineIntoSets(
				rawLine = ln,
				listTitle = src,
				allowExact = allowExact,
				allowZones = allowZones,
				blockExact = blockExact,
				blockZones = blockZones,
				hostRouteAllows = hostAllows,
				hostRouteBlocks = hostBlocks,
				tokenRouteAllows = tokenAllows,
				tokenRouteBlocks = tokenBlocks,
				fallbackRouteBlocks = fallback,
				seenRouteKeys = seenRoutes,
				sourcePool = pool,
			)
		}

		RuleEngine.compactRuleSets(
			allowExact = allowExact,
			allowZones = allowZones,
			blockExact = blockExact,
			blockZones = blockZones,
			hostRouteBlocks = hostBlocks,
			sourcePool = pool,
		)

		assertEquals(0, blockExact.size)
		assertEquals(setOf("doubleclick.net", "allowed.org"), blockZones.keys)
		assertEquals("List2, List3, List4, ...", blockZones["doubleclick.net"])
		assertFalse(hostBlocks.containsKey("doubleclick.net"))
		assertTrue(hostBlocks.containsKey("allowed.org"))
		assertEquals(1, tokenBlocks.values.sumOf { it.size })
	}
}
