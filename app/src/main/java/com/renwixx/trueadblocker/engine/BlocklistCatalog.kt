package com.renwixx.trueadblocker.engine

import com.renwixx.trueadblocker.BuildConfig
import com.renwixx.trueadblocker.data.BlocklistSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

data class GitHubRepoItem(
	val fullName: String,
	val description: String,
	val stars: Int,
	val defaultBranch: String,
)

data class GitHubRawListCandidate(
	val name: String,
	val path: String,
	val rawUrl: String,
	val sizeBytes: Long,
)

object GitHubBlocklistExplorer {
	private val _http = OkHttpClient.Builder()
		.connectTimeout(15, TimeUnit.SECONDS)
		.readTimeout(20, TimeUnit.SECONDS)
		.build()

	suspend fun searchRepos(userQuery: String): Result<List<GitHubRepoItem>> = withContext(Dispatchers.IO) {
		runCatching {
			val q = if (userQuery.isBlank()) {
				"adblock+blocklist+hosts"
			} else {
				URLEncoder.encode("$userQuery blocklist OR hosts OR adblock", "UTF-8")
			}
			val req = Request.Builder()
				.url("https://api.github.com/search/repositories?q=$q&sort=stars&order=desc&per_page=15")
				.header("Accept", "application/vnd.github+json")
				.header("User-Agent", "TrueBlock/${BuildConfig.VERSION_NAME}")
				.build()

			_http.newCall(req).execute().use { resp ->
				if (!resp.isSuccessful) {
					val msg = if (resp.code == 403 || resp.code == 429) {
						"GitHub API rate limit exceeded (HTTP ${resp.code})"
					} else {
						"GitHub API HTTP ${resp.code}"
					}
					throw IllegalStateException(msg)
				}
				val body = resp.body?.string() ?: "{}"
				val items = JSONObject(body).optJSONArray("items") ?: return@use emptyList()
				val out = ArrayList<GitHubRepoItem>(items.length())
				for (i in 0 until items.length()) {
					val o = items.getJSONObject(i)
					out.add(
						GitHubRepoItem(
							fullName = o.getString("full_name"),
							description = o.optString("description", "").take(140),
							stars = o.optInt("stargazers_count", 0),
							defaultBranch = o.optString("default_branch", "main"),
						)
					)
				}
				out
			}
		}
	}

	suspend fun listFilterFilesInRepo(repo: GitHubRepoItem): Result<List<GitHubRawListCandidate>> = withContext(Dispatchers.IO) {
		runCatching {
			val req = Request.Builder()
				.url("https://api.github.com/repos/${repo.fullName}/git/trees/${repo.defaultBranch}?recursive=1")
				.header("Accept", "application/vnd.github+json")
				.header("User-Agent", "TrueBlock/${BuildConfig.VERSION_NAME}")
				.build()

			_http.newCall(req).execute().use { resp ->
				if (!resp.isSuccessful) {
					val msg = if (resp.code == 403 || resp.code == 429) {
						"GitHub API rate limit exceeded (HTTP ${resp.code})"
					} else {
						"GitHub Tree HTTP ${resp.code}"
					}
					throw IllegalStateException(msg)
				}
				val body = resp.body?.string() ?: "{}"
				val tree = JSONObject(body).optJSONArray("tree") ?: return@use emptyList()
				val out = ArrayList<GitHubRawListCandidate>()
				for (i in 0 until tree.length()) {
					val node = tree.getJSONObject(i)
					if (node.optString("type") != "blob")
						continue
					val path = node.optString("path", "")
					val lower = path.lowercase()
					val size = node.optLong("size", 0L)
					if (size < 200L)
						continue
					val isCandidate = lower.endsWith(".txt") ||
						lower.endsWith(".hosts") ||
						lower.endsWith("hosts") ||
						lower.endsWith(".wildcards")
					val isDoc = lower.contains("readme") ||
						lower.contains("license") ||
						lower.contains("changelog") ||
						lower.contains("contributing") ||
						lower.startsWith(".")
					if (isCandidate && !isDoc) {
						val encodedBranch = URLEncoder.encode(repo.defaultBranch, "UTF-8").replace("+", "%20")
						val encodedPath = path.split('/').joinToString("/") { seg ->
							URLEncoder.encode(seg, "UTF-8").replace("+", "%20")
						}
						out.add(
							GitHubRawListCandidate(
								name = path.substringAfterLast('/'),
								path = path,
								rawUrl = "https://raw.githubusercontent.com/${repo.fullName}/$encodedBranch/$encodedPath",
								sizeBytes = size,
							)
						)
					}
					if (out.size >= 40)
						break
				}
				out
			}
		}
	}
}

val REMOVED_BLOCKLIST_IDS: List<String> = listOf(
	"1hosts_mini",
	"1hosts_lite",
	"1hosts_pro",
	"hagezi_tif",
	"urlhaus",
)

val BUILTIN_BLOCKLISTS: List<BlocklistSource> = listOf(
	BlocklistSource(
		id = "oisd_big",
		title = "OISD Big",
		url = "https://big.oisd.nl/domainswild",
		category = "Ads & Trackers",
		desc = "Comprehensive general-purpose ad and tracker blocklist with minimal false positives",
		isHighlight = true,
		isEnabled = true,
	),
	BlocklistSource(
		id = "adguard_dns",
		title = "AdGuard DNS Filter",
		url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
		category = "Ads & Trackers",
		desc = "Consolidated AdGuard filter (GitHub: AdguardTeam/AdGuardSDNSFilter)",
		isHighlight = true,
		isEnabled = true,
	),
	BlocklistSource(
		id = "adguard_mobile",
		title = "AdGuard Mobile Ads Filter",
		url = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
		category = "Mobile Ads",
		desc = "Dedicated filter for mobile in-app ad networks and SDK routes (GitHub: AdguardTeam)",
		isHighlight = true,
		isEnabled = false,
	),
	BlocklistSource(
		id = "hagezi_pro",
		title = "HaGeZi Multi PRO",
		url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
		category = "GitHub • HaGeZi",
		desc = "Balanced high-coverage blocklist (GitHub: hagezi/dns-blocklists)",
		isHighlight = true,
		isEnabled = false,
	),
	BlocklistSource(
		id = "hagezi_pro_plus",
		title = "HaGeZi Multi PRO++",
		url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
		category = "GitHub • HaGeZi",
		desc = "Aggressive multi-source ad, tracking, scam, and telemetry blocker",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "hagezi_ultimate",
		title = "HaGeZi Ultimate",
		url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
		category = "GitHub • HaGeZi",
		desc = "Maximum strictness privacy and ad shield from hagezi/dns-blocklists",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "hagezi_native_android",
		title = "HaGeZi Native Tracker (Xiaomi/Samsung/OEM)",
		url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt",
		category = "Privacy",
		desc = "Blocks native OS & OEM background telemetry on Android devices",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "hagezi_popup",
		title = "HaGeZi Anti-PopUps",
		url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt",
		category = "Web Routes & Ads",
		desc = "Blocks pop-under, redirect, and malvertising ad networks",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "easylist",
		title = "EasyList",
		url = "https://easylist.to/easylist/easylist.txt",
		category = "Web Routes & Ads",
		desc = "Primary web ad-blocking ruleset including URL path and route filters for HTTP/HTTPS",
		isHighlight = true,
		isEnabled = true,
	),
	BlocklistSource(
		id = "easyprivacy",
		title = "EasyPrivacy",
		url = "https://easylist.to/easylist/easyprivacy.txt",
		category = "Privacy",
		desc = "Web tracking scripts, analytics endpoints, beacons, and URL pixel routes",
		isHighlight = true,
		isEnabled = false,
	),
	BlocklistSource(
		id = "ublock_filters",
		title = "uBlock Origin Filters",
		url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
		category = "GitHub • uBlock",
		desc = "Official uBlock Origin network rules for routes, scripts, and WebSockets (uBlockOrigin/uAssets)",
		isHighlight = true,
		isEnabled = true,
	),
	BlocklistSource(
		id = "ublock_quick_fixes",
		title = "uBlock Origin Quick Fixes",
		url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt",
		category = "GitHub • uBlock",
		desc = "Rapidly updated daily ad-circumvention fixes from uBlockOrigin/uAssets",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "ublock_privacy",
		title = "uBlock Origin Privacy",
		url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
		category = "GitHub • uBlock",
		desc = "uBlock network rules blocking trackers and fingerprinting endpoints",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "ublock_badware",
		title = "uBlock Origin Badware Risks",
		url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
		category = "Security",
		desc = "Malicious sites, deceptive downloads, and exploit hosts maintained by uBlock",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "ublock_unbreak",
		title = "uBlock Origin Unbreak",
		url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
		category = "GitHub • uBlock",
		desc = "Essential allow-exceptions preventing broken websites when using strict lists",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "goodbyeads",
		title = "Goodbye Ads",
		url = "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
		category = "GitHub • Hosts",
		desc = "Mobile-focused ad and in-app analytics blocklist (GitHub: jerryn70/GoodbyeAds)",
		isHighlight = true,
		isEnabled = false,
	),
	BlocklistSource(
		id = "phishing_army",
		title = "Phishing Army Extended",
		url = "https://phishing.army/download/phishing_army_blocklist_extended.txt",
		category = "Security",
		desc = "Continuously updated phishing and credential-harvesting domains",
		isHighlight = true,
		isEnabled = true,
	),
	BlocklistSource(
		id = "oisd_small",
		title = "OISD Small",
		url = "https://small.oisd.nl/domainswild",
		category = "Ads & Trackers",
		desc = "Lightweight curated subset of OISD for minimal memory footprint",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "stevenblack",
		title = "StevenBlack Unified Hosts",
		url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		category = "GitHub • Hosts",
		desc = "Consolidated standard hosts file (GitHub: StevenBlack/hosts)",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "stevenblack_fakenews_gambling",
		title = "StevenBlack + Gambling & FakeNews",
		url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
		category = "GitHub • Hosts",
		desc = "Extended StevenBlack hosts blocking gambling and fake-news domains",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "dandelion_antimalware",
		title = "DandelionSprout Anti-Malware",
		url = "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
		category = "Security",
		desc = "Curated anti-malware & scam filter (GitHub: DandelionSprout/adfilt)",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "peter_lowe",
		title = "Peter Lowe's Ad & Tracking List",
		url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
		category = "Ads & Trackers",
		desc = "Long-running curated list of ad and tracking servers",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "disconnect_tracking",
		title = "Disconnect Tracking",
		url = "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		category = "Privacy",
		desc = "Tracker domains used by browser tracking protection",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "disconnect_ads",
		title = "Disconnect Ads",
		url = "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
		category = "Ads & Trackers",
		desc = "Advertising server domains curated by Disconnect",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "someonewhocares",
		title = "Dan Pollock's Hosts",
		url = "https://someonewhocares.org/hosts/zero/hosts",
		category = "Ads & Trackers",
		desc = "Zero-routed hosts blocking spyware, adware, and web beacons",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "spam404",
		title = "Spam404",
		url = "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
		category = "Security",
		desc = "Scam, spam, and fraudulent domains based on verified reports",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "nocoin",
		title = "NoCoin Filter List",
		url = "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
		category = "Security",
		desc = "Blocks browser-based crypto miners and WebSocket mining pools",
		isHighlight = false,
		isEnabled = false,
	),
	BlocklistSource(
		id = "perflyst_android",
		title = "Perflyst Android Tracking",
		url = "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
		category = "Privacy",
		desc = "OEM telemetry and Android system background tracking endpoints",
		isHighlight = false,
		isEnabled = false,
	),
)
