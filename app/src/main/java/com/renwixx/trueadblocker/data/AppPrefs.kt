package com.renwixx.trueadblocker.data

import android.content.Context
import androidx.compose.runtime.Immutable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

val DEFAULT_BROWSER_PACKAGES = setOf(
	"com.android.chrome",
	"com.chrome.beta",
	"com.chrome.dev",
	"com.chrome.canary",
	"com.brave.browser",
	"com.brave.browser_beta",
	"org.mozilla.firefox",
	"org.mozilla.firefox_beta",
	"org.mozilla.fenix",
	"com.microsoft.emmx",
	"com.vivaldi.browser",
	"com.opera.browser",
	"com.opera.gx",
	"com.sec.android.app.sbrowser",
	"com.duckduckgo.mobile.android",
	"com.kiwibrowser.browser",
	"org.cromite.cromite",
	"mark.via.gp",
)

const val DEFAULT_TRACKING_PARAM_RULES =
	"utm_*, fbclid, gclid, dclid, gbraid, wbraid, msclkid, yclid, ymclid, _openstat, " +
		"igshid, igsh, mc_cid, mc_eid, mkt_tok, _hsenc, _hsmi, vero_id, oly_enc_id, oly_anon_id, " +
		"rb_clickid, s_kwcid, wickedid, twclid, ttclid, li_fat_id, epik, spm, scm, si"

const val BLOCKED_DNS_ZERO_IP = 0
const val BLOCKED_DNS_NXDOMAIN = 1
const val BLOCKED_DNS_NODATA = 2

const val L3_MODE_AUTO = 0
const val L3_MODE_ALWAYS = 1
const val L3_MODE_OFF = 2

const val THEME_OLED = 0
const val THEME_DARK = 1
const val THEME_LIGHT = 2

data class BackupSections(
	val isGeneralConfig: Boolean = true,
	val isDnsAndNetworks: Boolean = true,
	val isAppsAndProxies: Boolean = true,
	val isCustomRules: Boolean = true,
	val isBlocklists: Boolean = true,
) {
	val hasAnySelected: Boolean
		get() = isGeneralConfig || isDnsAndNetworks || isAppsAndProxies || isCustomRules || isBlocklists
}

data class BackupInspection(
	val isPlainTextRules: Boolean = false,
	val hasGeneralConfig: Boolean = false,
	val hasDnsAndNetworks: Boolean = false,
	val hasAppsAndProxies: Boolean = false,
	val proxyCount: Int = 0,
	val hasCustomCss: Boolean = false,
	val customRulesCount: Int = 0,
	val blocklistsCount: Int = 0,
)

@Immutable
data class ProxyProfile(
	val id: String,
	val name: String,
	val isEnabled: Boolean = true,
	val type: String = "SOCKS5",
	val host: String,
	val port: Int,
	val username: String = "",
	val password: String = "",
	val isRemoteDns: Boolean = true,
	val isUdpRelay: Boolean = true,
	val isBlockUdpFallback: Boolean = true,
	val isAllApps: Boolean = false,
	val appPackages: Set<String> = emptySet(),
	val hostFilter: String = "*",
	val portFilter: String = "*",
) {
	fun toJson(): JSONObject {
		return JSONObject().apply {
			put("id", id)
			put("name", name)
			put("isEnabled", isEnabled)
			put("type", type)
			put("host", host)
			put("port", port)
			put("username", username)
			put("password", password)
			put("isRemoteDns", isRemoteDns)
			put("isUdpRelay", isUdpRelay)
			put("isBlockUdpFallback", isBlockUdpFallback)
			put("isAllApps", isAllApps)
			put("appPackages", JSONArray(appPackages.toList()))
			put("hostFilter", hostFilter)
			put("portFilter", portFilter)
		}
	}

	companion object {
		fun fromJson(o: JSONObject): ProxyProfile {
			val pkgs = HashSet<String>()
			o.optJSONArray("appPackages")?.let { arr ->
				for (i in 0 until arr.length())
					pkgs.add(arr.getString(i))
			}
			return ProxyProfile(
				id = o.optString("id", "proxy_${System.currentTimeMillis()}"),
				name = o.optString("name", "SOCKS5 Proxy"),
				isEnabled = o.optBoolean("isEnabled", true),
				type = o.optString("type", "SOCKS5"),
				host = o.optString("host", "127.0.0.1"),
				port = o.optInt("port", 1080).coerceIn(1, 65535),
				username = o.optString("username", ""),
				password = o.optString("password", ""),
				isRemoteDns = o.optBoolean("isRemoteDns", true),
				isUdpRelay = o.optBoolean("isUdpRelay", true),
				isBlockUdpFallback = o.optBoolean("isBlockUdpFallback", true),
				isAllApps = o.optBoolean("isAllApps", false),
				appPackages = pkgs,
				hostFilter = o.optString("hostFilter", "*"),
				portFilter = o.optString("portFilter", "*"),
			)
		}
	}
}

data class DnsPreset(
	val key: String,
	val name: String,
	val primaryIp: String,
	val secondaryIp: String,
	val dohUrl: String,
)

val DNS_PRESETS = listOf(
	DnsPreset("cloudflare", "Cloudflare", "1.1.1.1", "1.0.0.1", "https://cloudflare-dns.com/dns-query"),
	DnsPreset("google", "Google Public DNS", "8.8.8.8", "8.8.4.4", "https://dns.google/dns-query"),
	DnsPreset("quad9", "Quad9 Security", "9.9.9.9", "149.112.112.112", "https://dns.quad9.net/dns-query"),
	DnsPreset("adguard_unfiltered", "AdGuard Unfiltered", "94.140.14.140", "94.140.14.141", "https://unfiltered.adguard-dns.com/dns-query"),
	DnsPreset("mullvad", "Mullvad DNS", "194.242.2.2", "194.242.2.3", "https://dns.mullvad.net/dns-query"),
)

data class AppConfig(
	val isVpnDesired: Boolean = false,
	val isStartOnBoot: Boolean = false,
	val snoozeUntilMs: Long = 0L,
	val isHttpsFiltering: Boolean = false,
	val isStripHttpsDnsRecord: Boolean = true,
	val isCnameUncloaking: Boolean = true,
	val maxCnameDepth: Int = 8,
	val isRemoveTrackParams: Boolean = true,
	val trackedParamRules: String = DEFAULT_TRACKING_PARAM_RULES,
	val isCosmeticFiltering: Boolean = true,
	val maxGenericCosmeticSelectors: Int = 1200,
	val customCosmeticCss: String = "",
	val isUseDoh: Boolean = false,
	val isStrictDoh: Boolean = false,
	val dnsPresetKey: String = "cloudflare",
	val customDnsIp: String = "1.1.1.1",
	val customSecondaryDnsIp: String = "",
	val customDohUrl: String = "https://cloudflare-dns.com/dns-query",
	val isWifiProtection: Boolean = true,
	val isMobileProtection: Boolean = true,
	val isWifiUseDoh: Boolean = false,
	val isMobileUseDoh: Boolean = false,
	val isWifiCustomOverride: Boolean = false,
	val isMobileCustomOverride: Boolean = false,
	val wifiDnsIp: String = "1.1.1.1",
	val wifiSecondaryDnsIp: String = "",
	val wifiDohUrl: String = "",
	val mobileDnsIp: String = "1.1.1.1",
	val mobileSecondaryDnsIp: String = "",
	val mobileDohUrl: String = "",
	val isRawLoggingEnabled: Boolean = true,
	val maxAggEntries: Int = 500_000,
	val maxRawEntries: Int = 50_000,
	val logFlushIntervalMs: Int = 350,
	val logMaxBatchSize: Int = 512,
	val accentArgb: Int = 0xFF2979FF.toInt(),
	val isPureOled: Boolean = true,
	val themeMode: Int = THEME_OLED,
	val isAutoUpdateLists: Boolean = true,
	val autoUpdateIntervalHours: Int = 24,
	val lastAutoSyncMs: Long = 0L,
	val vpnClientIp: String = "10.111.222.2",
	val vpnDnsIp: String = "10.111.222.1",
	val vpnMtu: Int = 1500,
	val dnsWorkerThreads: Int = 12,
	val l3RoutingMode: Int = L3_MODE_AUTO,
	val isBlockIpv6: Boolean = false,
	val dnsCacheSize: Int = 2048,
	val dnsCacheTtlSec: Int = 90,
	val blockedDnsMode: Int = BLOCKED_DNS_ZERO_IP,
	val upstreamDnsTimeoutMs: Int = 3500,
	val proxyConnectTimeoutMs: Int = 10_000,
	val proxyReadTimeoutMs: Int = 20_000,
	val leafCertValidityDays: Int = 89,
	val bypassedApps: Set<String> = emptySet(),
	val httpsInspectedApps: Set<String> = DEFAULT_BROWSER_PACKAGES,
	val firewallWifiApps: Set<String> = emptySet(),
	val firewallMobileApps: Set<String> = emptySet(),
	val proxies: List<ProxyProfile> = emptyList(),
) {
	fun isAppBypassed(pkg: String): Boolean {
		return pkg.isNotEmpty() && bypassedApps.contains(pkg)
	}

	fun hasActiveUpstreamProxy(): Boolean {
		return proxies.any { it.isEnabled && it.host.isNotBlank() && (it.isAllApps || it.appPackages.isNotEmpty()) }
	}

	fun isAppFirewalled(pkg: String, isOnWifi: Boolean, isOnMobile: Boolean): Boolean {
		if (pkg.isEmpty() || bypassedApps.contains(pkg))
			return false
		if (isOnWifi && firewallWifiApps.contains(pkg))
			return true
		if (isOnMobile && firewallMobileApps.contains(pkg))
			return true
		if (!isOnWifi && !isOnMobile && firewallWifiApps.contains(pkg) && firewallMobileApps.contains(pkg))
			return true

		return false
	}

	fun shouldEnableFullL3Capture(isOnWifi: Boolean = true, isOnMobile: Boolean = true): Boolean {
		if (l3RoutingMode == L3_MODE_ALWAYS)
			return true
		if (l3RoutingMode == L3_MODE_OFF)
			return false

		val hasFirewall = when {
			isOnWifi -> firewallWifiApps.any { !bypassedApps.contains(it) }
			isOnMobile -> firewallMobileApps.any { !bypassedApps.contains(it) }
			else -> (firewallWifiApps + firewallMobileApps).any { !bypassedApps.contains(it) }
		}

		return hasFirewall || hasActiveUpstreamProxy()
	}

	fun activeDnsServers(isOnWifi: Boolean, isOnMobile: Boolean): Pair<String, String> {
		if (isOnWifi && isWifiCustomOverride && wifiDnsIp.isNotBlank())
			return wifiDnsIp.trim() to wifiSecondaryDnsIp.trim()
		if (isOnMobile && isMobileCustomOverride && mobileDnsIp.isNotBlank())
			return mobileDnsIp.trim() to mobileSecondaryDnsIp.trim()
		if (dnsPresetKey == "custom" && customDnsIp.isNotBlank())
			return customDnsIp.trim() to customSecondaryDnsIp.trim()

		val preset = DNS_PRESETS.firstOrNull { it.key == dnsPresetKey } ?: DNS_PRESETS.first()

		return preset.primaryIp to preset.secondaryIp
	}

	fun activeDohEndpoint(isOnWifi: Boolean, isOnMobile: Boolean): String? {
		if (isOnWifi && isWifiCustomOverride) {
			if (!isWifiUseDoh)
				return null
			if (wifiDohUrl.startsWith("https://"))
				return wifiDohUrl.trim()
		} else if (isOnMobile && isMobileCustomOverride) {
			if (!isMobileUseDoh)
				return null
			if (mobileDohUrl.startsWith("https://"))
				return mobileDohUrl.trim()
		} else if (!isUseDoh) {
			return null
		}

		if (dnsPresetKey == "custom" && customDohUrl.startsWith("https://"))
			return customDohUrl.trim()

		val preset = DNS_PRESETS.firstOrNull { it.key == dnsPresetKey } ?: DNS_PRESETS.first()

		return preset.dohUrl
	}

	fun sanitized(): AppConfig {
		val clampedTheme = themeMode.coerceIn(THEME_OLED, THEME_LIGHT)
		return copy(
			themeMode = clampedTheme,
			isPureOled = clampedTheme == THEME_OLED,
			maxCnameDepth = maxCnameDepth.coerceIn(1, 16),
			maxGenericCosmeticSelectors = maxGenericCosmeticSelectors.coerceIn(50, 5000),
			maxAggEntries = maxAggEntries.coerceIn(10_000, 2_000_000),
			maxRawEntries = maxRawEntries.coerceIn(1000, 500_000),
			logFlushIntervalMs = logFlushIntervalMs.coerceIn(50, 5000),
			logMaxBatchSize = logMaxBatchSize.coerceIn(32, 4096),
			autoUpdateIntervalHours = autoUpdateIntervalHours.coerceIn(1, 720),
			vpnMtu = vpnMtu.coerceIn(1280, 9000),
			dnsWorkerThreads = dnsWorkerThreads.coerceIn(2, 32),
			l3RoutingMode = l3RoutingMode.coerceIn(0, 2),
			dnsCacheSize = dnsCacheSize.coerceIn(64, 16384),
			dnsCacheTtlSec = dnsCacheTtlSec.coerceIn(5, 3600),
			blockedDnsMode = blockedDnsMode.coerceIn(0, 2),
			upstreamDnsTimeoutMs = upstreamDnsTimeoutMs.coerceIn(500, 15_000),
			proxyConnectTimeoutMs = proxyConnectTimeoutMs.coerceIn(1000, 30_000),
			proxyReadTimeoutMs = proxyReadTimeoutMs.coerceIn(2000, 60_000),
			leafCertValidityDays = leafCertValidityDays.coerceIn(1, 397),
		)
	}
}

class AppPrefs(ctx: Context) {
	private val _sp = ctx.applicationContext.getSharedPreferences("true_adblocker_prefs", Context.MODE_PRIVATE)
	private val _lock = Any()
	private val _state = MutableStateFlow(load())
	val state: StateFlow<AppConfig> = _state.asStateFlow()

	private fun load(): AppConfig {
		val isInit = _sp.getBoolean("is_initialized_https_apps", false)
		val inspected = if (!isInit) {
			_sp.edit()
				.putStringSet("https_inspected_apps", DEFAULT_BROWSER_PACKAGES)
				.putBoolean("is_initialized_https_apps", true)
				.apply()
			DEFAULT_BROWSER_PACKAGES
		} else {
			_sp.getStringSet("https_inspected_apps", DEFAULT_BROWSER_PACKAGES)?.toSet() ?: DEFAULT_BROWSER_PACKAGES
		}

		val proxiesJson = _sp.getString("proxy_profiles_json", "[]") ?: "[]"
		val parsedProxies = runCatching {
			val arr = JSONArray(proxiesJson)
			List(arr.length()) { i -> ProxyProfile.fromJson(arr.getJSONObject(i)) }
		}.getOrDefault(emptyList())

		val legacyOled = _sp.getBoolean("is_pure_oled", true)
		val loadedThemeMode = if (_sp.contains("theme_mode")) {
			_sp.getInt("theme_mode", THEME_OLED).coerceIn(THEME_OLED, THEME_LIGHT)
		} else {
			if (legacyOled) THEME_OLED else THEME_DARK
		}

		return AppConfig(
			isVpnDesired = _sp.getBoolean("is_vpn_desired", false),
			isStartOnBoot = _sp.getBoolean("is_start_on_boot", false),
			snoozeUntilMs = _sp.getLong("snooze_until_ms", 0L),
			isHttpsFiltering = _sp.getBoolean("is_https_filtering", false),
			isStripHttpsDnsRecord = _sp.getBoolean("is_strip_https_dns", true),
			isCnameUncloaking = _sp.getBoolean("is_cname_uncloaking", true),
			maxCnameDepth = _sp.getInt("max_cname_depth", 8),
			isRemoveTrackParams = _sp.getBoolean("is_remove_track_params", true),
			trackedParamRules = _sp.getString("tracked_param_rules", DEFAULT_TRACKING_PARAM_RULES)
				?: DEFAULT_TRACKING_PARAM_RULES,
			isCosmeticFiltering = _sp.getBoolean("is_cosmetic_filtering", true),
			maxGenericCosmeticSelectors = _sp.getInt("max_cosmetic_selectors", 1200),
			customCosmeticCss = _sp.getString("custom_cosmetic_css", "") ?: "",
			isUseDoh = _sp.getBoolean("is_use_doh", false),
			isStrictDoh = _sp.getBoolean("is_strict_doh", false),
			dnsPresetKey = _sp.getString("dns_preset_key", "cloudflare") ?: "cloudflare",
			customDnsIp = _sp.getString("custom_dns_ip", "1.1.1.1") ?: "1.1.1.1",
			customSecondaryDnsIp = _sp.getString("custom_secondary_dns_ip", "") ?: "",
			customDohUrl = _sp.getString("custom_doh_url", "https://cloudflare-dns.com/dns-query")
				?: "https://cloudflare-dns.com/dns-query",
			isWifiProtection = _sp.getBoolean("is_wifi_protection", true),
			isMobileProtection = _sp.getBoolean("is_mobile_protection", true),
			isWifiUseDoh = _sp.getBoolean("is_wifi_use_doh", false),
			isMobileUseDoh = _sp.getBoolean("is_mobile_use_doh", false),
			isWifiCustomOverride = _sp.getBoolean("is_wifi_override", false),
			isMobileCustomOverride = _sp.getBoolean("is_mobile_override", false),
			wifiDnsIp = _sp.getString("wifi_dns_ip", "1.1.1.1") ?: "1.1.1.1",
			wifiSecondaryDnsIp = _sp.getString("wifi_secondary_dns_ip", "") ?: "",
			wifiDohUrl = _sp.getString("wifi_doh_url", "") ?: "",
			mobileDnsIp = _sp.getString("mobile_dns_ip", "1.1.1.1") ?: "1.1.1.1",
			mobileSecondaryDnsIp = _sp.getString("mobile_secondary_dns_ip", "") ?: "",
			mobileDohUrl = _sp.getString("mobile_doh_url", "") ?: "",
			isRawLoggingEnabled = _sp.getBoolean("is_raw_logging", true),
			maxAggEntries = _sp.getInt("max_agg_entries", 500_000),
			maxRawEntries = _sp.getInt("max_raw_entries", 50_000),
			logFlushIntervalMs = _sp.getInt("log_flush_ms", 350),
			logMaxBatchSize = _sp.getInt("log_max_batch", 512),
			accentArgb = _sp.getInt("accent_argb", 0xFF2979FF.toInt()),
			isPureOled = loadedThemeMode == THEME_OLED,
			themeMode = loadedThemeMode,
			isAutoUpdateLists = _sp.getBoolean("is_auto_update_lists", true),
			autoUpdateIntervalHours = _sp.getInt("auto_update_hours", 24),
			lastAutoSyncMs = _sp.getLong("last_auto_sync_ms", 0L),
			vpnClientIp = _sp.getString("vpn_client_ip", "10.111.222.2") ?: "10.111.222.2",
			vpnDnsIp = _sp.getString("vpn_dns_ip", "10.111.222.1") ?: "10.111.222.1",
			vpnMtu = _sp.getInt("vpn_mtu", 1500),
			dnsWorkerThreads = _sp.getInt("dns_worker_threads", 12),
			l3RoutingMode = _sp.getInt("l3_routing_mode", L3_MODE_AUTO),
			isBlockIpv6 = _sp.getBoolean("is_block_ipv6", false),
			dnsCacheSize = _sp.getInt("dns_cache_size", 2048),
			dnsCacheTtlSec = _sp.getInt("dns_cache_ttl_sec", 90),
			blockedDnsMode = _sp.getInt("blocked_dns_mode", BLOCKED_DNS_ZERO_IP),
			upstreamDnsTimeoutMs = _sp.getInt("upstream_dns_timeout_ms", 3500),
			proxyConnectTimeoutMs = _sp.getInt("proxy_connect_timeout_ms", 10_000),
			proxyReadTimeoutMs = _sp.getInt("proxy_read_timeout_ms", 20_000),
			leafCertValidityDays = _sp.getInt("leaf_cert_days", 89),
			bypassedApps = _sp.getStringSet("bypassed_apps", emptySet())?.toSet() ?: emptySet(),
			httpsInspectedApps = inspected,
			firewallWifiApps = _sp.getStringSet("firewall_wifi_apps", emptySet())?.toSet() ?: emptySet(),
			firewallMobileApps = _sp.getStringSet("firewall_mobile_apps", emptySet())?.toSet() ?: emptySet(),
			proxies = parsedProxies,
		).sanitized()
	}

	fun update(transform: (AppConfig) -> AppConfig) {
		synchronized(_lock) {
			val prev = _state.value
			val next = transform(prev).sanitized()
			if (next == prev)
				return

			val ed = _sp.edit()
			if (next.isVpnDesired != prev.isVpnDesired) ed.putBoolean("is_vpn_desired", next.isVpnDesired)
			if (next.isStartOnBoot != prev.isStartOnBoot) ed.putBoolean("is_start_on_boot", next.isStartOnBoot)
			if (next.snoozeUntilMs != prev.snoozeUntilMs) ed.putLong("snooze_until_ms", next.snoozeUntilMs)
			if (next.isHttpsFiltering != prev.isHttpsFiltering) ed.putBoolean("is_https_filtering", next.isHttpsFiltering)
			if (next.isStripHttpsDnsRecord != prev.isStripHttpsDnsRecord) ed.putBoolean("is_strip_https_dns", next.isStripHttpsDnsRecord)
			if (next.isCnameUncloaking != prev.isCnameUncloaking) ed.putBoolean("is_cname_uncloaking", next.isCnameUncloaking)
			if (next.maxCnameDepth != prev.maxCnameDepth) ed.putInt("max_cname_depth", next.maxCnameDepth)
			if (next.isRemoveTrackParams != prev.isRemoveTrackParams) ed.putBoolean("is_remove_track_params", next.isRemoveTrackParams)
			if (next.trackedParamRules != prev.trackedParamRules) ed.putString("tracked_param_rules", next.trackedParamRules)
			if (next.isCosmeticFiltering != prev.isCosmeticFiltering) ed.putBoolean("is_cosmetic_filtering", next.isCosmeticFiltering)
			if (next.maxGenericCosmeticSelectors != prev.maxGenericCosmeticSelectors) ed.putInt("max_cosmetic_selectors", next.maxGenericCosmeticSelectors)
			if (next.customCosmeticCss != prev.customCosmeticCss) ed.putString("custom_cosmetic_css", next.customCosmeticCss)
			if (next.isUseDoh != prev.isUseDoh) ed.putBoolean("is_use_doh", next.isUseDoh)
			if (next.isStrictDoh != prev.isStrictDoh) ed.putBoolean("is_strict_doh", next.isStrictDoh)
			if (next.dnsPresetKey != prev.dnsPresetKey) ed.putString("dns_preset_key", next.dnsPresetKey)
			if (next.customDnsIp != prev.customDnsIp) ed.putString("custom_dns_ip", next.customDnsIp)
			if (next.customSecondaryDnsIp != prev.customSecondaryDnsIp) ed.putString("custom_secondary_dns_ip", next.customSecondaryDnsIp)
			if (next.customDohUrl != prev.customDohUrl) ed.putString("custom_doh_url", next.customDohUrl)
			if (next.isWifiProtection != prev.isWifiProtection) ed.putBoolean("is_wifi_protection", next.isWifiProtection)
			if (next.isMobileProtection != prev.isMobileProtection) ed.putBoolean("is_mobile_protection", next.isMobileProtection)
			if (next.isWifiUseDoh != prev.isWifiUseDoh) ed.putBoolean("is_wifi_use_doh", next.isWifiUseDoh)
			if (next.isMobileUseDoh != prev.isMobileUseDoh) ed.putBoolean("is_mobile_use_doh", next.isMobileUseDoh)
			if (next.isWifiCustomOverride != prev.isWifiCustomOverride) ed.putBoolean("is_wifi_override", next.isWifiCustomOverride)
			if (next.isMobileCustomOverride != prev.isMobileCustomOverride) ed.putBoolean("is_mobile_override", next.isMobileCustomOverride)
			if (next.wifiDnsIp != prev.wifiDnsIp) ed.putString("wifi_dns_ip", next.wifiDnsIp)
			if (next.wifiSecondaryDnsIp != prev.wifiSecondaryDnsIp) ed.putString("wifi_secondary_dns_ip", next.wifiSecondaryDnsIp)
			if (next.wifiDohUrl != prev.wifiDohUrl) ed.putString("wifi_doh_url", next.wifiDohUrl)
			if (next.mobileDnsIp != prev.mobileDnsIp) ed.putString("mobile_dns_ip", next.mobileDnsIp)
			if (next.mobileSecondaryDnsIp != prev.mobileSecondaryDnsIp) ed.putString("mobile_secondary_dns_ip", next.mobileSecondaryDnsIp)
			if (next.mobileDohUrl != prev.mobileDohUrl) ed.putString("mobile_doh_url", next.mobileDohUrl)
			if (next.isRawLoggingEnabled != prev.isRawLoggingEnabled) ed.putBoolean("is_raw_logging", next.isRawLoggingEnabled)
			if (next.maxAggEntries != prev.maxAggEntries) ed.putInt("max_agg_entries", next.maxAggEntries)
			if (next.maxRawEntries != prev.maxRawEntries) ed.putInt("max_raw_entries", next.maxRawEntries)
			if (next.logFlushIntervalMs != prev.logFlushIntervalMs) ed.putInt("log_flush_ms", next.logFlushIntervalMs)
			if (next.logMaxBatchSize != prev.logMaxBatchSize) ed.putInt("log_max_batch", next.logMaxBatchSize)
			if (next.accentArgb != prev.accentArgb) ed.putInt("accent_argb", next.accentArgb)
			if (next.isPureOled != prev.isPureOled) ed.putBoolean("is_pure_oled", next.isPureOled)
			if (next.themeMode != prev.themeMode) ed.putInt("theme_mode", next.themeMode)
			if (next.isAutoUpdateLists != prev.isAutoUpdateLists) ed.putBoolean("is_auto_update_lists", next.isAutoUpdateLists)
			if (next.autoUpdateIntervalHours != prev.autoUpdateIntervalHours) ed.putInt("auto_update_hours", next.autoUpdateIntervalHours)
			if (next.lastAutoSyncMs != prev.lastAutoSyncMs) ed.putLong("last_auto_sync_ms", next.lastAutoSyncMs)
			if (next.vpnClientIp != prev.vpnClientIp) ed.putString("vpn_client_ip", next.vpnClientIp)
			if (next.vpnDnsIp != prev.vpnDnsIp) ed.putString("vpn_dns_ip", next.vpnDnsIp)
			if (next.vpnMtu != prev.vpnMtu) ed.putInt("vpn_mtu", next.vpnMtu)
			if (next.dnsWorkerThreads != prev.dnsWorkerThreads) ed.putInt("dns_worker_threads", next.dnsWorkerThreads)
			if (next.l3RoutingMode != prev.l3RoutingMode) ed.putInt("l3_routing_mode", next.l3RoutingMode)
			if (next.isBlockIpv6 != prev.isBlockIpv6) ed.putBoolean("is_block_ipv6", next.isBlockIpv6)
			if (next.dnsCacheSize != prev.dnsCacheSize) ed.putInt("dns_cache_size", next.dnsCacheSize)
			if (next.dnsCacheTtlSec != prev.dnsCacheTtlSec) ed.putInt("dns_cache_ttl_sec", next.dnsCacheTtlSec)
			if (next.blockedDnsMode != prev.blockedDnsMode) ed.putInt("blocked_dns_mode", next.blockedDnsMode)
			if (next.upstreamDnsTimeoutMs != prev.upstreamDnsTimeoutMs) ed.putInt("upstream_dns_timeout_ms", next.upstreamDnsTimeoutMs)
			if (next.proxyConnectTimeoutMs != prev.proxyConnectTimeoutMs) ed.putInt("proxy_connect_timeout_ms", next.proxyConnectTimeoutMs)
			if (next.proxyReadTimeoutMs != prev.proxyReadTimeoutMs) ed.putInt("proxy_read_timeout_ms", next.proxyReadTimeoutMs)
			if (next.leafCertValidityDays != prev.leafCertValidityDays) ed.putInt("leaf_cert_days", next.leafCertValidityDays)
			if (next.bypassedApps != prev.bypassedApps) ed.putStringSet("bypassed_apps", next.bypassedApps)
			if (next.httpsInspectedApps != prev.httpsInspectedApps) ed.putStringSet("https_inspected_apps", next.httpsInspectedApps)
			if (next.firewallWifiApps != prev.firewallWifiApps) ed.putStringSet("firewall_wifi_apps", next.firewallWifiApps)
			if (next.firewallMobileApps != prev.firewallMobileApps) ed.putStringSet("firewall_mobile_apps", next.firewallMobileApps)
			if (next.proxies != prev.proxies) {
				val proxyArr = JSONArray().apply {
					for (p in next.proxies)
						put(p.toJson())
				}
				ed.putString("proxy_profiles_json", proxyArr.toString())
			}
			ed.apply()
			_state.value = next
		}
	}

	fun resetEngineTuningToDefaults() {
		update { cur ->
			val def = AppConfig()
			cur.copy(
				vpnClientIp = def.vpnClientIp,
				vpnDnsIp = def.vpnDnsIp,
				vpnMtu = def.vpnMtu,
				dnsWorkerThreads = def.dnsWorkerThreads,
				l3RoutingMode = def.l3RoutingMode,
				isBlockIpv6 = def.isBlockIpv6,
				dnsCacheSize = def.dnsCacheSize,
				dnsCacheTtlSec = def.dnsCacheTtlSec,
				blockedDnsMode = def.blockedDnsMode,
				upstreamDnsTimeoutMs = def.upstreamDnsTimeoutMs,
				proxyConnectTimeoutMs = def.proxyConnectTimeoutMs,
				proxyReadTimeoutMs = def.proxyReadTimeoutMs,
				leafCertValidityDays = def.leafCertValidityDays,
				logFlushIntervalMs = def.logFlushIntervalMs,
				logMaxBatchSize = def.logMaxBatchSize,
				maxCnameDepth = def.maxCnameDepth,
				maxGenericCosmeticSelectors = def.maxGenericCosmeticSelectors,
				trackedParamRules = def.trackedParamRules,
			)
		}
	}

	suspend fun exportJson(db: AppDatabase, sections: BackupSections = BackupSections()): String {
		val cfg = _state.value
		val root = JSONObject()
		root.put("version", 3)
		root.put("exportedAt", System.currentTimeMillis())

		if (sections.isGeneralConfig || sections.isDnsAndNetworks || sections.isAppsAndProxies) {
			val settingsObj = JSONObject()
			if (sections.isGeneralConfig) {
				settingsObj.put("isStartOnBoot", cfg.isStartOnBoot)
				settingsObj.put("isHttpsFiltering", cfg.isHttpsFiltering)
				settingsObj.put("isStripHttpsDnsRecord", cfg.isStripHttpsDnsRecord)
				settingsObj.put("isCnameUncloaking", cfg.isCnameUncloaking)
				settingsObj.put("maxCnameDepth", cfg.maxCnameDepth)
				settingsObj.put("isRemoveTrackParams", cfg.isRemoveTrackParams)
				settingsObj.put("trackedParamRules", cfg.trackedParamRules)
				settingsObj.put("isCosmeticFiltering", cfg.isCosmeticFiltering)
				settingsObj.put("maxGenericCosmeticSelectors", cfg.maxGenericCosmeticSelectors)
				settingsObj.put("customCosmeticCss", cfg.customCosmeticCss)
				settingsObj.put("isRawLoggingEnabled", cfg.isRawLoggingEnabled)
				settingsObj.put("maxAggEntries", cfg.maxAggEntries)
				settingsObj.put("maxRawEntries", cfg.maxRawEntries)
				settingsObj.put("logFlushIntervalMs", cfg.logFlushIntervalMs)
				settingsObj.put("logMaxBatchSize", cfg.logMaxBatchSize)
				settingsObj.put("accentArgb", cfg.accentArgb)
				settingsObj.put("isPureOled", cfg.isPureOled)
				settingsObj.put("themeMode", cfg.themeMode)
				settingsObj.put("isAutoUpdateLists", cfg.isAutoUpdateLists)
				settingsObj.put("autoUpdateIntervalHours", cfg.autoUpdateIntervalHours)
				settingsObj.put("vpnClientIp", cfg.vpnClientIp)
				settingsObj.put("vpnDnsIp", cfg.vpnDnsIp)
				settingsObj.put("vpnMtu", cfg.vpnMtu)
				settingsObj.put("dnsWorkerThreads", cfg.dnsWorkerThreads)
				settingsObj.put("l3RoutingMode", cfg.l3RoutingMode)
				settingsObj.put("isBlockIpv6", cfg.isBlockIpv6)
				settingsObj.put("dnsCacheSize", cfg.dnsCacheSize)
				settingsObj.put("dnsCacheTtlSec", cfg.dnsCacheTtlSec)
				settingsObj.put("blockedDnsMode", cfg.blockedDnsMode)
				settingsObj.put("upstreamDnsTimeoutMs", cfg.upstreamDnsTimeoutMs)
				settingsObj.put("proxyConnectTimeoutMs", cfg.proxyConnectTimeoutMs)
				settingsObj.put("proxyReadTimeoutMs", cfg.proxyReadTimeoutMs)
				settingsObj.put("leafCertValidityDays", cfg.leafCertValidityDays)
			}

			if (sections.isDnsAndNetworks) {
				settingsObj.put("isUseDoh", cfg.isUseDoh)
				settingsObj.put("isStrictDoh", cfg.isStrictDoh)
				settingsObj.put("dnsPresetKey", cfg.dnsPresetKey)
				settingsObj.put("customDnsIp", cfg.customDnsIp)
				settingsObj.put("customSecondaryDnsIp", cfg.customSecondaryDnsIp)
				settingsObj.put("customDohUrl", cfg.customDohUrl)
				settingsObj.put("isWifiProtection", cfg.isWifiProtection)
				settingsObj.put("isMobileProtection", cfg.isMobileProtection)
				settingsObj.put("isWifiUseDoh", cfg.isWifiUseDoh)
				settingsObj.put("isMobileUseDoh", cfg.isMobileUseDoh)
				settingsObj.put("isWifiCustomOverride", cfg.isWifiCustomOverride)
				settingsObj.put("isMobileCustomOverride", cfg.isMobileCustomOverride)
				settingsObj.put("wifiDnsIp", cfg.wifiDnsIp)
				settingsObj.put("wifiSecondaryDnsIp", cfg.wifiSecondaryDnsIp)
				settingsObj.put("wifiDohUrl", cfg.wifiDohUrl)
				settingsObj.put("mobileDnsIp", cfg.mobileDnsIp)
				settingsObj.put("mobileSecondaryDnsIp", cfg.mobileSecondaryDnsIp)
				settingsObj.put("mobileDohUrl", cfg.mobileDohUrl)
			}

			if (sections.isAppsAndProxies) {
				val proxyArr = JSONArray().apply {
					for (p in cfg.proxies)
						put(p.toJson())
				}
				settingsObj.put("bypassedApps", JSONArray(cfg.bypassedApps.toList()))
				settingsObj.put("httpsInspectedApps", JSONArray(cfg.httpsInspectedApps.toList()))
				settingsObj.put("firewallWifiApps", JSONArray(cfg.firewallWifiApps.toList()))
				settingsObj.put("firewallMobileApps", JSONArray(cfg.firewallMobileApps.toList()))
				settingsObj.put("proxies", proxyArr)
			}

			root.put("settings", settingsObj)
		}

		if (sections.isCustomRules) {
			val rules = db.ruleDao().getAll()
			val rulesArr = JSONArray()
			for (r in rules) {
				rulesArr.put(
					JSONObject().apply {
						put("pattern", r.pattern)
						put("matchMode", r.matchMode)
						put("isAllow", r.isAllow)
						put("isRoute", r.isRoute)
						put("isEnabled", r.isEnabled)
						put("note", r.note)
					}
				)
			}
			root.put("customRules", rulesArr)
		}

		if (sections.isBlocklists) {
			val lists = db.blocklistDao().getAll()
			val listsArr = JSONArray()
			for (b in lists) {
				listsArr.put(
					JSONObject().apply {
						put("id", b.id)
						put("title", b.title)
						put("url", b.url)
						put("category", b.category)
						put("desc", b.desc)
						put("isHighlight", b.isHighlight)
						put("isEnabled", b.isEnabled)
					}
				)
			}
			root.put("blocklists", listsArr)
		}

		return root.toString(2)
	}

	fun inspectBackupContent(rawText: String): BackupInspection {
		val trimmed = rawText.trim()
		if (!trimmed.startsWith("{")) {
			val ruleLines = parsePlainTextRules(trimmed)
			return BackupInspection(
				isPlainTextRules = true,
				customRulesCount = ruleLines.size,
			)
		}

		val root = JSONObject(trimmed)
		val s = root.optJSONObject("settings")
		val hasGeneral = s != null && (
			s.has("isStartOnBoot") || s.has("isHttpsFiltering") || s.has("themeMode") ||
				s.has("isPureOled") || s.has("vpnMtu") || s.has("trackedParamRules") || s.has("customCosmeticCss")
			)
		val hasDns = s != null && (
			s.has("dnsPresetKey") || s.has("isUseDoh") || s.has("customDnsIp") ||
				s.has("isWifiProtection") || s.has("isMobileProtection")
			)
		val proxiesLen = s?.optJSONArray("proxies")?.length() ?: 0
		val hasApps = s != null && (
			s.has("bypassedApps") || s.has("httpsInspectedApps") ||
				s.has("firewallWifiApps") || s.has("firewallMobileApps") || s.has("proxies")
			)
		val hasCss = s?.optString("customCosmeticCss", "")?.isNotBlank() == true
		val rulesCnt = root.optJSONArray("customRules")?.length() ?: 0
		val listsCnt = root.optJSONArray("blocklists")?.length() ?: 0

		return BackupInspection(
			isPlainTextRules = false,
			hasGeneralConfig = hasGeneral,
			hasDnsAndNetworks = hasDns,
			hasAppsAndProxies = hasApps,
			proxyCount = proxiesLen,
			hasCustomCss = hasCss,
			customRulesCount = rulesCnt,
			blocklistsCount = listsCnt,
		)
	}

	suspend fun importJson(
		jsonText: String,
		db: AppDatabase,
		sections: BackupSections = BackupSections(),
	) {
		val trimmed = jsonText.trim()
		if (!trimmed.startsWith("{")) {
			if (!sections.isCustomRules)
				return
			val plainRules = parsePlainTextRules(trimmed)
			if (plainRules.isNotEmpty())
				db.ruleDao().upsertAll(plainRules)
			return
		}

		val root = JSONObject(trimmed)
		root.optJSONObject("settings")?.let { s ->
			fun readSet(key: String): Set<String>? {
				val arr = s.optJSONArray(key) ?: return null
				val out = HashSet<String>(arr.length())
				for (i in 0 until arr.length())
					out.add(arr.getString(i))
				return out
			}

			val importedProxies = if (sections.isAppsAndProxies) {
				s.optJSONArray("proxies")?.let { arr ->
					List(arr.length()) { i -> ProxyProfile.fromJson(arr.getJSONObject(i)) }
				}
			} else {
				null
			}

			update { cur ->
				var next = cur
				if (sections.isGeneralConfig) {
					val importedTheme = if (s.has("themeMode")) {
						s.optInt("themeMode", cur.themeMode)
					} else if (s.has("isPureOled")) {
						if (s.optBoolean("isPureOled", true)) THEME_OLED else THEME_DARK
					} else {
						cur.themeMode
					}
					next = next.copy(
						isStartOnBoot = s.optBoolean("isStartOnBoot", next.isStartOnBoot),
						isHttpsFiltering = s.optBoolean("isHttpsFiltering", next.isHttpsFiltering),
						isStripHttpsDnsRecord = s.optBoolean("isStripHttpsDnsRecord", next.isStripHttpsDnsRecord),
						isCnameUncloaking = s.optBoolean("isCnameUncloaking", next.isCnameUncloaking),
						maxCnameDepth = s.optInt("maxCnameDepth", next.maxCnameDepth),
						isRemoveTrackParams = s.optBoolean("isRemoveTrackParams", next.isRemoveTrackParams),
						trackedParamRules = s.optString("trackedParamRules", next.trackedParamRules),
						isCosmeticFiltering = s.optBoolean("isCosmeticFiltering", next.isCosmeticFiltering),
						maxGenericCosmeticSelectors = s.optInt("maxGenericCosmeticSelectors", next.maxGenericCosmeticSelectors),
						customCosmeticCss = s.optString("customCosmeticCss", next.customCosmeticCss),
						isRawLoggingEnabled = s.optBoolean("isRawLoggingEnabled", next.isRawLoggingEnabled),
						maxAggEntries = s.optInt("maxAggEntries", next.maxAggEntries),
						maxRawEntries = s.optInt("maxRawEntries", next.maxRawEntries),
						logFlushIntervalMs = s.optInt("logFlushIntervalMs", next.logFlushIntervalMs),
						logMaxBatchSize = s.optInt("logMaxBatchSize", next.logMaxBatchSize),
						accentArgb = s.optInt("accentArgb", next.accentArgb),
						themeMode = importedTheme,
						isPureOled = importedTheme == THEME_OLED,
						isAutoUpdateLists = s.optBoolean("isAutoUpdateLists", next.isAutoUpdateLists),
						autoUpdateIntervalHours = s.optInt("autoUpdateIntervalHours", next.autoUpdateIntervalHours),
						vpnClientIp = s.optString("vpnClientIp", next.vpnClientIp),
						vpnDnsIp = s.optString("vpnDnsIp", next.vpnDnsIp),
						vpnMtu = s.optInt("vpnMtu", next.vpnMtu),
						dnsWorkerThreads = s.optInt("dnsWorkerThreads", next.dnsWorkerThreads),
						l3RoutingMode = s.optInt("l3RoutingMode", next.l3RoutingMode),
						isBlockIpv6 = s.optBoolean("isBlockIpv6", next.isBlockIpv6),
						dnsCacheSize = s.optInt("dnsCacheSize", next.dnsCacheSize),
						dnsCacheTtlSec = s.optInt("dnsCacheTtlSec", next.dnsCacheTtlSec),
						blockedDnsMode = s.optInt("blockedDnsMode", next.blockedDnsMode),
						upstreamDnsTimeoutMs = s.optInt("upstreamDnsTimeoutMs", next.upstreamDnsTimeoutMs),
						proxyConnectTimeoutMs = s.optInt("proxyConnectTimeoutMs", next.proxyConnectTimeoutMs),
						proxyReadTimeoutMs = s.optInt("proxyReadTimeoutMs", next.proxyReadTimeoutMs),
						leafCertValidityDays = s.optInt("leafCertValidityDays", next.leafCertValidityDays),
					)
				}

				if (sections.isDnsAndNetworks) {
					next = next.copy(
						isUseDoh = s.optBoolean("isUseDoh", next.isUseDoh),
						isStrictDoh = s.optBoolean("isStrictDoh", next.isStrictDoh),
						dnsPresetKey = s.optString("dnsPresetKey", next.dnsPresetKey),
						customDnsIp = s.optString("customDnsIp", next.customDnsIp),
						customSecondaryDnsIp = s.optString("customSecondaryDnsIp", next.customSecondaryDnsIp),
						customDohUrl = s.optString("customDohUrl", next.customDohUrl),
						isWifiProtection = s.optBoolean("isWifiProtection", next.isWifiProtection),
						isMobileProtection = s.optBoolean("isMobileProtection", next.isMobileProtection),
						isWifiUseDoh = s.optBoolean("isWifiUseDoh", next.isWifiUseDoh),
						isMobileUseDoh = s.optBoolean("isMobileUseDoh", next.isMobileUseDoh),
						isWifiCustomOverride = s.optBoolean("isWifiCustomOverride", next.isWifiCustomOverride),
						isMobileCustomOverride = s.optBoolean("isMobileCustomOverride", next.isMobileCustomOverride),
						wifiDnsIp = s.optString("wifiDnsIp", next.wifiDnsIp),
						wifiSecondaryDnsIp = s.optString("wifiSecondaryDnsIp", next.wifiSecondaryDnsIp),
						wifiDohUrl = s.optString("wifiDohUrl", next.wifiDohUrl),
						mobileDnsIp = s.optString("mobileDnsIp", next.mobileDnsIp),
						mobileSecondaryDnsIp = s.optString("mobileSecondaryDnsIp", next.mobileSecondaryDnsIp),
						mobileDohUrl = s.optString("mobileDohUrl", next.mobileDohUrl),
					)
				}

				if (sections.isAppsAndProxies) {
					next = next.copy(
						bypassedApps = readSet("bypassedApps") ?: next.bypassedApps,
						httpsInspectedApps = readSet("httpsInspectedApps") ?: next.httpsInspectedApps,
						firewallWifiApps = readSet("firewallWifiApps") ?: next.firewallWifiApps,
						firewallMobileApps = readSet("firewallMobileApps") ?: next.firewallMobileApps,
						proxies = importedProxies ?: next.proxies,
					)
				}

				next
			}
		}

		if (sections.isCustomRules) {
			root.optJSONArray("customRules")?.let { arr ->
				val imported = ArrayList<CustomRule>(arr.length())
				for (i in 0 until arr.length()) {
					val o = arr.getJSONObject(i)
					imported.add(
						CustomRule(
							pattern = o.getString("pattern"),
							matchMode = o.optInt("matchMode", MODE_EXACT),
							isAllow = o.optBoolean("isAllow", false),
							isRoute = o.optBoolean("isRoute", o.getString("pattern").contains('/')),
							isEnabled = o.optBoolean("isEnabled", true),
							note = o.optString("note", ""),
						)
					)
				}
				if (imported.isNotEmpty())
					db.ruleDao().upsertAll(imported)
			}
		}

		if (sections.isBlocklists) {
			root.optJSONArray("blocklists")?.let { arr ->
				for (i in 0 until arr.length()) {
					val o = arr.getJSONObject(i)
					val safeId = sanitizeBlocklistId(o.getString("id"))
					if (safeId.isEmpty())
						continue
					val rawUrl = o.getString("url").trim()
					if (!rawUrl.startsWith("https://"))
						continue
					db.blocklistDao().upsert(
						BlocklistSource(
							id = safeId,
							title = o.getString("title"),
							url = rawUrl,
							category = o.optString("category", "Custom"),
							desc = o.optString("desc", ""),
							isHighlight = o.optBoolean("isHighlight", false),
							isEnabled = o.optBoolean("isEnabled", false),
						)
					)
				}
			}
		}
	}

	private fun parsePlainTextRules(trimmed: String): List<CustomRule> {
		return trimmed.lineSequence()
			.map { it.trim() }
			.filter {
				it.isNotEmpty() &&
					!it.startsWith("#") &&
					!it.startsWith("!") &&
					!it.startsWith("[") &&
					!it.contains("##") &&
					!it.contains("#@#") &&
					!it.contains("#?#") &&
					!it.contains("#$#") &&
					!it.contains("#%#")
			}
			.mapNotNull { rawLine ->
				var line = rawLine
				val commentIdx = line.indexOfFirst { it == '#' }
				if (commentIdx > 0 && (line[commentIdx - 1] == ' ' || line[commentIdx - 1] == '\t'))
					line = line.substring(0, commentIdx).trim()

				if (
					line.startsWith("0.0.0.0 ") ||
					line.startsWith("127.0.0.1 ") ||
					line.startsWith("0.0.0.0\t") ||
					line.startsWith("127.0.0.1\t") ||
					line.startsWith("::1 ") ||
					line.startsWith("::1\t") ||
					line.startsWith(":: ") ||
					line.startsWith("::\t")
				) {
					val ws = line.indexOfFirst { it == ' ' || it == '\t' }
					line = line.substring(ws + 1).trim().split(Regex("\\s+")).firstOrNull().orEmpty()
				}

				val dollarIdx = line.indexOf('$')
				if (dollarIdx >= 0) {
					val mods = line.substring(dollarIdx + 1).lowercase()
					if (
						mods.contains("badfilter") ||
						mods.contains("elemhide") ||
						mods.contains("generichide") ||
						mods.contains("specifichide") ||
						mods.contains("csp=") ||
						mods.contains("removeparam") ||
						mods.contains("popup")
					) {
						return@mapNotNull null
					}
					line = line.substring(0, dollarIdx).trim()
				}

				val isAllow = line.startsWith("@@")
				val clean = line
					.removePrefix("@@")
					.removePrefix("||")
					.removeSuffix("^")
					.removeSuffix("|")
					.trim()
				if (clean.isEmpty() || clean == "localhost" || clean == "0.0.0.0" || clean == "127.0.0.1")
					return@mapNotNull null

				val isWildcard = clean.contains('*') || clean.contains('?')
				val isRoute = clean.contains('/')
				CustomRule(
					pattern = clean,
					matchMode = if (isWildcard) MODE_WILDCARD else MODE_EXACT,
					isAllow = isAllow,
					isRoute = isRoute,
					isEnabled = true,
				)
			}
			.toList()
	}
}

fun sanitizeBlocklistId(raw: String): String {
	return raw.trim()
		.replace(Regex("[^a-zA-Z0-9_-]"), "_")
		.trim('_')
		.take(64)
}
