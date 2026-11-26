package com.renwixx.trueadblocker.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.paging.compose.collectAsLazyPagingItems
import com.renwixx.trueadblocker.data.AggregatedLog
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.RawLog
import com.renwixx.trueadblocker.ui.theme.ShieldGreen
import com.renwixx.trueadblocker.ui.theme.ShieldRed
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

@Composable
fun HomeScreen(
	vm: MainViewModel,
	onToggleVpn: () -> Unit,
	onOpenHttpsSetup: () -> Unit,
	onOpenActivity: () -> Unit,
	onOpenSettings: () -> Unit,
	onOpenEngineConfig: () -> Unit = {},
) {
	val vpn by vm.vpnState.collectAsState()
	val cfg by vm.config.collectAsState()
	val stats by vm.engineStats.collectAsState()
	val ca by vm.caStatus.collectAsState()
	val totalRequests by vm.totalRequests.collectAsState()
	val totalBlocked by vm.totalBlocked.collectAsState()
	val totalParamsRemoved by vm.totalTrackerParamsRemoved.collectAsState()
	val totalCname by vm.totalCnameUncloaked.collectAsState()
	val installedSet by vm.installedPkgSet.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var isMenuOpen by remember { mutableStateOf(false) }

	val isActive = vpn.isRunning && !vpn.isPausedByNetworkRule && !vpn.isSnoozed
	val pulse = if (isActive) {
		val inf = rememberInfiniteTransition(label = "ring")
		val animated by inf.animateFloat(
			initialValue = 0.96f,
			targetValue = 1.04f,
			animationSpec = infiniteRepeatable(
				animation = tween(2200, easing = FastOutSlowInEasing),
				repeatMode = RepeatMode.Reverse,
			),
			label = "pulse",
		)
		animated
	} else {
		1f
	}
	val statusHeadline = when {
		vpn.isRunning && vpn.isSnoozed -> {
			val mm = vpn.snoozeRemainingSec / 60
			val ss = vpn.snoozeRemainingSec % 60
			"SNOOZED (%d:%02d)".format(mm, ss)
		}
		vpn.isRunning && vpn.isPausedByNetworkRule -> "PAUSED (${vpn.activeTransport.uppercase()})"
		vpn.isRunning -> "ACTIVE"
		else -> "DEACTIVATED"
	}

	Column(
		modifier = Modifier
			.fillMaxSize()
			.padding(horizontal = 20.dp, vertical = 10.dp),
		horizontalAlignment = Alignment.CenterHorizontally,
	) {
		Row(
			modifier = Modifier.fillMaxWidth(),
			horizontalArrangement = Arrangement.End,
		) {
			Box {
				IconButton(onClick = { isMenuOpen = true }) {
					Icon(Icons.Default.MoreVert, contentDescription = "Menu")
				}
				DropdownMenu(
					expanded = isMenuOpen,
					onDismissRequest = { isMenuOpen = false },
				) {
					DropdownMenuItem(
						text = { Text("Activity Logs") },
						onClick = {
							isMenuOpen = false
							onOpenActivity()
						},
					)
					DropdownMenuItem(
						text = { Text("HTTPS Route Setup") },
						onClick = {
							isMenuOpen = false
							onOpenHttpsSetup()
						},
					)
					DropdownMenuItem(
						text = { Text("Live Engine Config") },
						onClick = {
							isMenuOpen = false
							onOpenEngineConfig()
						},
					)
					DropdownMenuItem(
						text = { Text("Sync Blocklists") },
						onClick = {
							isMenuOpen = false
							vm.refreshAllBlocklists()
						},
					)
					DropdownMenuItem(
						text = { Text("Settings") },
						onClick = {
							isMenuOpen = false
							onOpenSettings()
						},
					)
				}
			}
		}

		Spacer(Modifier.height(6.dp))

		Text(
			text = "T R U E B L O C K",
			fontSize = 26.sp,
			fontWeight = FontWeight.ExtraBold,
			letterSpacing = 3.sp,
			color = MaterialTheme.colorScheme.onBackground,
		)
		Spacer(Modifier.height(4.dp))
		Text(
			text = statusHeadline,
			fontSize = 14.sp,
			fontWeight = FontWeight.Bold,
			letterSpacing = 2.sp,
			color = when {
				isActive -> accent
				vpn.isSnoozed -> ShieldRed
				else -> MaterialTheme.colorScheme.onSurfaceVariant
			},
		)

		Spacer(Modifier.weight(1f))

		Box(
			contentAlignment = Alignment.Center,
			modifier = Modifier
				.size(224.dp)
				.clickable(
					interactionSource = remember { MutableInteractionSource() },
					indication = null,
					onClick = onToggleVpn,
				),
		) {
			val innerCircleColor = MaterialTheme.colorScheme.surface
			val inactiveRingColor = MaterialTheme.colorScheme.outline
			val secondaryRing = Color(
				red = (accent.red * 0.65f + 0.35f).coerceIn(0f, 1f),
				green = (accent.green * 0.45f).coerceIn(0f, 1f),
				blue = (accent.blue * 0.85f + 0.15f).coerceIn(0f, 1f),
				alpha = 1f,
			)

			Canvas(modifier = Modifier.fillMaxSize()) {
				val baseRadius = (size.minDimension / 2f) - 16.dp.toPx()
				val r = if (isActive) baseRadius * pulse else baseRadius

				if (isActive) {
					drawCircle(
						brush = Brush.radialGradient(
							colors = listOf(accent.copy(alpha = 0.25f), Color.Transparent),
							radius = r * 1.2f,
						),
						radius = r * 1.18f,
					)
				}

				drawCircle(
					color = innerCircleColor,
					radius = baseRadius - 6.dp.toPx(),
				)

				if (isActive) {
					drawCircle(
						brush = Brush.sweepGradient(
							listOf(accent, secondaryRing, accent),
						),
						radius = baseRadius,
						style = Stroke(width = 11.dp.toPx()),
					)
				} else {
					drawCircle(
						color = if (vpn.isSnoozed) ShieldRed.copy(alpha = 0.65f) else inactiveRingColor,
						radius = baseRadius,
						style = Stroke(width = 9.dp.toPx()),
					)
				}
			}

			Icon(
				imageVector = Icons.Default.PowerSettingsNew,
				contentDescription = "Toggle Protection",
				tint = when {
					isActive -> accent
					vpn.isSnoozed -> ShieldRed
					else -> MaterialTheme.colorScheme.onSurfaceVariant
				},
				modifier = Modifier.size(64.dp),
			)
		}

		Spacer(Modifier.weight(1f))

		val formattedBlocked = remember(totalBlocked) {
			NumberFormat.getIntegerInstance(Locale.US).format(totalBlocked)
		}
		val formattedTotal = remember(totalRequests) {
			NumberFormat.getIntegerInstance(Locale.US).format(totalRequests.coerceAtLeast(totalBlocked))
		}
		val formattedParams = remember(totalParamsRemoved) {
			NumberFormat.getIntegerInstance(Locale.US).format(totalParamsRemoved)
		}

		Text(
			text = buildAnnotatedString {
				append("Blocked ")
				withStyle(SpanStyle(color = accent, fontWeight = FontWeight.Bold)) {
					append(formattedBlocked)
				}
				append(" out of ")
				withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
					append(formattedTotal)
				}
				append(" requests")
			},
			fontSize = 15.sp,
		)

		Spacer(Modifier.height(3.dp))

		Text(
			text = buildAnnotatedString {
				append("+ ")
				withStyle(SpanStyle(color = ShieldGreen, fontWeight = FontWeight.Bold)) {
					append(formattedParams)
				}
				append(" tracker parameters removed")
				if (totalCname > 0L) {
					append(" • ")
					withStyle(SpanStyle(color = accent, fontWeight = FontWeight.SemiBold)) {
						append("$totalCname")
					}
					append(" CNAMEs")
				}
			},
			fontSize = 12.5.sp,
			color = MaterialTheme.colorScheme.onSurfaceVariant,
		)

		Spacer(Modifier.height(10.dp))

		Row(
			horizontalArrangement = Arrangement.spacedBy(8.dp),
			verticalAlignment = Alignment.CenterVertically,
		) {
			val domFmt = remember(stats.totalDomainRules) {
				NumberFormat.getIntegerInstance(Locale.US).format(stats.totalDomainRules)
			}
			val routeFmt = remember(stats.totalRouteRules) {
				NumberFormat.getIntegerInstance(Locale.US).format(stats.totalRouteRules)
			}
			StatPill(text = if (stats.isSyncing) "Syncing..." else "$domFmt domains")
			StatPill(text = "$routeFmt routes")
			if (vpn.isRunning)
				StatPill(text = if (vpn.isL3CaptureActive) "${vpn.activeTransport} • L3" else vpn.activeTransport)
		}

		if (vpn.isRunning) {
			Spacer(Modifier.height(10.dp))
			if (vpn.isSnoozed) {
				Row(
					verticalAlignment = Alignment.CenterVertically,
					horizontalArrangement = Arrangement.spacedBy(10.dp),
					modifier = Modifier
						.clip(RoundedCornerShape(20.dp))
						.background(ShieldRed.copy(alpha = 0.16f))
						.border(1.dp, ShieldRed.copy(alpha = 0.5f), RoundedCornerShape(20.dp))
						.clickable { vm.resumeProtection() }
						.padding(horizontal = 14.dp, vertical = 6.dp),
				) {
					Text(
						text = "Protection Snoozed — Tap to Resume Now",
						fontSize = 12.sp,
						fontWeight = FontWeight.SemiBold,
						color = ShieldRed,
					)
				}
			} else {
				Row(
					verticalAlignment = Alignment.CenterVertically,
					horizontalArrangement = Arrangement.spacedBy(8.dp),
				) {
					Text("Snooze:", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
					for (mins in listOf(1, 5, 15)) {
						Box(
							modifier = Modifier
								.clip(RoundedCornerShape(16.dp))
								.background(MaterialTheme.colorScheme.surface)
								.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp))
								.clickable { vm.snoozeProtection(mins) }
								.padding(horizontal = 11.dp, vertical = 4.dp),
						) {
							Text("${mins}m", fontSize = 11.5.sp, fontWeight = FontWeight.Medium, color = accent)
						}
					}
				}
			}
		}

		Spacer(Modifier.height(14.dp))

		val isHttpsTrusted = cfg.isHttpsFiltering && ca.isReady && ca.isInstalledInSystem
		val installedHttpsCount = remember(cfg.httpsInspectedApps, installedSet) {
			if (installedSet.isEmpty()) cfg.httpsInspectedApps.size else cfg.httpsInspectedApps.count { installedSet.contains(it) }
		}
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(14.dp))
				.background(MaterialTheme.colorScheme.surface)
				.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
				.clickable(onClick = onOpenHttpsSetup)
				.padding(horizontal = 16.dp, vertical = 13.dp),
		) {
			Icon(
				imageVector = Icons.Default.Lock,
				contentDescription = null,
				tint = if (isHttpsTrusted) ShieldGreen else accent,
				modifier = Modifier.size(24.dp),
			)
			Spacer(Modifier.width(14.dp))
			Column(modifier = Modifier.weight(1f)) {
				Text(
					text = when {
						isHttpsTrusted -> "HTTPS & Route Filtering Active"
						cfg.isHttpsFiltering && ca.isReady -> "Install Root CA in Android Settings"
						else -> "Configure HTTPS URL Route Filtering"
					},
					fontWeight = FontWeight.SemiBold,
					fontSize = 14.sp,
				)
				Text(
					text = when {
						isHttpsTrusted -> "Trusted by Chrome • uBlock noop, CSS & WebSocket shield ($installedHttpsCount apps)"
						cfg.isHttpsFiltering && ca.isReady -> "CA generated, tap here to save .crt & install in Android User Store"
						else -> "Enable local Root CA to filter paths like xxx.com/ad in browsers"
					},
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
			}
		}

		Spacer(Modifier.height(6.dp))
	}
}

@Composable
private fun StatPill(text: String) {
	Box(
		modifier = Modifier
			.clip(RoundedCornerShape(20.dp))
			.background(MaterialTheme.colorScheme.surface)
			.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(20.dp))
			.padding(horizontal = 11.dp, vertical = 5.dp),
	) {
		Text(
			text = text,
			fontSize = 12.sp,
			color = MaterialTheme.colorScheme.onSurfaceVariant,
		)
	}
}

data class InspectedEntry(
	val target: String,
	val isBlocked: Boolean,
	val isRoute: Boolean,
	val hitCount: Long,
	val firstSeen: Long,
	val lastSeen: Long,
	val appPkg: String,
	val matchedRule: String,
	val proto: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityScreen(vm: MainViewModel) {
	val filter by vm.activityFilter.collectAsState()
	val rulesRev by vm.rulesRevision.collectAsState()
	val labelRev by vm.labelRevision.collectAsState()
	val aggItems = vm.pagedAggregated.collectAsLazyPagingItems()
	val rawItems = vm.pagedRaw.collectAsLazyPagingItems()
	val accent = MaterialTheme.colorScheme.primary
	val ctx = LocalContext.current
	val haptics = LocalHapticFeedback.current
	val nowMs = System.currentTimeMillis()

	fun copyTargetToClipboard(value: String) {
		haptics.performHapticFeedback(HapticFeedbackType.LongPress)
		val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
		cb.setPrimaryClip(ClipData.newPlainText("url", value))
		vm.postMessage("Copied: $value")
	}

	var isSearchVisible by remember { mutableStateOf(filter.query.isNotEmpty()) }
	var isFilterMenuOpen by remember { mutableStateOf(false) }
	var selectedEntry by remember { mutableStateOf<InspectedEntry?>(null) }
	var ruleEditorTarget by remember { mutableStateOf<Pair<String, Boolean>?>(null) }

	val isShowingRawList = filter.viewMode == ACTIVITY_MODE_LIVE_RAW ||
		(filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.isHttpsLiveStream)

	Column(modifier = Modifier.fillMaxSize()) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier
				.fillMaxWidth()
				.padding(horizontal = 16.dp, vertical = 6.dp),
		) {
			Text(
				text = "Activity",
				fontSize = 21.sp,
				fontWeight = FontWeight.Bold,
				modifier = Modifier.weight(1f),
			)

			if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS) {
				FilterChip(
					selected = filter.isHttpsLiveStream,
					onClick = { vm.updateActivityFilter { it.copy(isHttpsLiveStream = !it.isHttpsLiveStream) } },
					label = { Text(if (filter.isHttpsLiveStream) "Live Stream" else "Grouped URLs", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
			}

			IconButton(onClick = {
				isSearchVisible = !isSearchVisible
				if (!isSearchVisible && filter.query.isNotEmpty())
					vm.updateActivityFilter { it.copy(query = "") }
			}) {
				Icon(Icons.Default.Search, contentDescription = "Search")
			}

			Box {
				IconButton(onClick = { isFilterMenuOpen = true }) {
					Icon(
						Icons.Default.FilterList,
						contentDescription = "Filter",
						tint = if (filter.blockFilter != -1) accent else MaterialTheme.colorScheme.onSurface,
					)
				}
				DropdownMenu(
					expanded = isFilterMenuOpen,
					onDismissRequest = { isFilterMenuOpen = false },
				) {
					DropdownMenuItem(
						text = { Text("All requests") },
						onClick = {
							isFilterMenuOpen = false
							vm.updateActivityFilter { it.copy(blockFilter = -1) }
						},
					)
					DropdownMenuItem(
						text = { Text("Blocked only") },
						onClick = {
							isFilterMenuOpen = false
							vm.updateActivityFilter { it.copy(blockFilter = 1) }
						},
					)
					DropdownMenuItem(
						text = { Text("Allowed only") },
						onClick = {
							isFilterMenuOpen = false
							vm.updateActivityFilter { it.copy(blockFilter = 0) }
						},
					)
				}
			}

			IconButton(onClick = { vm.clearTrafficLogs() }) {
				Icon(Icons.Default.DeleteOutline, contentDescription = "Clear logs")
			}
		}

		TabRow(
			selectedTabIndex = filter.viewMode.coerceIn(0, 2),
			containerColor = Color.Transparent,
			contentColor = accent,
			indicator = { positions ->
				TabRowDefaults.SecondaryIndicator(
					Modifier.tabIndicatorOffset(positions[filter.viewMode.coerceIn(0, 2)]),
					color = accent,
				)
			},
		) {
			Tab(
				selected = filter.viewMode == ACTIVITY_MODE_GROUPED,
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_GROUPED) } },
				text = { Text("GROUPED", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
			Tab(
				selected = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS,
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_HTTPS_URLS) } },
				text = { Text("HTTPS URLS", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
			Tab(
				selected = filter.viewMode == ACTIVITY_MODE_LIVE_RAW,
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_LIVE_RAW) } },
				text = { Text("LIVE RAW", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
		}

		if (isSearchVisible) {
			OutlinedTextField(
				value = filter.query,
				onValueChange = { q -> vm.updateActivityFilter { it.copy(query = q) } },
				placeholder = { Text("Filter domain, full HTTPS URL, or package...") },
				singleLine = true,
				trailingIcon = {
					if (filter.query.isNotEmpty()) {
						IconButton(onClick = { vm.updateActivityFilter { it.copy(query = "") } }) {
							Icon(Icons.Default.Close, contentDescription = "Clear")
						}
					}
				},
				modifier = Modifier
					.fillMaxWidth()
					.padding(horizontal = 16.dp, vertical = 4.dp),
			)
		}

		if (!isShowingRawList) {
			Row(
				horizontalArrangement = Arrangement.spacedBy(8.dp),
				verticalAlignment = Alignment.CenterVertically,
				modifier = Modifier
					.fillMaxWidth()
					.padding(horizontal = 14.dp, vertical = 4.dp),
			) {
				FilterChip(
					selected = !filter.isTopSort,
					onClick = { vm.updateActivityFilter { it.copy(isTopSort = false) } },
					label = { Text("Recent", fontSize = 11.5.sp, maxLines = 1) },
				)
				FilterChip(
					selected = filter.isTopSort,
					onClick = { vm.updateActivityFilter { it.copy(isTopSort = true) } },
					label = { Text("Top Hits", fontSize = 11.5.sp, maxLines = 1) },
				)
				if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS) {
					Spacer(Modifier.weight(1f))
					Text(
						text = "Intercepted HTTP/HTTPS/WS URLs",
						fontSize = 11.sp,
						color = MaterialTheme.colorScheme.onSurfaceVariant,
						maxLines = 1,
					)
				}
			}

			if (aggItems.itemCount == 0) {
				EmptyTrafficPlaceholder(
					isHttpsTab = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS,
				)
			} else {
				LazyColumn(
					modifier = Modifier.fillMaxSize(),
					contentPadding = PaddingValues(vertical = 2.dp),
				) {
					items(
						count = aggItems.itemCount,
						key = { idx -> aggItems.peek(idx)?.target ?: "agg_$idx" },
						contentType = { "agg_row" },
					) { idx ->
						val item = aggItems[idx] ?: return@items
						val customOverride = remember(item.target, item.isRoute, rulesRev) {
							vm.matchCustomFast(item.target, item.isRoute)
						}
						val appLabel = remember(item.lastApp, labelRev) { vm.appLabelFast(item.lastApp) }
						AggregatedTrafficRow(
							item = item,
							nowMs = nowMs,
							isOverrideBlocked = customOverride?.isBlocked,
							overrideRule = customOverride?.summaryText() ?: "",
							appLabel = appLabel,
							onClick = {
								selectedEntry = InspectedEntry(
									target = item.target,
									isBlocked = item.isBlocked,
									isRoute = item.isRoute,
									hitCount = item.hitCount,
									firstSeen = item.firstSeen,
									lastSeen = item.lastSeen,
									appPkg = item.lastApp,
									matchedRule = item.lastRule,
									proto = if (item.isRoute) "HTTP/S" else "DNS",
								)
							},
							onLongCopy = { copyTargetToClipboard(item.target) },
						)
						HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
					}
				}
			}
		} else {
			if (rawItems.itemCount == 0) {
				EmptyTrafficPlaceholder(
					isHttpsTab = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS,
				)
			} else {
				LazyColumn(
					modifier = Modifier.fillMaxSize(),
					contentPadding = PaddingValues(vertical = 2.dp),
				) {
					items(
						count = rawItems.itemCount,
						key = { idx -> rawItems.peek(idx)?.id ?: (-idx.toLong()) },
						contentType = { "raw_row" },
					) { idx ->
						val item = rawItems[idx] ?: return@items
						val isRouteItem = item.target.indexOf('/') >= 0
						val customOverride = remember(item.target, isRouteItem, rulesRev) {
							vm.matchCustomFast(item.target, isRouteItem)
						}
						val appLabel = remember(item.appPkg, labelRev) { vm.appLabelFast(item.appPkg) }
						RawTrafficRow(
							item = item,
							isOverrideBlocked = customOverride?.isBlocked,
							overrideRule = customOverride?.summaryText() ?: "",
							appLabel = appLabel,
							onClick = {
								selectedEntry = InspectedEntry(
									target = item.target,
									isBlocked = item.isBlocked,
									isRoute = isRouteItem,
									hitCount = 1L,
									firstSeen = item.ts,
									lastSeen = item.ts,
									appPkg = item.appPkg,
									matchedRule = item.matchedRule,
									proto = item.proto,
								)
							},
							onLongCopy = { copyTargetToClipboard(item.target) },
						)
						HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
					}
				}
			}
		}
	}

	selectedEntry?.let { entry ->
		ModalBottomSheet(
			onDismissRequest = { selectedEntry = null },
			containerColor = MaterialTheme.colorScheme.surface,
		) {
			ActivityDetailSheet(
				vm = vm,
				entry = entry,
				rulesRev = rulesRev,
				onQuickBlock = {
					vm.quickToggleDomainRule(entry.target, isMakeBlocked = true)
					selectedEntry = null
				},
				onQuickAllow = {
					vm.quickToggleDomainRule(entry.target, isMakeBlocked = false)
					selectedEntry = null
				},
				onOpenCustomEditor = { isAllowRule ->
					val prefill = entry.target
					selectedEntry = null
					ruleEditorTarget = prefill to isAllowRule
				},
				onCopy = {
					val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
					cb.setPrimaryClip(ClipData.newPlainText("url", entry.target))
					vm.postMessage("Copied to clipboard")
				},
			)
		}
	}

	ruleEditorTarget?.let { (prefill, isAllowPrefill) ->
		RuleEditorDialog(
			initialRule = null,
			prefillPattern = prefill,
			prefillIsAllow = isAllowPrefill,
			onDismiss = { ruleEditorTarget = null },
			onSave = { rule: CustomRule ->
				vm.saveCustomRule(rule)
				ruleEditorTarget = null
			},
		)
	}
}

@Composable
private fun EmptyTrafficPlaceholder(isHttpsTab: Boolean = false) {
	Box(
		contentAlignment = Alignment.Center,
		modifier = Modifier.fillMaxSize().padding(32.dp),
	) {
		Text(
			text = if (isHttpsTab) {
				"No intercepted full HTTP/HTTPS URLs yet.\nEnable HTTPS & Route Filtering with trusted Root CA and browse in an inspected app."
			} else {
				"No traffic recorded matching current filters."
			},
			color = MaterialTheme.colorScheme.onSurfaceVariant,
			fontSize = 14.sp,
		)
	}
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun AggregatedTrafficRow(
	item: AggregatedLog,
	nowMs: Long,
	isOverrideBlocked: Boolean?,
	overrideRule: String,
	appLabel: String,
	onClick: () -> Unit,
	onLongCopy: () -> Unit,
) {
	val isVisuallyBlocked = isOverrideBlocked ?: item.isBlocked

	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.combinedClickable(
				onClick = onClick,
				onLongClick = onLongCopy,
			)
			.padding(horizontal = 12.dp, vertical = 7.dp),
	) {
		Icon(
			imageVector = if (isVisuallyBlocked) Icons.Default.Block else Icons.Default.Shield,
			contentDescription = null,
			tint = if (isVisuallyBlocked) ShieldRed else ShieldGreen,
			modifier = Modifier.size(22.dp),
		)
		Spacer(Modifier.width(10.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(
				text = item.target,
				fontSize = 13.5.sp,
				fontWeight = FontWeight.Medium,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
			val meta = buildString(96) {
				append(formatRelativeTime(item.lastSeen, nowMs))
				append(" • ")
				append(if (item.isBlocked) "blocked " else "allowed ")
				append(item.hitCount).append('x')
				if (appLabel.isNotEmpty())
					append(" • ").append(appLabel)
				val ruleInfo = overrideRule.ifEmpty { item.lastRule }
				if (ruleInfo.isNotEmpty())
					append(" • ").append(ruleInfo)
			}
			Text(
				text = meta,
				fontSize = 11.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
		}
		if (isOverrideBlocked != null) {
			val badgeCol = if (isOverrideBlocked) ShieldRed else ShieldGreen
			Spacer(Modifier.width(6.dp))
			Box(
				modifier = Modifier
					.clip(RoundedCornerShape(5.dp))
					.background(badgeCol.copy(alpha = 0.18f))
					.padding(horizontal = 5.dp, vertical = 1.dp),
			) {
				Text(
					text = if (isOverrideBlocked) "BLOCKED" else "ALLOWED",
					fontSize = 9.5.sp,
					color = badgeCol,
					fontWeight = FontWeight.Bold,
				)
			}
		}
	}
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun RawTrafficRow(
	item: RawLog,
	isOverrideBlocked: Boolean?,
	overrideRule: String,
	appLabel: String,
	onClick: () -> Unit,
	onLongCopy: () -> Unit,
) {
	val isVisuallyBlocked = isOverrideBlocked ?: item.isBlocked

	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.combinedClickable(
				onClick = onClick,
				onLongClick = onLongCopy,
			)
			.padding(horizontal = 12.dp, vertical = 7.dp),
	) {
		Icon(
			imageVector = if (isVisuallyBlocked) Icons.Default.Block else Icons.Default.Shield,
			contentDescription = null,
			tint = if (isVisuallyBlocked) ShieldRed else ShieldGreen,
			modifier = Modifier.size(22.dp),
		)
		Spacer(Modifier.width(10.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(
				text = item.target,
				fontSize = 13.5.sp,
				fontWeight = FontWeight.Medium,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
			val meta = buildString(96) {
				append(formatShortClockFast(item.ts))
				append(" • ").append(item.proto)
				if (appLabel.isNotEmpty())
					append(" • ").append(appLabel)
				val ruleInfo = overrideRule.ifEmpty { item.matchedRule }
				if (ruleInfo.isNotEmpty())
					append(" • ").append(ruleInfo)
			}
			Text(
				text = meta,
				fontSize = 11.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
		}
		if (isOverrideBlocked != null) {
			val badgeCol = if (isOverrideBlocked) ShieldRed else ShieldGreen
			Spacer(Modifier.width(6.dp))
			Box(
				modifier = Modifier
					.clip(RoundedCornerShape(5.dp))
					.background(badgeCol.copy(alpha = 0.18f))
					.padding(horizontal = 5.dp, vertical = 1.dp),
			) {
				Text(
					text = if (isOverrideBlocked) "BLOCKED" else "ALLOWED",
					fontSize = 9.5.sp,
					color = badgeCol,
					fontWeight = FontWeight.Bold,
				)
			}
		}
	}
}

@Composable
private fun ActivityDetailSheet(
	vm: MainViewModel,
	entry: InspectedEntry,
	rulesRev: Long,
	onQuickBlock: () -> Unit,
	onQuickAllow: () -> Unit,
	onOpenCustomEditor: (Boolean) -> Unit,
	onCopy: () -> Unit,
) {
	val accent = MaterialTheme.colorScheme.primary
	val liveVerdict = remember(entry.target, entry.isRoute, rulesRev) {
		vm.evaluateLive(entry.target, entry.isRoute)
	}
	val isNowBlocked = liveVerdict.isBlocked || (liveVerdict.matchedRule.isEmpty() && entry.isBlocked)
	val isCustomNow = liveVerdict.ruleSource.startsWith("Custom Rule")
	val sourceDisplay = vm.appLabelFast(entry.appPkg)

	val parsedStoredSource = if (entry.matchedRule.contains(" • ")) {
		entry.matchedRule.substringBefore(" • ")
	} else if (entry.matchedRule.startsWith("custom:")) {
		"Custom Rule"
	} else if (entry.matchedRule.contains(':')) {
		entry.matchedRule.substringBefore(':')
	} else {
		""
	}

	val parsedStoredPattern = if (entry.matchedRule.contains(" • ")) {
		entry.matchedRule.substringAfter(" • ")
	} else {
		entry.matchedRule
	}

	val effectiveRuleSource = when {
		liveVerdict.ruleSource.isNotEmpty() -> liveVerdict.ruleSource
		parsedStoredSource.isNotEmpty() -> parsedStoredSource
		isNowBlocked -> "Active Blocklist"
		else -> "Default policy (not in active blocklists)"
	}

	val effectiveRulePattern = liveVerdict.matchedRule.ifEmpty { parsedStoredPattern }

	Column(
		modifier = Modifier
			.fillMaxWidth()
			.padding(horizontal = 20.dp, vertical = 10.dp),
	) {
		Row(verticalAlignment = Alignment.CenterVertically) {
			Icon(
				imageVector = if (isNowBlocked) Icons.Default.Block else Icons.Default.Shield,
				contentDescription = null,
				tint = if (isNowBlocked) ShieldRed else ShieldGreen,
				modifier = Modifier.size(40.dp),
			)
			Spacer(Modifier.width(14.dp))
			Column(modifier = Modifier.weight(1f)) {
				Text(entry.target, fontWeight = FontWeight.Bold, fontSize = 15.sp)
				Text(
					text = if (isNowBlocked) {
						"Blocked — $effectiveRuleSource"
					} else {
						"Allowed — $effectiveRuleSource"
					},
					color = if (isNowBlocked) ShieldRed else ShieldGreen,
					fontSize = 12.5.sp,
					fontWeight = FontWeight.Medium,
				)
			}
		}

		Spacer(Modifier.height(14.dp))
		HorizontalDivider(color = MaterialTheme.colorScheme.outline)
		Spacer(Modifier.height(10.dp))

		Text("Actions", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
		Spacer(Modifier.height(6.dp))

		ActionRowItem(
			icon = Icons.Default.Block,
			tint = ShieldRed,
			label = if (isNowBlocked && isCustomNow) "✓ Added to Blocked" else "Add to Blocked (Exact)",
			onClick = onQuickBlock,
		)
		ActionRowItem(
			icon = Icons.Default.Shield,
			tint = ShieldGreen,
			label = if (!isNowBlocked && isCustomNow) "✓ Added to Allowed" else "Add to Allowed (Exception)",
			onClick = onQuickAllow,
		)
		ActionRowItem(
			icon = Icons.Default.Edit,
			tint = accent,
			label = "Edit & Add Custom Rule (Exact / Wildcard / Regex / Route)...",
			onClick = { onOpenCustomEditor(false) },
		)
		ActionRowItem(
			icon = Icons.Default.ContentCopy,
			tint = MaterialTheme.colorScheme.onSurfaceVariant,
			label = "Copy to Clipboard",
			onClick = onCopy,
		)

		Spacer(Modifier.height(10.dp))
		HorizontalDivider(color = MaterialTheme.colorScheme.outline)
		Spacer(Modifier.height(10.dp))

		Text("Information", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
		Spacer(Modifier.height(6.dp))
		InfoField("Full target", entry.target)
		InfoField("Rule source", effectiveRuleSource)
		if (effectiveRulePattern.isNotEmpty())
			InfoField("Matched rule", effectiveRulePattern)
		if (sourceDisplay.isNotEmpty())
			InfoField("Source app", sourceDisplay)
		InfoField("Occurrences", entry.hitCount.toString())
		InfoField("First seen", formatFullDate(entry.firstSeen))
		InfoField("Last seen", formatFullDate(entry.lastSeen))

		Spacer(Modifier.height(22.dp))
	}
}

@Composable
private fun ActionRowItem(
	icon: androidx.compose.ui.graphics.vector.ImageVector,
	tint: Color,
	label: String,
	onClick: () -> Unit,
) {
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.clickable(onClick = onClick)
			.padding(vertical = 9.dp, horizontal = 6.dp),
	) {
		Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(21.dp))
		Spacer(Modifier.width(12.dp))
		Text(label, fontSize = 13.5.sp, color = tint, fontWeight = FontWeight.Medium)
	}
}

@Composable
private fun InfoField(label: String, value: String) {
	Column(modifier = Modifier.padding(vertical = 3.dp)) {
		Text(label, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
		Text(value, fontSize = 13.5.sp)
	}
}

fun formatRelativeTime(tsMillis: Long, nowMs: Long = System.currentTimeMillis()): String {
	val diffSec = ((nowMs - tsMillis) / 1000L).coerceAtLeast(0L)
	return when {
		diffSec < 5L -> "just now"
		diffSec < 60L -> "${diffSec}s ago"
		diffSec < 3600L -> "${diffSec / 60L}m ago"
		diffSec < 86_400L -> "${diffSec / 3600L}h ago"
		else -> "${diffSec / 86_400L}d ago"
	}
}

private fun formatShortClockFast(tsMillis: Long): String {
	val tzOffset = TimeZone.getDefault().getOffset(tsMillis)
	val localSec = ((tsMillis + tzOffset) / 1000L).mod(86_400L)
	val hh = (localSec / 3600L).toInt()
	val mm = ((localSec % 3600L) / 60L).toInt()
	val ss = (localSec % 60L).toInt()
	val c = CharArray(8)
	c[0] = ('0'.code + hh / 10).toChar()
	c[1] = ('0'.code + hh % 10).toChar()
	c[2] = ':'
	c[3] = ('0'.code + mm / 10).toChar()
	c[4] = ('0'.code + mm % 10).toChar()
	c[5] = ':'
	c[6] = ('0'.code + ss / 10).toChar()
	c[7] = ('0'.code + ss % 10).toChar()

	return String(c)
}

private fun formatFullDate(tsMillis: Long): String {
	if (tsMillis <= 0L)
		return "Never"

	return SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(tsMillis))
}
