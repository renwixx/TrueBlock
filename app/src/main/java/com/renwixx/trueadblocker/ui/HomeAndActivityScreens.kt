package com.renwixx.trueadblocker.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
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
import com.renwixx.trueadblocker.data.HttpsDomainGroup
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
	val updateState by vm.updateState.collectAsState()
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

			val powerIconTint by animateColorAsState(
				targetValue = when {
					isActive -> accent
					vpn.isSnoozed -> ShieldRed
					else -> MaterialTheme.colorScheme.onSurfaceVariant
				},
				animationSpec = tween(250),
				label = "power_tint",
			)

			Icon(
				imageVector = Icons.Default.PowerSettingsNew,
				contentDescription = "Toggle Protection",
				tint = powerIconTint,
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

		AnimatedVisibility(visible = vpn.isRunning) {
			Column(horizontalAlignment = Alignment.CenterHorizontally) {
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
		}

		val isUpdateBannerVisible = updateState is UpdateUiState.Available ||
			updateState is UpdateUiState.Downloading ||
			updateState is UpdateUiState.ReadyToInstall
		AnimatedVisibility(visible = isUpdateBannerVisible) {
			Column {
				val uState = updateState
				val info = when (uState) {
					is UpdateUiState.Available -> uState.info
					is UpdateUiState.Downloading -> uState.info
					is UpdateUiState.ReadyToInstall -> uState.info
					else -> null
				}
				if (info != null) {
					Column(
						modifier = Modifier
							.fillMaxWidth()
							.clip(RoundedCornerShape(14.dp))
							.background(accent.copy(alpha = 0.12f))
							.border(1.dp, accent.copy(alpha = 0.55f), RoundedCornerShape(14.dp))
							.padding(horizontal = 14.dp, vertical = 10.dp),
					) {
						Row(verticalAlignment = Alignment.CenterVertically) {
							Icon(Icons.Default.FileDownload, contentDescription = null, tint = accent, modifier = Modifier.size(22.dp))
							Spacer(Modifier.width(10.dp))
							Column(modifier = Modifier.weight(1f)) {
								Text(
									text = "Update available: ${info.versionName}",
									fontWeight = FontWeight.SemiBold,
									fontSize = 13.5.sp,
									maxLines = 1,
									overflow = TextOverflow.Ellipsis,
								)
								if (info.notes.isNotEmpty()) {
									Text(
										text = info.notes,
										fontSize = 11.5.sp,
										color = MaterialTheme.colorScheme.onSurfaceVariant,
										maxLines = 1,
										overflow = TextOverflow.Ellipsis,
									)
								}
							}
							Spacer(Modifier.width(8.dp))
							if (uState is UpdateUiState.Downloading) {
								Text(
									text = "${(uState.progress * 100).toInt()}%",
									fontWeight = FontWeight.Bold,
									fontSize = 12.sp,
									color = accent,
								)
							} else {
								Button(
									onClick = { vm.downloadAndInstallUpdate() },
									contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
								) {
									Text(
										text = if (uState is UpdateUiState.ReadyToInstall) "Install" else "Update",
										fontSize = 12.sp,
										maxLines = 1,
									)
								}
							}
						}
						if (uState is UpdateUiState.Downloading) {
							Spacer(Modifier.height(6.dp))
							LinearProgressIndicator(
								progress = { uState.progress.coerceIn(0f, 1f) },
								color = accent,
								trackColor = MaterialTheme.colorScheme.outline,
								modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
							)
						}
					}
					Spacer(Modifier.height(10.dp))
				}
			}
		}

		Spacer(Modifier.height(10.dp))

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
	val contentType: String = "",
	val fileExt: String = "",
)

fun shortenUrlForDisplay(target: String): String {
	val slashIdx = target.indexOf('/')
	if (slashIdx < 0)
		return target

	val host = target.substring(0, slashIdx)
	val rest = target.substring(slashIdx)
	val qIdx = rest.indexOf('?')
	val pathOnly = if (qIdx >= 0) rest.substring(0, qIdx) else rest
	val hasQuery = qIdx >= 0

	val segs = pathOnly.split('/').filter { it.isNotEmpty() }
	val compactPath = when {
		segs.isEmpty() -> "/"
		segs.size <= 2 && pathOnly.length <= 42 -> pathOnly
		segs.size == 1 -> "/${segs[0].take(28)}…"
		else -> {
			val first = segs.first().take(16)
			val last = segs.last().take(24)
			if (segs.size > 2) "/$first/…/$last" else "/$first/$last"
		}
	}

	return if (hasQuery) "$host$compactPath?…" else "$host$compactPath"
}

private fun formatResponseTypeBadge(contentType: String, fileExt: String): String {
	if (fileExt.isNotEmpty() && contentType == "file")
		return ".${fileExt.uppercase()}"

	return when (contentType) {
		"image" -> if (fileExt.isNotEmpty()) "IMG.${fileExt.uppercase()}" else "IMG"
		"video" -> if (fileExt.isNotEmpty()) "VID.${fileExt.uppercase()}" else "VID"
		"audio" -> if (fileExt.isNotEmpty()) "AUD.${fileExt.uppercase()}" else "AUD"
		"file" -> "FILE"
		"default" -> "TEXT/API"
		else -> ""
	}
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityScreen(vm: MainViewModel) {
	val filter by vm.activityFilter.collectAsState()
	val rulesRev by vm.rulesRevision.collectAsState()
	val labelRev by vm.labelRevision.collectAsState()
	val loggedApps by vm.loggedApps.collectAsState()
	val installedApps by vm.installedApps.collectAsState()
	val aggItems = vm.pagedAggregated.collectAsLazyPagingItems()
	val domainItems = vm.pagedHttpsDomains.collectAsLazyPagingItems()
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
	var isAppFilterDialogOpen by remember { mutableStateOf(false) }
	var isTypeFilterDialogOpen by remember { mutableStateOf(false) }
	var selectedEntry by remember { mutableStateOf<InspectedEntry?>(null) }
	var ruleEditorTarget by remember { mutableStateOf<Pair<String, Boolean>?>(null) }

	val isShowingRawList = filter.viewMode == ACTIVITY_MODE_LIVE_RAW ||
		(filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.isHttpsLiveStream)
	val isShowingHttpsDomainList = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS &&
		!isShowingRawList &&
		filter.isGroupHttpsByDomain &&
		filter.selectedHttpsDomain.isEmpty()

	BackHandler(enabled = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.selectedHttpsDomain.isNotEmpty()) {
		vm.updateActivityFilter { it.copy(selectedHttpsDomain = "") }
	}

	Column(modifier = Modifier.fillMaxSize()) {
		ScreenHeader(title = "Activity") {
			if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS) {
				FilterChip(
					selected = filter.isHttpsLiveStream,
					onClick = { vm.updateActivityFilter { it.copy(isHttpsLiveStream = !it.isHttpsLiveStream) } },
					label = { Text(if (filter.isHttpsLiveStream) "Live" else "Grouped", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
				Spacer(Modifier.width(2.dp))
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
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_GROUPED, selectedHttpsDomain = "") } },
				text = { Text("GROUPED", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
			Tab(
				selected = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS,
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_HTTPS_URLS) } },
				text = { Text("HTTPS URLS", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
			Tab(
				selected = filter.viewMode == ACTIVITY_MODE_LIVE_RAW,
				onClick = { vm.updateActivityFilter { it.copy(viewMode = ACTIVITY_MODE_LIVE_RAW, selectedHttpsDomain = "") } },
				text = { Text("LIVE RAW", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) },
			)
		}

		AnimatedVisibility(visible = isSearchVisible) {
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

		Row(
			horizontalArrangement = Arrangement.spacedBy(8.dp),
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier
				.fillMaxWidth()
				.horizontalScroll(rememberScrollState())
				.padding(horizontal = 14.dp, vertical = 4.dp),
		) {
			val activeAppLabel = remember(filter.appPkgFilter, labelRev) {
				if (filter.appPkgFilter.isEmpty()) {
					"All Apps"
				} else {
					vm.appLabelFast(filter.appPkgFilter).substringBefore(" (")
				}
			}
			FilterChip(
				selected = filter.appPkgFilter.isNotEmpty(),
				onClick = { isAppFilterDialogOpen = true },
				leadingIcon = { Icon(Icons.Default.Apps, contentDescription = null, modifier = Modifier.size(16.dp)) },
				trailingIcon = if (filter.appPkgFilter.isNotEmpty()) {
					{
						Icon(
							Icons.Default.Close,
							contentDescription = "Clear app filter",
							modifier = Modifier
								.size(16.dp)
								.clickable { vm.updateActivityFilter { it.copy(appPkgFilter = "") } },
						)
					}
				} else {
					null
				},
				label = { Text(activeAppLabel, fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
			)

			if (!isShowingRawList) {
				FilterChip(
					selected = !filter.isTopSort,
					onClick = { vm.updateActivityFilter { it.copy(isTopSort = false) } },
					label = { Text("Recent", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
				FilterChip(
					selected = filter.isTopSort,
					onClick = { vm.updateActivityFilter { it.copy(isTopSort = true) } },
					label = { Text("Top Hits", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
			}

			if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS) {
				FilterChip(
					selected = filter.isShortenUrls,
					onClick = { vm.updateActivityFilter { it.copy(isShortenUrls = !it.isShortenUrls) } },
					label = { Text("Short URLs", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
				if (!isShowingRawList) {
					FilterChip(
						selected = filter.isGroupHttpsByDomain,
						onClick = {
							vm.updateActivityFilter {
								it.copy(isGroupHttpsByDomain = !it.isGroupHttpsByDomain, selectedHttpsDomain = "")
							}
						},
						label = { Text("By Domain", fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
					)
				}
				val typeLabel = when (filter.responseTypeFilter) {
					"image" -> "Type: Images"
					"video" -> "Type: Video"
					"audio" -> "Type: Audio"
					"default" -> "Type: Default"
					"file" -> if (filter.customFileExt.isNotBlank()) "File: .${filter.customFileExt.trim().removePrefix(".")}" else "Type: Files"
					else -> "Type: All"
				}
				FilterChip(
					selected = filter.responseTypeFilter.isNotEmpty(),
					onClick = { isTypeFilterDialogOpen = true },
					trailingIcon = if (filter.responseTypeFilter.isNotEmpty()) {
						{
							Icon(
								Icons.Default.Close,
								contentDescription = "Clear type filter",
								modifier = Modifier
									.size(16.dp)
									.clickable { vm.updateActivityFilter { it.copy(responseTypeFilter = "", customFileExt = "") } },
							)
						}
					} else {
						null
					},
					label = { Text(typeLabel, fontSize = 11.5.sp, maxLines = 1, softWrap = false) },
				)
			}
		}

		AnimatedVisibility(visible = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.selectedHttpsDomain.isNotEmpty()) {
			Row(
				verticalAlignment = Alignment.CenterVertically,
				modifier = Modifier
					.fillMaxWidth()
					.background(MaterialTheme.colorScheme.surface)
					.clickable { vm.updateActivityFilter { it.copy(selectedHttpsDomain = "") } }
					.padding(horizontal = 12.dp, vertical = 8.dp),
			) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "All domains", tint = accent, modifier = Modifier.size(18.dp))
				Spacer(Modifier.width(8.dp))
				Text(
					text = "Paths on ${filter.selectedHttpsDomain}",
					fontWeight = FontWeight.SemiBold,
					fontSize = 13.sp,
					color = accent,
					maxLines = 1,
					overflow = TextOverflow.Ellipsis,
					modifier = Modifier.weight(1f),
				)
				Text("All domains", fontSize = 11.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			}
		}

		val listModeKey = when {
			isShowingRawList -> "raw"
			isShowingHttpsDomainList -> "domains"
			else -> "agg_${filter.selectedHttpsDomain}"
		}
		AnimatedContent(
			targetState = listModeKey,
			transitionSpec = { fadeIn(tween(150)).togetherWith(fadeOut(tween(100))) },
			label = "activity_list_mode",
			modifier = Modifier.weight(1f),
		) { modeKey ->
			when {
				modeKey == "raw" -> {
					if (rawItems.itemCount == 0) {
						EmptyTrafficPlaceholder(isHttpsTab = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS)
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
								val displayText = if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.isShortenUrls) {
									shortenUrlForDisplay(item.target)
								} else {
									item.target
								}
								RawTrafficRow(
									item = item,
									displayTarget = displayText,
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
											contentType = item.contentType,
											fileExt = item.fileExt,
										)
									},
									onLongCopy = { copyTargetToClipboard(item.target) },
								)
								HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
							}
						}
					}
				}
				modeKey == "domains" -> {
					if (domainItems.itemCount == 0) {
						EmptyTrafficPlaceholder(isHttpsTab = true)
					} else {
						LazyColumn(
							modifier = Modifier.fillMaxSize(),
							contentPadding = PaddingValues(vertical = 2.dp),
						) {
							items(
								count = domainItems.itemCount,
								key = { idx -> domainItems.peek(idx)?.host ?: "dom_$idx" },
								contentType = { "https_domain_row" },
							) { idx ->
								val grp = domainItems[idx] ?: return@items
								val appLabel = remember(grp.lastApp, labelRev) { vm.appLabelFast(grp.lastApp) }
								HttpsDomainGroupRow(
									group = grp,
									nowMs = nowMs,
									appLabel = appLabel,
									onClick = { vm.updateActivityFilter { it.copy(selectedHttpsDomain = grp.host) } },
									onLongCopy = { copyTargetToClipboard(grp.host) },
								)
								HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
							}
						}
					}
				}
				else -> {
					if (aggItems.itemCount == 0) {
						EmptyTrafficPlaceholder(isHttpsTab = filter.viewMode == ACTIVITY_MODE_HTTPS_URLS)
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
								val displayText = if (filter.viewMode == ACTIVITY_MODE_HTTPS_URLS && filter.isShortenUrls) {
									shortenUrlForDisplay(item.target)
								} else {
									item.target
								}
								AggregatedTrafficRow(
									item = item,
									displayTarget = displayText,
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
											contentType = item.contentType,
											fileExt = item.fileExt,
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
		}
	}

	if (isAppFilterDialogOpen) {
		ActivityAppFilterDialog(
			loggedPackages = loggedApps,
			installedApps = installedApps,
			selectedPkg = filter.appPkgFilter,
			resolveLabel = { pkg -> vm.appLabelFast(pkg) },
			getCachedIcon = { pkg -> vm.getCachedAppIcon(pkg) },
			getIcon = { pkg -> vm.getAppIcon(pkg) },
			onDismiss = { isAppFilterDialogOpen = false },
			onSelect = { pkg ->
				vm.updateActivityFilter { it.copy(appPkgFilter = pkg) }
				isAppFilterDialogOpen = false
			},
		)
	}

	if (isTypeFilterDialogOpen) {
		ResponseTypeFilterDialog(
			currentType = filter.responseTypeFilter,
			currentExt = filter.customFileExt,
			onDismiss = { isTypeFilterDialogOpen = false },
			onApply = { typeVal, extVal ->
				vm.updateActivityFilter { it.copy(responseTypeFilter = typeVal, customFileExt = extVal) }
				isTypeFilterDialogOpen = false
			},
		)
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
private fun HttpsDomainGroupRow(
	group: HttpsDomainGroup,
	nowMs: Long,
	appLabel: String,
	onClick: () -> Unit,
	onLongCopy: () -> Unit,
) {
	val accent = MaterialTheme.colorScheme.primary
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.combinedClickable(onClick = onClick, onLongClick = onLongCopy)
			.padding(horizontal = 12.dp, vertical = 9.dp),
	) {
		Icon(
			imageVector = Icons.Default.Language,
			contentDescription = null,
			tint = if (group.blockedHits > 0L) ShieldRed else accent,
			modifier = Modifier.size(22.dp),
		)
		Spacer(Modifier.width(10.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(
				text = group.host,
				fontSize = 13.5.sp,
				fontWeight = FontWeight.SemiBold,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
			val meta = buildString(96) {
				append("${group.routeCount} path(s)")
				append(" • ${group.totalHits}x")
				if (group.blockedHits > 0L)
					append(" • ${group.blockedHits} blocked")
				append(" • ").append(formatRelativeTime(group.lastSeen, nowMs))
				if (appLabel.isNotEmpty())
					append(" • ").append(appLabel)
			}
			Text(
				text = meta,
				fontSize = 11.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
		}
		Icon(Icons.Default.ChevronRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
	}
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun AggregatedTrafficRow(
	item: AggregatedLog,
	displayTarget: String,
	nowMs: Long,
	isOverrideBlocked: Boolean?,
	overrideRule: String,
	appLabel: String,
	onClick: () -> Unit,
	onLongCopy: () -> Unit,
) {
	val isVisuallyBlocked = isOverrideBlocked ?: item.isBlocked
	val typeBadge = formatResponseTypeBadge(item.contentType, item.fileExt)

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
				text = displayTarget,
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
				if (typeBadge.isNotEmpty())
					append(" • ").append(typeBadge)
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
	displayTarget: String,
	isOverrideBlocked: Boolean?,
	overrideRule: String,
	appLabel: String,
	onClick: () -> Unit,
	onLongCopy: () -> Unit,
) {
	val isVisuallyBlocked = isOverrideBlocked ?: item.isBlocked
	val typeBadge = formatResponseTypeBadge(item.contentType, item.fileExt)

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
				text = displayTarget,
				fontSize = 13.5.sp,
				fontWeight = FontWeight.Medium,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
			val meta = buildString(96) {
				append(formatShortClockFast(item.ts))
				append(" • ").append(item.proto)
				if (typeBadge.isNotEmpty())
					append(" • ").append(typeBadge)
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
private fun ActivityAppFilterDialog(
	loggedPackages: List<String>,
	installedApps: List<InstalledAppItem>,
	selectedPkg: String,
	resolveLabel: (String) -> String,
	getCachedIcon: (String) -> ImageBitmap?,
	getIcon: suspend (String) -> ImageBitmap?,
	onDismiss: () -> Unit,
	onSelect: (String) -> Unit,
) {
	var query by remember { mutableStateOf("") }
	val accent = MaterialTheme.colorScheme.primary

	val candidates = remember(loggedPackages, installedApps, query) {
		val seen = LinkedHashSet<String>()
		val ordered = ArrayList<Pair<String, String>>(loggedPackages.size + installedApps.size)
		for (pkg in loggedPackages) {
			if (pkg.isNotEmpty() && seen.add(pkg))
				ordered.add(pkg to resolveLabel(pkg))
		}
		for (app in installedApps) {
			if (seen.add(app.packageName))
				ordered.add(app.packageName to "${app.label} (${app.packageName})")
		}
		if (query.isBlank()) {
			ordered
		} else {
			ordered.filter { (pkg, lbl) ->
				lbl.contains(query, ignoreCase = true) || pkg.contains(query, ignoreCase = true)
			}
		}
	}

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("Filter by App", fontWeight = FontWeight.Bold) },
		text = {
			Column {
				OutlinedTextField(
					value = query,
					onValueChange = { query = it },
					placeholder = { Text("Search app or package...") },
					leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(8.dp))
				Row(
					verticalAlignment = Alignment.CenterVertically,
					modifier = Modifier
						.fillMaxWidth()
						.clip(RoundedCornerShape(8.dp))
						.background(if (selectedPkg.isEmpty()) accent.copy(alpha = 0.14f) else Color.Transparent)
						.clickable { onSelect("") }
						.padding(horizontal = 8.dp, vertical = 10.dp),
				) {
					Icon(Icons.Default.Apps, contentDescription = null, tint = accent, modifier = Modifier.size(22.dp))
					Spacer(Modifier.width(10.dp))
					Text("All Apps", fontWeight = FontWeight.SemiBold, fontSize = 13.5.sp)
				}
				HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
				LazyColumn(modifier = Modifier.height(300.dp)) {
					items(candidates, key = { it.first }) { (pkg, label) ->
						val isSelected = pkg == selectedPkg
						val cachedBmp = remember(pkg) { getCachedIcon(pkg) }
						val bmp by produceState(initialValue = cachedBmp, key1 = pkg) {
							if (value == null)
								value = getIcon(pkg)
						}
						Row(
							verticalAlignment = Alignment.CenterVertically,
							modifier = Modifier
								.fillMaxWidth()
								.clip(RoundedCornerShape(8.dp))
								.background(if (isSelected) accent.copy(alpha = 0.14f) else Color.Transparent)
								.clickable { onSelect(pkg) }
								.padding(horizontal = 8.dp, vertical = 7.dp),
						) {
							val icon = bmp
							if (icon != null) {
								Image(bitmap = icon, contentDescription = null, modifier = Modifier.size(28.dp).clip(RoundedCornerShape(6.dp)))
							} else {
								Box(Modifier.size(28.dp).clip(RoundedCornerShape(6.dp)).background(MaterialTheme.colorScheme.surfaceVariant))
							}
							Spacer(Modifier.width(10.dp))
							Column(modifier = Modifier.weight(1f)) {
								Text(label.substringBefore(" ("), fontSize = 13.sp, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
								Text(pkg, fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
							}
						}
					}
				}
			}
		},
		confirmButton = {
			TextButton(onClick = onDismiss) { Text("Close") }
		},
	)
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ResponseTypeFilterDialog(
	currentType: String,
	currentExt: String,
	onDismiss: () -> Unit,
	onApply: (String, String) -> Unit,
) {
	var selectedType by remember { mutableStateOf(currentType) }
	var extText by remember { mutableStateOf(currentExt) }

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("Response Type Filter", fontWeight = FontWeight.Bold) },
		text = {
			Column {
				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalArrangement = Arrangement.spacedBy(6.dp),
				) {
					for ((key, label) in listOf(
						"" to "All",
						"image" to "Images",
						"video" to "Video",
						"audio" to "Audio",
						"file" to "File / Ext",
						"default" to "Default (HTML / API)",
					)) {
						FilterChip(
							selected = selectedType == key,
							onClick = { selectedType = key },
							label = { Text(label, fontSize = 12.sp, maxLines = 1, softWrap = false) },
						)
					}
				}

				AnimatedVisibility(visible = selectedType == "file") {
					Column {
						Spacer(Modifier.height(10.dp))
						OutlinedTextField(
							value = extText,
							onValueChange = { extText = it.trim().lowercase().removePrefix(".").take(10) },
							label = { Text("Extension (blank = any file)", maxLines = 1) },
							placeholder = { Text("e.g. apk, pdf, zip, js, json", maxLines = 1) },
							singleLine = true,
							modifier = Modifier.fillMaxWidth(),
						)
						Spacer(Modifier.height(8.dp))
						FlowRow(
							horizontalArrangement = Arrangement.spacedBy(6.dp),
							verticalArrangement = Arrangement.spacedBy(4.dp),
						) {
							for (presetExt in listOf("apk", "pdf", "zip", "js", "json", "m3u8")) {
								FilterChip(
									selected = extText == presetExt,
									onClick = { extText = if (extText == presetExt) "" else presetExt },
									label = { Text(".$presetExt", fontSize = 11.5.sp, maxLines = 1) },
								)
							}
						}
					}
				}
			}
		},
		confirmButton = {
			Button(onClick = {
				val cleanExt = if (selectedType == "file") extText.trim().lowercase().removePrefix(".") else ""
				onApply(selectedType, cleanExt)
			}) {
				Text("Apply")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) { Text("Cancel") }
		},
	)
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
		val respTypeLabel = formatResponseTypeBadge(entry.contentType, entry.fileExt)
		if (respTypeLabel.isNotEmpty())
			InfoField("Response type", respTypeLabel)
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
