package com.renwixx.trueadblocker.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NODATA
import com.renwixx.trueadblocker.data.BLOCKED_DNS_NXDOMAIN
import com.renwixx.trueadblocker.data.BLOCKED_DNS_ZERO_IP
import com.renwixx.trueadblocker.data.HourlyBucket
import com.renwixx.trueadblocker.data.L3_MODE_ALWAYS
import com.renwixx.trueadblocker.data.L3_MODE_AUTO
import com.renwixx.trueadblocker.data.L3_MODE_OFF
import com.renwixx.trueadblocker.data.ProxyProfile
import com.renwixx.trueadblocker.net.CertAuthority
import com.renwixx.trueadblocker.ui.theme.ShieldGreen
import com.renwixx.trueadblocker.ui.theme.ShieldRed
import kotlinx.coroutines.delay
import java.text.NumberFormat
import java.util.Locale

@Composable
fun AnalyticsScreen(vm: MainViewModel) {
	val totalReq by vm.totalRequests.collectAsState()
	val totalBlocked by vm.totalBlocked.collectAsState()
	val totalCname by vm.totalCnameUncloaked.collectAsState()
	val totalParams by vm.totalTrackerParamsRemoved.collectAsState()
	val topParams by vm.topTrackerParams.collectAsState()
	val hourly by vm.hourlyBuckets.collectAsState()
	val topApps by vm.topAppsBreakdown.collectAsState()
	val cfg by vm.config.collectAsState()
	val labelRev by vm.labelRevision.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var isParamEditorOpen by remember { mutableStateOf(false) }
	var isInitialLoaded by remember { mutableStateOf(false) }

	LaunchedEffect(totalReq) {
		if (!isInitialLoaded) {
			isInitialLoaded = true
			vm.refreshAnalytics()
		} else {
			delay(2500L)
			vm.refreshAnalytics()
		}
	}

	val blockRatio = if (totalReq > 0L) (totalBlocked.toDouble() * 100.0 / totalReq.toDouble()) else 0.0
	val fmt = remember { NumberFormat.getIntegerInstance(Locale.US) }

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState())
			.padding(horizontal = 16.dp, vertical = 12.dp),
	) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth(),
		) {
			Text("Analytics", fontSize = 24.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
			IconButton(onClick = { vm.refreshAnalytics() }) {
				Icon(Icons.Default.Refresh, contentDescription = "Refresh analytics")
			}
		}

		Spacer(Modifier.height(10.dp))

		Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
			KpiStatCard(
				title = "Block Ratio",
				value = "%.1f%%".format(Locale.US, blockRatio),
				subtitle = "${fmt.format(totalBlocked)} / ${fmt.format(totalReq)}",
				valueColor = ShieldRed,
				modifier = Modifier.weight(1f),
			)
			KpiStatCard(
				title = "Total Requests",
				value = fmt.format(totalReq),
				subtitle = "${fmt.format((totalReq - totalBlocked).coerceAtLeast(0L))} allowed",
				valueColor = accent,
				modifier = Modifier.weight(1f),
			)
		}

		Spacer(Modifier.height(10.dp))

		Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
			KpiStatCard(
				title = "Tracker Params Removed",
				value = fmt.format(totalParams),
				subtitle = if (cfg.isRemoveTrackParams) "Tap to edit rules" else "Cleaner disabled",
				valueColor = ShieldGreen,
				modifier = Modifier
					.weight(1f)
					.clickable { isParamEditorOpen = true },
			)
			KpiStatCard(
				title = "CNAME Uncloaked",
				value = fmt.format(totalCname),
				subtitle = if (cfg.isCnameUncloaking) "Depth <= ${cfg.maxCnameDepth}" else "Uncloaking off",
				valueColor = accent,
				modifier = Modifier.weight(1f),
			)
		}

		Spacer(Modifier.height(16.dp))

		SectionContainer(title = "24-Hour Request Volume (Hourly)") {
			HourlyStackedBarChart(
				buckets = hourly,
				blockedColor = ShieldRed,
				allowedColor = accent,
			)
		}

		Spacer(Modifier.height(16.dp))

		SectionContainer(
			title = "Stripped URL Tracking Parameters",
			trailing = {
				Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
					TextButton(onClick = { isParamEditorOpen = true }) {
						Text("Rules", fontSize = 12.sp)
					}
					if (topParams.isNotEmpty()) {
						TextButton(onClick = { vm.clearTrackerParamStats() }) {
							Text("Clear", fontSize = 12.sp, color = ShieldRed)
						}
					}
				}
			},
		) {
			if (topParams.isEmpty()) {
				Text(
					text = "No tracking query parameters stripped yet. Browse via HTTPS/HTTP proxy to strip utm_*, fbclid, gclid, igshid, yclid, and \$removeparam tokens.",
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
			} else {
				val maxCnt = topParams.maxOf { it.removedCount }.coerceAtLeast(1L)
				for (p in topParams.take(15)) {
					Column(modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
						Row(verticalAlignment = Alignment.CenterVertically) {
							Text(
								text = "?${p.paramName}=",
								fontWeight = FontWeight.SemiBold,
								fontSize = 13.sp,
								color = ShieldGreen,
								modifier = Modifier.weight(1f),
							)
							Text(
								text = "${fmt.format(p.removedCount)}x",
								fontWeight = FontWeight.Bold,
								fontSize = 12.5.sp,
							)
						}
						Text(
							text = "Last stripped on ${p.lastHost} • ${formatRelativeTime(p.lastSeen)}",
							fontSize = 11.sp,
							color = MaterialTheme.colorScheme.onSurfaceVariant,
							maxLines = 1,
							overflow = TextOverflow.Ellipsis,
						)
						Spacer(Modifier.height(3.dp))
						LinearProgressIndicator(
							progress = { (p.removedCount.toFloat() / maxCnt.toFloat()).coerceIn(0.02f, 1f) },
							color = ShieldGreen,
							trackColor = MaterialTheme.colorScheme.outline,
							modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
						)
					}
				}
			}
		}

		Spacer(Modifier.height(16.dp))

		SectionContainer(title = "Top Apps by Network Activity") {
			if (topApps.isEmpty()) {
				Text(
					text = "App breakdown populates automatically as apps generate DNS, HTTP/S, or L3 traffic.",
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
			} else {
				for (row in topApps.take(20)) {
					val label = remember(row.appPkg, labelRev) { vm.appLabelFast(row.appPkg) }
					val isFw = cfg.firewallWifiApps.contains(row.appPkg) || cfg.firewallMobileApps.contains(row.appPkg)
					val ratio = if (row.totalHits > 0L) (row.blockedHits.toFloat() / row.totalHits.toFloat()).coerceIn(0f, 1f) else 0f

					Row(
						verticalAlignment = Alignment.CenterVertically,
						modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
					) {
						Column(modifier = Modifier.weight(1f)) {
							Text(label, fontWeight = FontWeight.Medium, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
							Text(
								text = "${fmt.format(row.blockedHits)} blocked / ${fmt.format(row.totalHits)} total • ${row.uniqueDomains} targets",
								fontSize = 11.sp,
								color = MaterialTheme.colorScheme.onSurfaceVariant,
							)
							Spacer(Modifier.height(4.dp))
							LinearProgressIndicator(
								progress = { ratio },
								color = ShieldRed,
								trackColor = accent.copy(alpha = 0.28f),
								modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)),
							)
						}
						Spacer(Modifier.width(10.dp))
						FilterChip(
							selected = isFw,
							onClick = { vm.toggleAppFirewallBoth(row.appPkg) },
							label = { Text(if (isFw) "Firewalled" else "Firewall", fontSize = 11.sp, maxLines = 1, softWrap = false) },
						)
					}
					HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
				}
			}
		}

		Spacer(Modifier.height(24.dp))
	}

	if (isParamEditorOpen) {
		TrackingParamRulesDialog(
			isCleanerEnabled = cfg.isRemoveTrackParams,
			initialRules = cfg.trackedParamRules,
			blocklistParamCount = vm.engineStats.collectAsState().value.totalRemoveParamRules,
			onDismiss = { isParamEditorOpen = false },
			onSave = { enabled, rulesText ->
				vm.prefs.update { it.copy(isRemoveTrackParams = enabled, trackedParamRules = rulesText) }
				isParamEditorOpen = false
				vm.postMessage("Tracking parameter rules updated")
			},
		)
	}
}

@Composable
private fun KpiStatCard(
	title: String,
	value: String,
	subtitle: String,
	valueColor: Color,
	modifier: Modifier = Modifier,
) {
	Column(
		modifier = modifier
			.clip(RoundedCornerShape(14.dp))
			.background(MaterialTheme.colorScheme.surface)
			.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
			.padding(14.dp),
	) {
		Text(title, fontSize = 11.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
		Spacer(Modifier.height(4.dp))
		Text(value, fontSize = 20.sp, fontWeight = FontWeight.ExtraBold, color = valueColor, maxLines = 1)
		Spacer(Modifier.height(2.dp))
		Text(subtitle, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
	}
}

@Composable
private fun SectionContainer(
	title: String,
	trailing: (@Composable () -> Unit)? = null,
	content: @Composable () -> Unit,
) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(14.dp))
			.background(MaterialTheme.colorScheme.surface)
			.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
			.padding(14.dp),
	) {
		Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
			Text(title, fontWeight = FontWeight.Bold, fontSize = 14.5.sp, modifier = Modifier.weight(1f))
			trailing?.invoke()
		}
		Spacer(Modifier.height(8.dp))
		content()
	}
}

@Composable
private fun HourlyStackedBarChart(
	buckets: List<HourlyBucket>,
	blockedColor: Color,
	allowedColor: Color,
) {
	val nowHour = System.currentTimeMillis() / 3_600_000L
	val startHour = nowHour - 23L
	val byHour = remember(buckets) { buckets.associateBy { it.hourEpoch } }
	val series = remember(byHour, startHour) {
		List(24) { idx ->
			val h = startHour + idx
			byHour[h] ?: HourlyBucket(h, 0L, 0L)
		}
	}
	val peak = series.maxOfOrNull { it.blockedCount + it.allowedCount }?.coerceAtLeast(1L) ?: 1L
	val emptyBarColor = MaterialTheme.colorScheme.outline

	Column(modifier = Modifier.fillMaxWidth()) {
		Row(
			horizontalArrangement = Arrangement.SpaceBetween,
			modifier = Modifier.fillMaxWidth(),
		) {
			Row(verticalAlignment = Alignment.CenterVertically) {
				Box(Modifier.size(9.dp).clip(RoundedCornerShape(2.dp)).background(blockedColor))
				Spacer(Modifier.width(5.dp))
				Text("Blocked", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
				Spacer(Modifier.width(12.dp))
				Box(Modifier.size(9.dp).clip(RoundedCornerShape(2.dp)).background(allowedColor))
				Spacer(Modifier.width(5.dp))
				Text("Allowed", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			}
			Text("Peak: $peak / hr", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
		}

		Spacer(Modifier.height(10.dp))

		Canvas(
			modifier = Modifier
				.fillMaxWidth()
				.height(136.dp),
		) {
			val count = series.size
			val slotW = size.width / count.toFloat()
			val barW = (slotW * 0.68f).coerceAtLeast(3f)
			val padX = (slotW - barW) / 2f
			val maxH = size.height

			for (i in 0 until count) {
				val b = series[i]
				val tot = b.blockedCount + b.allowedCount
				val x = i * slotW + padX
				if (tot <= 0L) {
					drawRoundRect(
						color = emptyBarColor,
						topLeft = Offset(x, maxH - 3f),
						size = Size(barW, 3f),
						cornerRadius = CornerRadius(2f, 2f),
					)
					continue
				}

				val totalBarH = ((tot.toFloat() / peak.toFloat()) * (maxH - 6f)).coerceAtLeast(4f)
				val blockedH = (b.blockedCount.toFloat() / tot.toFloat()) * totalBarH
				val allowedH = totalBarH - blockedH

				if (allowedH > 0.5f) {
					drawRoundRect(
						color = allowedColor.copy(alpha = 0.78f),
						topLeft = Offset(x, maxH - totalBarH),
						size = Size(barW, allowedH),
						cornerRadius = CornerRadius(3f, 3f),
					)
				}
				if (blockedH > 0.5f) {
					drawRoundRect(
						color = blockedColor,
						topLeft = Offset(x, maxH - blockedH),
						size = Size(barW, blockedH),
						cornerRadius = CornerRadius(3f, 3f),
					)
				}
			}
		}

		Spacer(Modifier.height(4.dp))
		Row(
			horizontalArrangement = Arrangement.SpaceBetween,
			modifier = Modifier.fillMaxWidth(),
		) {
			Text("-24h", fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			Text("-12h", fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			Text("-6h", fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			Text("Now", fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
		}
	}
}

@Composable
private fun TrackingParamRulesDialog(
	isCleanerEnabled: Boolean,
	initialRules: String,
	blocklistParamCount: Int,
	onDismiss: () -> Unit,
	onSave: (Boolean, String) -> Unit,
) {
	var isEnabled by remember { mutableStateOf(isCleanerEnabled) }
	var rulesText by remember { mutableStateOf(initialRules) }

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("URL Tracking Parameter Cleaner") },
		text = {
			Column {
				Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
					Text("Strip tracking parameters", modifier = Modifier.weight(1f), fontWeight = FontWeight.Medium)
					Switch(checked = isEnabled, onCheckedChange = { isEnabled = it })
				}
				Spacer(Modifier.height(6.dp))
				Text(
					text = "Comma-separated exact names or wildcards (e.g. utm_*, fbclid, gclid, yclid). Plus $blocklistParamCount global \$removeparam rules active from blocklists.",
					fontSize = 11.5.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
				Spacer(Modifier.height(10.dp))
				OutlinedTextField(
					value = rulesText,
					onValueChange = { rulesText = it },
					label = { Text("Tracked parameter patterns") },
					minLines = 4,
					maxLines = 7,
					modifier = Modifier.fillMaxWidth(),
				)
			}
		},
		confirmButton = {
			Button(onClick = { onSave(isEnabled, rulesText) }) {
				Text("Save")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) { Text("Cancel") }
		},
	)
}

@Composable
fun ProxiesSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
) {
	LaunchedEffect(Unit) {
		vm.loadInstalledAppsIfNeeded()
	}

	val cfg by vm.config.collectAsState()
	val apps by vm.installedApps.collectAsState()
	val installedSet by vm.installedPkgSet.collectAsState()
	val testingId by vm.testingProxyId.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var editingProfile by remember { mutableStateOf<ProxyProfile?>(null) }
	var isAddingNew by remember { mutableStateOf(false) }

	Column(modifier = Modifier.fillMaxSize()) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("Per-App Proxies", fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
			Button(
				onClick = { isAddingNew = true },
				modifier = Modifier.padding(end = 8.dp),
			) {
				Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
				Spacer(Modifier.width(4.dp))
				Text("Add Proxy", maxLines = 1, softWrap = false)
			}
		}

		Text(
			text = "Route all device traffic or selected apps (WhatsApp, Telegram, games, browsers) via SOCKS5 (TCP + UDP ASSOCIATE + Remote DNS) or HTTP CONNECT (TCP + Remote DNS), with automatic UDP/IPv6 leak protection.",
			fontSize = 12.sp,
			color = MaterialTheme.colorScheme.onSurfaceVariant,
			modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
		)

		if (cfg.proxies.isEmpty()) {
			Box(
				contentAlignment = Alignment.Center,
				modifier = Modifier.fillMaxSize().padding(32.dp),
			) {
				Text(
					text = "No upstream proxies configured yet.\nTap '+ Add Proxy' to create a SOCKS5 or HTTP proxy profile.",
					color = MaterialTheme.colorScheme.onSurfaceVariant,
					fontSize = 14.sp,
				)
			}
		} else {
			LazyColumn(
				modifier = Modifier.fillMaxSize(),
				contentPadding = PaddingValues(16.dp),
				verticalArrangement = Arrangement.spacedBy(10.dp),
			) {
				items(cfg.proxies, key = { it.id }) { p ->
					val matchedInstalledCount = if (installedSet.isEmpty()) p.appPackages.size else p.appPackages.count { installedSet.contains(it) }
					val scopeLabel = if (p.isAllApps) "All non-bypassed apps" else "$matchedInstalledCount selected app(s)"
					val isTestingThis = testingId == p.id

					Column(
						modifier = Modifier
							.fillMaxWidth()
							.clip(RoundedCornerShape(14.dp))
							.background(MaterialTheme.colorScheme.surface)
							.border(
								width = 1.dp,
								color = if (p.isEnabled) accent.copy(alpha = 0.7f) else MaterialTheme.colorScheme.outline,
								shape = RoundedCornerShape(14.dp),
							)
							.clickable { editingProfile = p }
							.padding(14.dp),
					) {
						Row(verticalAlignment = Alignment.CenterVertically) {
							Column(modifier = Modifier.weight(1f)) {
								Row(verticalAlignment = Alignment.CenterVertically) {
									Text(p.name, fontWeight = FontWeight.Bold, fontSize = 15.5.sp)
									Spacer(Modifier.width(8.dp))
									Box(
										modifier = Modifier
											.clip(RoundedCornerShape(4.dp))
											.background(accent.copy(alpha = 0.16f))
											.padding(horizontal = 6.dp, vertical = 2.dp),
									) {
										Text(p.type.uppercase(), fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = accent)
									}
								}
								Text(
									text = "${p.host}:${p.port}" +
										(if (p.username.isNotEmpty()) " • Auth" else "") +
										(if (p.isRemoteDns) " • Remote DNS" else "") +
										(if (p.type.equals("SOCKS5", true) && p.isUdpRelay) " • UDP Relay" else "") +
										(if (p.isBlockUdpFallback) " • No UDP Leak" else ""),
									fontSize = 12.5.sp,
									color = MaterialTheme.colorScheme.onSurfaceVariant,
								)
								Text(
									text = "$scopeLabel • Hosts: ${p.hostFilter} • Ports: ${p.portFilter}",
									fontSize = 11.5.sp,
									color = MaterialTheme.colorScheme.onSurfaceVariant,
								)
							}
							Switch(
								checked = p.isEnabled,
								onCheckedChange = { vm.toggleProxyProfileEnabled(p.id) },
							)
						}

						Spacer(Modifier.height(8.dp))
						Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
							OutlinedButton(
								enabled = !isTestingThis,
								onClick = { vm.testProxyProfile(p) },
							) {
								if (isTestingThis) {
									CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
								} else {
									Icon(Icons.Default.NetworkCheck, contentDescription = null, modifier = Modifier.size(16.dp))
								}
								Spacer(Modifier.width(6.dp))
								Text("Test", fontSize = 12.sp, maxLines = 1)
							}
							OutlinedButton(onClick = { editingProfile = p }) {
								Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(16.dp))
								Spacer(Modifier.width(6.dp))
								Text("Edit", fontSize = 12.sp, maxLines = 1)
							}
							OutlinedButton(onClick = { vm.deleteProxyProfile(p.id) }) {
								Icon(Icons.Default.DeleteOutline, contentDescription = null, tint = ShieldRed, modifier = Modifier.size(16.dp))
								Spacer(Modifier.width(4.dp))
								Text("Delete", fontSize = 12.sp, color = ShieldRed, maxLines = 1)
							}
						}
					}
				}
			}
		}
	}

	if (isAddingNew) {
		ProxyEditorDialog(
			initial = null,
			installedApps = apps,
			getIcon = { pkg -> vm.getAppIcon(pkg) },
			onDismiss = { isAddingNew = false },
			onSave = { created ->
				vm.saveProxyProfile(created)
				isAddingNew = false
			},
		)
	}

	editingProfile?.let { existing ->
		ProxyEditorDialog(
			initial = existing,
			installedApps = apps,
			getIcon = { pkg -> vm.getAppIcon(pkg) },
			onDismiss = { editingProfile = null },
			onSave = { updated ->
				vm.saveProxyProfile(updated)
				editingProfile = null
			},
		)
	}
}

@Composable
private fun ProxyEditorDialog(
	initial: ProxyProfile?,
	installedApps: List<InstalledAppItem>,
	getIcon: suspend (String) -> ImageBitmap?,
	onDismiss: () -> Unit,
	onSave: (ProxyProfile) -> Unit,
) {
	var name by remember { mutableStateOf(initial?.name ?: "SOCKS5 Proxy") }
	var type by remember { mutableStateOf(initial?.type ?: "SOCKS5") }
	var host by remember { mutableStateOf(initial?.host ?: "") }
	var portText by remember { mutableStateOf((initial?.port ?: 1080).toString()) }
	var username by remember { mutableStateOf(initial?.username ?: "") }
	var password by remember { mutableStateOf(initial?.password ?: "") }
	var isRemoteDns by remember { mutableStateOf(initial?.isRemoteDns ?: true) }
	var isUdpRelay by remember { mutableStateOf(initial?.isUdpRelay ?: true) }
	var isBlockUdpFallback by remember { mutableStateOf(initial?.isBlockUdpFallback ?: true) }
	var isAllApps by remember { mutableStateOf(initial?.isAllApps ?: false) }
	var selectedPkgs by remember { mutableStateOf(initial?.appPackages ?: emptySet()) }
	var hostFilter by remember { mutableStateOf(initial?.hostFilter ?: "*") }
	var portFilter by remember { mutableStateOf(initial?.portFilter ?: "*") }
	var isPickingApps by remember { mutableStateOf(false) }

	val portNum = portText.toIntOrNull() ?: 0
	val isValid = host.trim().isNotEmpty() && portNum in 1..65535

	if (isPickingApps) {
		AppMultiSelectDialog(
			allApps = installedApps,
			selected = selectedPkgs,
			getIcon = getIcon,
			onDismiss = { isPickingApps = false },
			onConfirm = { picked ->
				selectedPkgs = picked
				isPickingApps = false
			},
		)
		return
	}

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text(if (initial == null) "New Proxy Profile" else "Edit Proxy Profile") },
		text = {
			Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					FilterChip(
						selected = type.equals("SOCKS5", ignoreCase = true),
						onClick = { type = "SOCKS5" },
						label = { Text("SOCKS5", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = type.equals("HTTP", ignoreCase = true),
						onClick = { type = "HTTP" },
						label = { Text("HTTP CONNECT", maxLines = 1, softWrap = false) },
					)
				}

				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = name,
					onValueChange = { name = it },
					label = { Text("Profile Name (e.g. WhatsApp SOCKS5)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = host,
						onValueChange = { host = it },
						label = { Text("Proxy Host / IP") },
						singleLine = true,
						modifier = Modifier.weight(1.8f),
					)
					OutlinedTextField(
						value = portText,
						onValueChange = { portText = it.filter { c -> c.isDigit() }.take(5) },
						label = { Text("Port") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = username,
						onValueChange = { username = it },
						label = { Text("Username (optional)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = password,
						onValueChange = { password = it },
						label = { Text("Password (optional)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(6.dp))
				Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
					Column(modifier = Modifier.weight(1f)) {
						Text("Remote DNS via Proxy", fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
						Text("Tunnels DNS & sends domain names to proxy to prevent ISP DNS leaks", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
					}
					Switch(checked = isRemoteDns, onCheckedChange = { isRemoteDns = it })
				}

				if (type.equals("SOCKS5", ignoreCase = true)) {
					Spacer(Modifier.height(6.dp))
					Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
						Column(modifier = Modifier.weight(1f)) {
							Text("UDP Relay (SOCKS5 UDP ASSOCIATE)", fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
							Text("Proxies UDP traffic (calls, WebRTC, games, QUIC) if server supports RFC 1928 UDP", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
						}
						Switch(checked = isUdpRelay, onCheckedChange = { isUdpRelay = it })
					}
				}

				Spacer(Modifier.height(6.dp))
				Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
					Column(modifier = Modifier.weight(1f)) {
						Text("Block Unproxied UDP (Prevent Real IP Leak)", fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
						Text("Drops direct UDP when using HTTP CONNECT or if SOCKS5 server lacks UDP support", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
					}
					Switch(checked = isBlockUdpFallback, onCheckedChange = { isBlockUdpFallback = it })
				}

				Spacer(Modifier.height(8.dp))
				Text("App Routing Filter", fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
				Spacer(Modifier.height(4.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					FilterChip(
						selected = !isAllApps,
						onClick = { isAllApps = false },
						label = { Text("Selected Apps (${selectedPkgs.size})", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = isAllApps,
						onClick = { isAllApps = true },
						label = { Text("All Apps", maxLines = 1, softWrap = false) },
					)
				}

				if (!isAllApps) {
					Spacer(Modifier.height(6.dp))
					OutlinedButton(
						onClick = { isPickingApps = true },
						modifier = Modifier.fillMaxWidth(),
					) {
						Text("Choose Apps (${selectedPkgs.size} selected — e.g. WhatsApp)")
					}
				}

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = hostFilter,
						onValueChange = { hostFilter = it },
						label = { Text("Host Filter (* or *.org)") },
						singleLine = true,
						modifier = Modifier.weight(1.3f),
					)
					OutlinedTextField(
						value = portFilter,
						onValueChange = { portFilter = it },
						label = { Text("Ports (* or 443,5222)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}
			}
		},
		confirmButton = {
			Button(
				enabled = isValid,
				onClick = {
					onSave(
						ProxyProfile(
							id = initial?.id ?: "proxy_${System.currentTimeMillis()}",
							name = name.trim().ifEmpty { "$type Proxy" },
							isEnabled = initial?.isEnabled ?: true,
							type = type,
							host = host.trim(),
							port = portNum,
							username = username.trim(),
							password = password,
							isRemoteDns = isRemoteDns,
							isUdpRelay = isUdpRelay,
							isBlockUdpFallback = isBlockUdpFallback,
							isAllApps = isAllApps,
							appPackages = selectedPkgs,
							hostFilter = hostFilter.trim().ifEmpty { "*" },
							portFilter = portFilter.trim().ifEmpty { "*" },
						)
					)
				},
			) {
				Text("Save")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) { Text("Cancel") }
		},
	)
}

@Composable
private fun AppMultiSelectDialog(
	allApps: List<InstalledAppItem>,
	selected: Set<String>,
	getIcon: suspend (String) -> ImageBitmap?,
	onDismiss: () -> Unit,
	onConfirm: (Set<String>) -> Unit,
) {
	var query by remember { mutableStateOf("") }
	var includeSystem by remember { mutableStateOf(false) }
	var currentSet by remember { mutableStateOf(selected) }

	val shown = remember(allApps, query, includeSystem, currentSet) {
		allApps
			.filter { a ->
				(includeSystem || !a.isSystem || currentSet.contains(a.packageName)) &&
					(query.isBlank() || a.label.contains(query, true) || a.packageName.contains(query, true))
			}
			.sortedWith(compareByDescending<InstalledAppItem> { currentSet.contains(it.packageName) }.thenBy { it.label.lowercase() })
	}

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("Select Apps for Proxy (${currentSet.size})") },
		text = {
			Column {
				OutlinedTextField(
					value = query,
					onValueChange = { query = it },
					placeholder = { Text("Search e.g. WhatsApp, Chrome...") },
					leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Row(verticalAlignment = Alignment.CenterVertically) {
					Checkbox(checked = includeSystem, onCheckedChange = { includeSystem = it })
					Text("Show system apps", fontSize = 12.sp)
				}
				LazyColumn(modifier = Modifier.height(320.dp)) {
					items(shown, key = { it.packageName }) { app ->
						val isChecked = currentSet.contains(app.packageName)
						val bmp by produceState<ImageBitmap?>(initialValue = null, key1 = app.packageName) {
							value = getIcon(app.packageName)
						}
						Row(
							verticalAlignment = Alignment.CenterVertically,
							modifier = Modifier
								.fillMaxWidth()
								.clickable {
									val m = currentSet.toMutableSet()
									if (!m.add(app.packageName))
										m.remove(app.packageName)
									currentSet = m
								}
								.padding(vertical = 6.dp),
						) {
							val icon = bmp
							if (icon != null) {
								Image(bitmap = icon, contentDescription = null, modifier = Modifier.size(30.dp).clip(RoundedCornerShape(6.dp)))
							} else {
								Box(Modifier.size(30.dp).clip(RoundedCornerShape(6.dp)).background(MaterialTheme.colorScheme.surface))
							}
							Spacer(Modifier.width(10.dp))
							Column(modifier = Modifier.weight(1f)) {
								Text(app.label, fontSize = 13.sp, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
								Text(app.packageName, fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
							}
							Checkbox(
								checked = isChecked,
								onCheckedChange = {
									val m = currentSet.toMutableSet()
									if (!m.add(app.packageName))
										m.remove(app.packageName)
									currentSet = m
								},
							)
						}
					}
				}
			}
		},
		confirmButton = {
			Button(onClick = { onConfirm(currentSet) }) {
				Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp))
				Spacer(Modifier.width(4.dp))
				Text("Done")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) { Text("Cancel") }
		},
	)
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EngineConfigSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
) {
	val cfg by vm.config.collectAsState()
	val stats by vm.engineStats.collectAsState()
	val vpn by vm.vpnState.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var clientIpText by remember(cfg.vpnClientIp) { mutableStateOf(cfg.vpnClientIp) }
	var dnsIpText by remember(cfg.vpnDnsIp) { mutableStateOf(cfg.vpnDnsIp) }
	var mtuText by remember(cfg.vpnMtu) { mutableStateOf(cfg.vpnMtu.toString()) }
	var workersText by remember(cfg.dnsWorkerThreads) { mutableStateOf(cfg.dnsWorkerThreads.toString()) }
	var cacheSizeText by remember(cfg.dnsCacheSize) { mutableStateOf(cfg.dnsCacheSize.toString()) }
	var cacheTtlText by remember(cfg.dnsCacheTtlSec) { mutableStateOf(cfg.dnsCacheTtlSec.toString()) }
	var dnsTimeoutText by remember(cfg.upstreamDnsTimeoutMs) { mutableStateOf(cfg.upstreamDnsTimeoutMs.toString()) }
	var cnameDepthText by remember(cfg.maxCnameDepth) { mutableStateOf(cfg.maxCnameDepth.toString()) }
	var maxCosmeticText by remember(cfg.maxGenericCosmeticSelectors) { mutableStateOf(cfg.maxGenericCosmeticSelectors.toString()) }
	var connectTimeoutText by remember(cfg.proxyConnectTimeoutMs) { mutableStateOf(cfg.proxyConnectTimeoutMs.toString()) }
	var readTimeoutText by remember(cfg.proxyReadTimeoutMs) { mutableStateOf(cfg.proxyReadTimeoutMs.toString()) }
	var certDaysText by remember(cfg.leafCertValidityDays) { mutableStateOf(cfg.leafCertValidityDays.toString()) }
	var flushMsText by remember(cfg.logFlushIntervalMs) { mutableStateOf(cfg.logFlushIntervalMs.toString()) }
	var batchSizeText by remember(cfg.logMaxBatchSize) { mutableStateOf(cfg.logMaxBatchSize.toString()) }
	var maxRawText by remember(cfg.maxRawEntries) { mutableStateOf(cfg.maxRawEntries.toString()) }

	LaunchedEffect(
		clientIpText,
		dnsIpText,
		mtuText,
		workersText,
		cacheSizeText,
		cacheTtlText,
		dnsTimeoutText,
		cnameDepthText,
		maxCosmeticText,
		connectTimeoutText,
		readTimeoutText,
		certDaysText,
		flushMsText,
		batchSizeText,
		maxRawText,
	) {
		delay(550L)
		vm.prefs.update { cur ->
			val nextClientIp = clientIpText.trim().let { if (CertAuthority.isIpv4Literal(it)) it else cur.vpnClientIp }
			val nextDnsIp = dnsIpText.trim().let { if (CertAuthority.isIpv4Literal(it) && it != nextClientIp) it else cur.vpnDnsIp }
			cur.copy(
				vpnClientIp = nextClientIp,
				vpnDnsIp = nextDnsIp,
				vpnMtu = mtuText.toIntOrNull()?.takeIf { it in 1280..9000 } ?: cur.vpnMtu,
				dnsWorkerThreads = workersText.toIntOrNull()?.takeIf { it in 2..32 } ?: cur.dnsWorkerThreads,
				dnsCacheSize = cacheSizeText.toIntOrNull()?.takeIf { it in 64..16384 } ?: cur.dnsCacheSize,
				dnsCacheTtlSec = cacheTtlText.toIntOrNull()?.takeIf { it in 5..3600 } ?: cur.dnsCacheTtlSec,
				upstreamDnsTimeoutMs = dnsTimeoutText.toIntOrNull()?.takeIf { it in 500..15000 } ?: cur.upstreamDnsTimeoutMs,
				maxCnameDepth = cnameDepthText.toIntOrNull()?.takeIf { it in 1..16 } ?: cur.maxCnameDepth,
				maxGenericCosmeticSelectors = maxCosmeticText.toIntOrNull()?.takeIf { it in 50..5000 } ?: cur.maxGenericCosmeticSelectors,
				proxyConnectTimeoutMs = connectTimeoutText.toIntOrNull()?.takeIf { it in 1000..30000 } ?: cur.proxyConnectTimeoutMs,
				proxyReadTimeoutMs = readTimeoutText.toIntOrNull()?.takeIf { it in 2000..60000 } ?: cur.proxyReadTimeoutMs,
				leafCertValidityDays = certDaysText.toIntOrNull()?.takeIf { it in 1..397 } ?: cur.leafCertValidityDays,
				logFlushIntervalMs = flushMsText.toIntOrNull()?.takeIf { it in 50..5000 } ?: cur.logFlushIntervalMs,
				logMaxBatchSize = batchSizeText.toIntOrNull()?.takeIf { it in 32..4096 } ?: cur.logMaxBatchSize,
				maxRawEntries = maxRawText.toIntOrNull()?.takeIf { it in 1000..500000 } ?: cur.maxRawEntries,
			)
		}
	}

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState()),
	) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("Live Engine Config", fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
			TextButton(onClick = { vm.resetEngineTuning() }) {
				Icon(Icons.Default.RestartAlt, contentDescription = null, modifier = Modifier.size(18.dp))
				Spacer(Modifier.width(4.dp))
				Text("Defaults")
			}
		}

		Column(
			verticalArrangement = Arrangement.spacedBy(14.dp),
			modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
		) {
			Text(
				text = "All parameters apply live on the fly. Active proxy port: ${vpn.proxyPort} • L3 router: ${if (vpn.isL3CaptureActive) "ACTIVE" else "STANDBY"}",
				fontSize = 12.sp,
				color = accent,
			)

			SectionContainer(title = "1. VPN Tunnel & L3 Packet Router") {
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = clientIpText,
						onValueChange = { v -> clientIpText = v },
						isError = clientIpText.isNotBlank() && !CertAuthority.isIpv4Literal(clientIpText.trim()),
						label = { Text("TUN Client IPv4") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = dnsIpText,
						onValueChange = { v -> dnsIpText = v },
						isError = dnsIpText.isNotBlank() && (!CertAuthority.isIpv4Literal(dnsIpText.trim()) || dnsIpText.trim() == clientIpText.trim()),
						label = { Text("Virtual DNS IPv4") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = mtuText,
						onValueChange = { v -> mtuText = v.filter { it.isDigit() }.take(4) },
						label = { Text("TUN MTU (1280–9000)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = workersText,
						onValueChange = { v -> workersText = v.filter { it.isDigit() }.take(2) },
						label = { Text("DNS Threads (2–32)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(10.dp))
				Text("L3 Full-Packet Capture Mode (0.0.0.0/0)", fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
				Spacer(Modifier.height(4.dp))
				FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					FilterChip(
						selected = cfg.l3RoutingMode == L3_MODE_AUTO,
						onClick = { vm.prefs.update { it.copy(l3RoutingMode = L3_MODE_AUTO) } },
						label = { Text("Auto (Proxy / FW)", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = cfg.l3RoutingMode == L3_MODE_ALWAYS,
						onClick = { vm.prefs.update { it.copy(l3RoutingMode = L3_MODE_ALWAYS) } },
						label = { Text("Always On", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = cfg.l3RoutingMode == L3_MODE_OFF,
						onClick = { vm.prefs.update { it.copy(l3RoutingMode = L3_MODE_OFF) } },
						label = { Text("DNS + HTTP Proxy Only", maxLines = 1, softWrap = false) },
					)
				}

				Spacer(Modifier.height(8.dp))
				SettingSwitchCard(
					title = "Sinkhole IPv6 inside VPN (Prevent IPv6 Leak)",
					subtitle = "Routes ::/0 into local sinkhole so apps cannot bypass IPv4 DNS/proxy/firewall over IPv6",
					isChecked = cfg.isBlockIpv6,
					onToggle = { v -> vm.prefs.update { it.copy(isBlockIpv6 = v) } },
				)
			}

			SectionContainer(title = "2. DNS Engine & CNAME Uncloaking") {
				Text("Blocked DNS Response Type", fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
				Spacer(Modifier.height(4.dp))
				FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					FilterChip(
						selected = cfg.blockedDnsMode == BLOCKED_DNS_ZERO_IP,
						onClick = { vm.prefs.update { it.copy(blockedDnsMode = BLOCKED_DNS_ZERO_IP) } },
						label = { Text("0.0.0.0 / ::", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = cfg.blockedDnsMode == BLOCKED_DNS_NXDOMAIN,
						onClick = { vm.prefs.update { it.copy(blockedDnsMode = BLOCKED_DNS_NXDOMAIN) } },
						label = { Text("NXDOMAIN (Rcode 3)", maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = cfg.blockedDnsMode == BLOCKED_DNS_NODATA,
						onClick = { vm.prefs.update { it.copy(blockedDnsMode = BLOCKED_DNS_NODATA) } },
						label = { Text("Empty NODATA", maxLines = 1, softWrap = false) },
					)
				}

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = cacheSizeText,
						onValueChange = { v -> cacheSizeText = v.filter { it.isDigit() }.take(5) },
						label = { Text("DNS Cache Entries") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = cacheTtlText,
						onValueChange = { v -> cacheTtlText = v.filter { it.isDigit() }.take(4) },
						label = { Text("Cache TTL (sec)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(8.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = dnsTimeoutText,
						onValueChange = { v -> dnsTimeoutText = v.filter { it.isDigit() }.take(5) },
						label = { Text("DNS Timeout (ms)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = cnameDepthText,
						onValueChange = { v -> cnameDepthText = v.filter { it.isDigit() }.take(2) },
						label = { Text("Max CNAME Depth") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(8.dp))
				SettingSwitchCard(
					title = "DNS CNAME Uncloaking",
					subtitle = "Inspects upstream DNS CNAME chains and blocks disguised first-party tracker aliases",
					isChecked = cfg.isCnameUncloaking,
					onToggle = { v -> vm.prefs.update { it.copy(isCnameUncloaking = v) } },
				)
			}

			SectionContainer(title = "3. URL Tracking Parameter Cleaner (\$removeparam)") {
				SettingSwitchCard(
					title = "Strip Tracking Query Parameters",
					subtitle = "Removes utm_*, fbclid, gclid, yclid, igshid + ${stats.totalRemoveParamRules} list \$removeparam rules",
					isChecked = cfg.isRemoveTrackParams,
					onToggle = { v -> vm.prefs.update { it.copy(isRemoveTrackParams = v) } },
				)
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = cfg.trackedParamRules,
					onValueChange = { txt -> vm.prefs.update { it.copy(trackedParamRules = txt) } },
					label = { Text("Tracking Parameter Patterns (comma-separated, * supported)") },
					minLines = 3,
					maxLines = 6,
					modifier = Modifier.fillMaxWidth(),
				)
			}

			SectionContainer(title = "4. HTML Cosmetic CSS Injection (##)") {
				SettingSwitchCard(
					title = "Inject Cosmetic Element-Hiding CSS",
					subtitle = "Hides DOM ad placeholders in intercepted HTML (${stats.totalCosmeticRules} selectors parsed)",
					isChecked = cfg.isCosmeticFiltering,
					onToggle = { v -> vm.prefs.update { it.copy(isCosmeticFiltering = v) } },
				)
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = maxCosmeticText,
					onValueChange = { v -> maxCosmeticText = v.filter { it.isDigit() }.take(4) },
					label = { Text("Max Generic CSS Selectors Injected (50–5000)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = cfg.customCosmeticCss,
					onValueChange = { css -> vm.prefs.update { it.copy(customCosmeticCss = css) } },
					label = { Text("Custom Global CSS (e.g. .ad-box{display:none!important})") },
					minLines = 2,
					maxLines = 5,
					modifier = Modifier.fillMaxWidth(),
				)
			}

			SectionContainer(title = "5. MITM TLS & Outbound Socket Timeouts") {
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = connectTimeoutText,
						onValueChange = { v -> connectTimeoutText = v.filter { it.isDigit() }.take(5) },
						label = { Text("Connect Timeout (ms)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = readTimeoutText,
						onValueChange = { v -> readTimeoutText = v.filter { it.isDigit() }.take(5) },
						label = { Text("Read Timeout (ms)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = certDaysText,
					onValueChange = { v -> certDaysText = v.filter { it.isDigit() }.take(3) },
					label = { Text("MITM Leaf Certificate Validity (days, 1–397)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
			}

			SectionContainer(title = "6. Traffic Database Batching & Retention") {
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedTextField(
						value = flushMsText,
						onValueChange = { v -> flushMsText = v.filter { it.isDigit() }.take(4) },
						label = { Text("DB Flush Delay (ms)") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
					OutlinedTextField(
						value = batchSizeText,
						onValueChange = { v -> batchSizeText = v.filter { it.isDigit() }.take(4) },
						label = { Text("Max Batch Rows") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = maxRawText,
					onValueChange = { v -> maxRawText = v.filter { it.isDigit() }.take(6) },
					label = { Text("Max Live Raw Rows Retained (1000–500000)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
			}

			Spacer(Modifier.height(24.dp))
		}
	}
}
