package com.renwixx.trueadblocker.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.paging.compose.collectAsLazyPagingItems
import com.renwixx.trueadblocker.BuildConfig
import com.renwixx.trueadblocker.data.BackupInspection
import com.renwixx.trueadblocker.data.BackupSections
import com.renwixx.trueadblocker.data.BlocklistSource
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.DNS_PRESETS
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import com.renwixx.trueadblocker.data.THEME_DARK
import com.renwixx.trueadblocker.data.THEME_LIGHT
import com.renwixx.trueadblocker.data.THEME_OLED
import com.renwixx.trueadblocker.engine.GitHubRepoItem
import com.renwixx.trueadblocker.net.AdBlockVpnService
import com.renwixx.trueadblocker.ui.theme.ShieldGreen
import com.renwixx.trueadblocker.ui.theme.ShieldRed
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class AdvancedSubScreen {
	HUB,
	CUSTOM_RULES,
	BLOCKLISTS,
	HTTPS_SETUP,
	PROXIES,
	APPS,
	NETWORKS,
	ENGINE_CONFIG,
}

@Composable
fun AdvancedScreen(
	vm: MainViewModel,
	currentSub: AdvancedSubScreen,
	onNavigateSub: (AdvancedSubScreen) -> Unit,
	onSaveCaFile: () -> Unit,
	onOpenSystemSecuritySettings: () -> Unit,
	onImportLocalFilterTxt: () -> Unit,
) {
	if (currentSub != AdvancedSubScreen.HUB) {
		BackHandler { onNavigateSub(AdvancedSubScreen.HUB) }
	}

	when (currentSub) {
		AdvancedSubScreen.HUB -> AdvancedHubView(vm, onNavigateSub)
		AdvancedSubScreen.CUSTOM_RULES -> CustomRulesSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
		)
		AdvancedSubScreen.BLOCKLISTS -> BlocklistsSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
			onImportLocalTxt = onImportLocalFilterTxt,
		)
		AdvancedSubScreen.HTTPS_SETUP -> HttpsSetupSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
			onSaveCaFile = onSaveCaFile,
			onOpenSystemSecuritySettings = onOpenSystemSecuritySettings,
		)
		AdvancedSubScreen.PROXIES -> ProxiesSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
		)
		AdvancedSubScreen.APPS -> AppsSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
			onOpenProxies = { onNavigateSub(AdvancedSubScreen.PROXIES) },
		)
		AdvancedSubScreen.NETWORKS -> NetworksSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
		)
		AdvancedSubScreen.ENGINE_CONFIG -> EngineConfigSubView(
			vm = vm,
			onBack = { onNavigateSub(AdvancedSubScreen.HUB) },
		)
	}
}

@Composable
private fun AdvancedHubView(
	vm: MainViewModel,
	onSelect: (AdvancedSubScreen) -> Unit,
) {
	val lists by vm.blocklists.collectAsState()
	val rulesSummary by vm.customRulesSummary.collectAsState()
	val cfg by vm.config.collectAsState()
	val ca by vm.caStatus.collectAsState()
	val installedSet by vm.installedPkgSet.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	val activeLists = lists.count { it.isEnabled }
	val autoText = if (cfg.isAutoUpdateLists) "Auto-sync every ${cfg.autoUpdateIntervalHours}h" else "Auto-sync off"

	val bypassedCnt = remember(cfg.bypassedApps, installedSet) {
		if (installedSet.isEmpty()) cfg.bypassedApps.size else cfg.bypassedApps.count { installedSet.contains(it) }
	}
	val httpsCnt = remember(cfg.httpsInspectedApps, installedSet) {
		if (installedSet.isEmpty()) cfg.httpsInspectedApps.size else cfg.httpsInspectedApps.count { installedSet.contains(it) }
	}
	val fwCnt = remember(cfg.firewallWifiApps, cfg.firewallMobileApps, installedSet) {
		val union = cfg.firewallWifiApps + cfg.firewallMobileApps
		if (installedSet.isEmpty()) union.size else union.count { installedSet.contains(it) }
	}
	val enabledProxies = cfg.proxies.count { it.isEnabled }

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState())
			.padding(horizontal = 16.dp, vertical = 12.dp),
	) {
		Text("Advanced", fontSize = 24.sp, fontWeight = FontWeight.Bold)
		Spacer(Modifier.height(14.dp))

		HubCardRow(
			icon = Icons.Default.Edit,
			accent = accent,
			title = "Custom Rules Editor",
			subtitle = "${rulesSummary.first} blocked • ${rulesSummary.second} allowed — Exact / Wildcard / Regex / Routes",
			onClick = { onSelect(AdvancedSubScreen.CUSTOM_RULES) },
		)
		HubCardRow(
			icon = Icons.Default.Shield,
			accent = accent,
			title = "Blocklists & GitHub Explorer",
			subtitle = "$activeLists/${lists.size} active • Browse GitHub lists, add direct URL • $autoText",
			onClick = { onSelect(AdvancedSubScreen.BLOCKLISTS) },
		)
		HubCardRow(
			icon = Icons.Default.Lock,
			accent = accent,
			title = "HTTPS & URL Route Filtering",
			subtitle = when {
				cfg.isHttpsFiltering && ca.isInstalledInSystem -> "Active & Trusted by Chrome — filtering HTTPS routes ($httpsCnt apps)"
				cfg.isHttpsFiltering && ca.isReady -> "CA generated — install .crt in Android Settings"
				else -> "Configure Root CA for path rules (xxx.com/ad vs xxx.com/content)"
			},
			onClick = { onSelect(AdvancedSubScreen.HTTPS_SETUP) },
		)
		HubCardRow(
			icon = Icons.Default.SwapHoriz,
			accent = accent,
			title = "Per-App Proxies (SOCKS5 / HTTP)",
			subtitle = "$enabledProxies/${cfg.proxies.size} active — route apps (e.g. WhatsApp) via SOCKS5 or HTTP CONNECT",
			onClick = { onSelect(AdvancedSubScreen.PROXIES) },
		)
		HubCardRow(
			icon = Icons.Default.Apps,
			accent = accent,
			title = "Apps & Per-App Firewall",
			subtitle = "$bypassedCnt bypassed • $httpsCnt HTTPS • $fwCnt firewalled",
			onClick = { onSelect(AdvancedSubScreen.APPS) },
		)
		HubCardRow(
			icon = Icons.Default.Wifi,
			accent = accent,
			title = "Networks & DNS",
			subtitle = "Upstream DNS / DoH & separate Wi-Fi / Mobile policies",
			onClick = { onSelect(AdvancedSubScreen.NETWORKS) },
		)
		HubCardRow(
			icon = Icons.Default.Tune,
			accent = accent,
			title = "Live Engine & Protocol Config",
			subtitle = "Edit MTU, VPN IPs, L3 capture, CNAME, \$removeparam, Cosmetic CSS & timeouts on the fly",
			onClick = { onSelect(AdvancedSubScreen.ENGINE_CONFIG) },
		)
	}
}

@Composable
private fun HubCardRow(
	icon: ImageVector,
	accent: Color,
	title: String,
	subtitle: String,
	onClick: () -> Unit,
) {
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.padding(vertical = 6.dp)
			.clip(RoundedCornerShape(14.dp))
			.background(MaterialTheme.colorScheme.surface)
			.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
			.clickable(onClick = onClick)
			.padding(14.dp),
	) {
		Box(
			contentAlignment = Alignment.Center,
			modifier = Modifier
				.size(46.dp)
				.clip(RoundedCornerShape(12.dp))
				.background(accent.copy(alpha = 0.2f)),
		) {
			Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(24.dp))
		}
		Spacer(Modifier.width(14.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(title, fontWeight = FontWeight.SemiBold, fontSize = 15.5.sp)
			Spacer(Modifier.height(2.dp))
			Text(subtitle, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
		}
		Icon(Icons.Default.ChevronRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
	}
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun BlocklistsSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
	onImportLocalTxt: () -> Unit,
) {
	val allLists by vm.blocklists.collectAsState()
	val stats by vm.engineStats.collectAsState()
	val cfg by vm.config.collectAsState()
	val ghRepos by vm.githubRepos.collectAsState()
	val isGhLoading by vm.isGithubLoading.collectAsState()
	val repoFiles by vm.repoFiles.collectAsState()
	val isRepoFilesLoading by vm.isRepoFilesLoading.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var tabIdx by remember { mutableIntStateOf(0) }
	var isAddDialogOpen by remember { mutableStateOf(false) }
	var catalogSearch by remember { mutableStateOf("") }
	var ghQuery by remember { mutableStateOf("") }
	var selectedRepo by remember { mutableStateOf<GitHubRepoItem?>(null) }
	var customHoursText by remember(cfg.autoUpdateIntervalHours) {
		mutableStateOf(cfg.autoUpdateIntervalHours.toString())
	}

	LaunchedEffect(tabIdx) {
		if (tabIdx == 2 && ghRepos.isEmpty())
			vm.searchGitHubLists("")
	}

	val shownCatalog = remember(allLists, tabIdx, catalogSearch) {
		val base = if (tabIdx == 0) allLists.filter { it.isEnabled } else allLists
		if (catalogSearch.isBlank()) {
			base
		} else {
			base.filter {
				it.title.contains(catalogSearch, ignoreCase = true) ||
					it.category.contains(catalogSearch, ignoreCase = true) ||
					it.desc.contains(catalogSearch, ignoreCase = true)
			}
		}
	}

	Column(modifier = Modifier.fillMaxSize()) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("Blocklists", fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
			IconButton(onClick = { isAddDialogOpen = true }) {
				Icon(Icons.Default.Link, contentDescription = "Add Direct URL")
			}
			IconButton(onClick = onImportLocalTxt) {
				Icon(Icons.Default.FileUpload, contentDescription = "Import local file")
			}
			IconButton(
				onClick = {
					if (stats.isSyncing)
						vm.cancelSync()
					else
						vm.refreshAllBlocklists()
				},
			) {
				if (stats.isSyncing) {
					Icon(Icons.Default.Stop, contentDescription = "Stop sync", tint = ShieldRed)
				} else {
					Icon(Icons.Default.Refresh, contentDescription = "Sync all")
				}
			}
		}

		TabRow(
			selectedTabIndex = tabIdx,
			containerColor = Color.Transparent,
			contentColor = accent,
			indicator = { pos ->
				TabRowDefaults.SecondaryIndicator(Modifier.tabIndicatorOffset(pos[tabIdx]), color = accent)
			},
		) {
			Tab(selected = tabIdx == 0, onClick = { tabIdx = 0 }, text = { Text("ACTIVE", fontSize = 12.sp, maxLines = 1) })
			Tab(selected = tabIdx == 1, onClick = { tabIdx = 1 }, text = { Text("CATALOG (${allLists.size})", fontSize = 12.sp, maxLines = 1) })
			Tab(selected = tabIdx == 2, onClick = { tabIdx = 2 }, text = { Text("GITHUB", fontSize = 12.sp, maxLines = 1) })
			Tab(selected = tabIdx == 3, onClick = { tabIdx = 3 }, text = { Text("AUTO-SYNC", fontSize = 12.sp, maxLines = 1) })
		}

		when (tabIdx) {
			0, 1 -> {
				Row(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalAlignment = Alignment.CenterVertically,
					modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
				) {
					OutlinedTextField(
						value = catalogSearch,
						onValueChange = { catalogSearch = it },
						placeholder = { Text("Filter lists...", fontSize = 13.sp) },
						singleLine = true,
						leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
						modifier = Modifier.weight(1f),
					)
					Button(onClick = { isAddDialogOpen = true }) {
						Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
						Spacer(Modifier.width(4.dp))
						Text("URL", maxLines = 1)
					}
				}

				LazyColumn(
					modifier = Modifier.fillMaxSize(),
					contentPadding = PaddingValues(bottom = 20.dp),
				) {
					items(shownCatalog, key = { it.id }) { item ->
						BlocklistRow(
							item = item,
							isSyncingThis = stats.isSyncing && stats.syncingListId == item.id,
							onToggle = { vm.toggleBlocklist(item) },
							onRefresh = { vm.refreshSingleBlocklist(item) },
							onDelete = if (item.category.startsWith("Custom")) ({ vm.deleteCustomBlocklist(item) }) else null,
						)
						HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
					}
				}
			}

			2 -> {
				Column(modifier = Modifier.fillMaxSize()) {
					Row(
						verticalAlignment = Alignment.CenterVertically,
						horizontalArrangement = Arrangement.spacedBy(8.dp),
						modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
					) {
						OutlinedTextField(
							value = ghQuery,
							onValueChange = { ghQuery = it },
							placeholder = { Text("Search GitHub blocklists (e.g. ads, privacy, telemetry)...", fontSize = 12.5.sp) },
							singleLine = true,
							modifier = Modifier.weight(1f),
						)
						Button(
							enabled = !isGhLoading,
							onClick = { vm.searchGitHubLists(ghQuery) },
						) {
							Text("Search", maxLines = 1)
						}
					}

					if (isGhLoading) {
						Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
							CircularProgressIndicator()
						}
					} else {
						LazyColumn(
							modifier = Modifier.fillMaxSize(),
							contentPadding = PaddingValues(bottom = 20.dp),
						) {
							items(ghRepos, key = { it.fullName }) { repo ->
								Row(
									verticalAlignment = Alignment.CenterVertically,
									modifier = Modifier
										.fillMaxWidth()
										.clickable {
											selectedRepo = repo
											vm.inspectGitHubRepoFiles(repo)
										}
										.padding(horizontal = 16.dp, vertical = 12.dp),
								) {
									Column(modifier = Modifier.weight(1f)) {
										Text(repo.fullName, fontWeight = FontWeight.SemiBold, fontSize = 14.5.sp, color = accent)
										if (repo.description.isNotEmpty()) {
											Text(
												text = repo.description,
												fontSize = 12.sp,
												color = MaterialTheme.colorScheme.onSurfaceVariant,
												maxLines = 2,
												overflow = TextOverflow.Ellipsis,
											)
										}
										Text(
											text = "★ ${repo.stars} stars • branch: ${repo.defaultBranch} • tap to browse filter files",
											fontSize = 11.sp,
											color = MaterialTheme.colorScheme.onSurfaceVariant,
										)
									}
									Icon(Icons.Default.ChevronRight, contentDescription = null)
								}
								HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
							}
						}
					}
				}
			}

			3 -> {
				Column(
					modifier = Modifier
						.fillMaxSize()
						.verticalScroll(rememberScrollState())
						.padding(16.dp),
				) {
					SettingSwitchCard(
						title = "Automatic Blocklist Updates",
						subtitle = "Periodically fetch & recompile enabled remote dictionaries in the background",
						isChecked = cfg.isAutoUpdateLists,
						onToggle = { v -> vm.prefs.update { it.copy(isAutoUpdateLists = v) } },
					)

					Spacer(Modifier.height(14.dp))
					Text("Update Check Interval", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = accent)
					Spacer(Modifier.height(8.dp))

					FlowRow(
						horizontalArrangement = Arrangement.spacedBy(8.dp),
						verticalArrangement = Arrangement.spacedBy(6.dp),
					) {
						for ((hrs, label) in listOf(6 to "Every 6h", 12 to "Every 12h", 24 to "Daily (24h)", 48 to "Every 48h", 168 to "Weekly")) {
							FilterChip(
								selected = cfg.autoUpdateIntervalHours == hrs,
								onClick = {
									customHoursText = hrs.toString()
									vm.prefs.update { it.copy(autoUpdateIntervalHours = hrs) }
								},
								label = { Text(label, maxLines = 1, softWrap = false) },
							)
						}
					}

					Spacer(Modifier.height(10.dp))
					Row(
						verticalAlignment = Alignment.CenterVertically,
						horizontalArrangement = Arrangement.spacedBy(10.dp),
					) {
						OutlinedTextField(
							value = customHoursText,
							onValueChange = { txt ->
								val digits = txt.filter { it.isDigit() }.take(3)
								customHoursText = digits
								val parsed = digits.toIntOrNull()
								if (parsed != null && parsed in 1..720)
									vm.prefs.update { it.copy(autoUpdateIntervalHours = parsed) }
							},
							label = { Text("Custom timer (hours, 1–720)") },
							singleLine = true,
							modifier = Modifier.weight(1f),
						)
						Button(
							onClick = {
								if (stats.isSyncing)
									vm.cancelSync()
								else
									vm.refreshAllBlocklists()
							},
						) {
							Icon(
								imageVector = if (stats.isSyncing) Icons.Default.Stop else Icons.Default.Schedule,
								contentDescription = null,
								modifier = Modifier.size(18.dp),
							)
							Spacer(Modifier.width(6.dp))
							Text(if (stats.isSyncing) "Stop" else "Sync Now")
						}
					}

					Spacer(Modifier.height(14.dp))
					val lastStr = if (cfg.lastAutoSyncMs > 0L) {
						SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(cfg.lastAutoSyncMs))
					} else {
						"Pending initial sync"
					}
					Text(
						text = "Last sync check: $lastStr  •  Current timer: every ${cfg.autoUpdateIntervalHours} hour(s)",
						fontSize = 12.sp,
						color = MaterialTheme.colorScheme.onSurfaceVariant,
					)
				}
			}
		}
	}

	if (isAddDialogOpen) {
		AddBlocklistUrlDialog(
			onDismiss = { isAddDialogOpen = false },
			onAdd = { title, url ->
				vm.addCustomUrlBlocklist(title, url)
				isAddDialogOpen = false
			},
		)
	}

	selectedRepo?.let { repo ->
		AlertDialog(
			onDismissRequest = {
				selectedRepo = null
				vm.clearInspectedRepoFiles()
			},
			containerColor = MaterialTheme.colorScheme.surface,
			title = { Text(repo.fullName, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
			text = {
				if (isRepoFilesLoading) {
					Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxWidth().height(140.dp)) {
						CircularProgressIndicator()
					}
				} else if (repoFiles.isEmpty()) {
					Text("No plain .txt / hosts filter files found in root tree.", fontSize = 13.sp)
				} else {
					LazyColumn(modifier = Modifier.height(320.dp)) {
						items(repoFiles, key = { it.path }) { f ->
							Row(
								verticalAlignment = Alignment.CenterVertically,
								modifier = Modifier
									.fillMaxWidth()
									.clickable {
										vm.addCustomUrlBlocklist("${repo.fullName.substringAfter('/')}/${f.name}", f.rawUrl)
										selectedRepo = null
										vm.clearInspectedRepoFiles()
										tabIdx = 0
									}
									.padding(vertical = 8.dp),
							) {
								Column(modifier = Modifier.weight(1f)) {
									Text(f.path, fontSize = 13.sp, fontWeight = FontWeight.Medium)
									Text("${f.sizeBytes / 1024} KB • tap to download & enable", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
								}
								Icon(Icons.Default.Add, contentDescription = "Add", tint = accent)
							}
							HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
						}
					}
				}
			},
			confirmButton = {
				TextButton(onClick = {
					selectedRepo = null
					vm.clearInspectedRepoFiles()
				}) {
					Text("Close")
				}
			},
		)
	}
}

@Composable
private fun BlocklistRow(
	item: BlocklistSource,
	isSyncingThis: Boolean,
	onToggle: () -> Unit,
	onRefresh: () -> Unit,
	onDelete: (() -> Unit)?,
) {
	val accent = MaterialTheme.colorScheme.primary
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.clickable(onClick = onToggle)
			.padding(horizontal = 14.dp, vertical = 10.dp),
	) {
		Box(
			contentAlignment = Alignment.Center,
			modifier = Modifier
				.size(40.dp)
				.clip(RoundedCornerShape(10.dp))
				.background(accent.copy(alpha = 0.16f)),
		) {
			if (isSyncingThis) {
				CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
			} else {
				Text(
					text = item.title.take(2).uppercase(),
					fontWeight = FontWeight.Bold,
					fontSize = 13.sp,
					color = accent,
				)
			}
		}
		Spacer(Modifier.width(12.dp))
		Column(modifier = Modifier.weight(1f)) {
			Row(verticalAlignment = Alignment.CenterVertically) {
				Text(item.title, fontWeight = FontWeight.SemiBold, fontSize = 14.5.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
				Spacer(Modifier.width(6.dp))
				Text(
					text = item.category,
					fontSize = 10.sp,
					color = accent,
					maxLines = 1,
					modifier = Modifier
						.clip(RoundedCornerShape(4.dp))
						.background(accent.copy(alpha = 0.14f))
						.padding(horizontal = 5.dp, vertical = 1.dp),
				)
			}
			Text(
				text = item.desc,
				fontSize = 11.5.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				maxLines = 2,
				overflow = TextOverflow.Ellipsis,
			)
			val meta = when {
				item.lastError.isNotEmpty() -> "Error: ${item.lastError}"
				item.lastUpdated > 0L -> {
					val domCnt = NumberFormat.getIntegerInstance(Locale.US).format(item.ruleCount)
					val rtCnt = NumberFormat.getIntegerInstance(Locale.US).format(item.routeRuleCount)
					"$domCnt domains • $rtCnt routes • ${formatRelativeTime(item.lastUpdated)}"
				}
				else -> "Tap or switch on to download & activate"
			}
			Text(
				text = meta,
				fontSize = 11.sp,
				color = if (item.lastError.isNotEmpty()) ShieldRed else MaterialTheme.colorScheme.onSurfaceVariant,
			)
		}
		if (item.isEnabled && !isSyncingThis && item.url.startsWith("https://", ignoreCase = true)) {
			IconButton(onClick = onRefresh) {
				Icon(Icons.Default.Refresh, contentDescription = "Update list", tint = accent)
			}
		}
		if (onDelete != null) {
			IconButton(onClick = onDelete) {
				Icon(Icons.Default.DeleteOutline, contentDescription = "Delete", tint = ShieldRed)
			}
		}
		Switch(checked = item.isEnabled, onCheckedChange = { onToggle() })
	}
}

@Composable
private fun AddBlocklistUrlDialog(
	onDismiss: () -> Unit,
	onAdd: (String, String) -> Unit,
) {
	var title by remember { mutableStateOf("") }
	var url by remember { mutableStateOf("https://") }
	val trimmedUrl = url.trim()
	val isHttpCleartext = trimmedUrl.startsWith("http://", ignoreCase = true)
	val isValidHttps = trimmedUrl.startsWith("https://", ignoreCase = true) && trimmedUrl.length > 10

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("Add Custom List by Direct URL") },
		text = {
			Column {
				OutlinedTextField(
					value = title,
					onValueChange = { title = it },
					label = { Text("Custom Name (optional)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(10.dp))
				OutlinedTextField(
					value = url,
					onValueChange = { url = it },
					isError = isHttpCleartext,
					supportingText = if (isHttpCleartext) {
						{ Text("Only HTTPS URLs are permitted for remote filter lists", color = ShieldRed, fontSize = 11.sp) }
					} else {
						null
					},
					label = { Text("Direct HTTPS URL (raw GitHub / hosts / Adblock .txt)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
			}
		},
		confirmButton = {
			TextButton(
				enabled = isValidHttps,
				onClick = { onAdd(title, trimmedUrl) },
			) {
				Text("Download & Enable")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) { Text("Cancel") }
		},
	)
}

@Composable
private fun CustomRulesSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
) {
	val rf by vm.ruleFilter.collectAsState()
	val pagedRules = vm.pagedCustomRules.collectAsLazyPagingItems()
	val accent = MaterialTheme.colorScheme.primary

	var editingRule by remember { mutableStateOf<CustomRule?>(null) }
	var isCreatingNew by remember { mutableStateOf(false) }

	Scaffold(
		containerColor = Color.Transparent,
		contentWindowInsets = WindowInsets(0, 0, 0, 0),
		floatingActionButton = {
			FloatingActionButton(
				onClick = { isCreatingNew = true },
				containerColor = accent,
				contentColor = MaterialTheme.colorScheme.onPrimary,
			) {
				Icon(Icons.Default.Add, contentDescription = "Add custom rule")
			}
		},
	) { innerPad ->
		Column(
			modifier = Modifier
				.fillMaxSize()
				.padding(innerPad),
		) {
			Row(
				verticalAlignment = Alignment.CenterVertically,
				modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
			) {
				IconButton(onClick = onBack) {
					Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
				}
				Text("Custom Rules Editor", fontSize = 19.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
				IconButton(onClick = { isCreatingNew = true }) {
					Icon(Icons.Default.Add, contentDescription = "New Rule")
				}
			}

			OutlinedTextField(
				value = rf.query,
				onValueChange = { q -> vm.updateRuleFilter { it.copy(query = q) } },
				placeholder = { Text("Search custom rules or notes...") },
				singleLine = true,
				leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
				trailingIcon = {
					if (rf.query.isNotEmpty()) {
						IconButton(onClick = { vm.updateRuleFilter { it.copy(query = "") } }) {
							Icon(Icons.Default.Close, contentDescription = "Clear")
						}
					}
				},
				modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
			)

			TabRow(
				selectedTabIndex = rf.tabIndex,
				containerColor = Color.Transparent,
				contentColor = accent,
				indicator = { pos ->
					TabRowDefaults.SecondaryIndicator(Modifier.tabIndicatorOffset(pos[rf.tabIndex]), color = accent)
				},
			) {
				Tab(
					selected = rf.tabIndex == 0,
					onClick = { vm.updateRuleFilter { it.copy(tabIndex = 0) } },
					text = { Text("ALL", fontSize = 12.sp) },
				)
				Tab(
					selected = rf.tabIndex == 1,
					onClick = { vm.updateRuleFilter { it.copy(tabIndex = 1) } },
					text = { Text("BLOCKED", fontSize = 12.sp) },
				)
				Tab(
					selected = rf.tabIndex == 2,
					onClick = { vm.updateRuleFilter { it.copy(tabIndex = 2) } },
					text = { Text("ALLOWED", fontSize = 12.sp) },
				)
				Tab(
					selected = rf.tabIndex == 3,
					onClick = { vm.updateRuleFilter { it.copy(tabIndex = 3) } },
					text = { Text("ROUTES", fontSize = 12.sp) },
				)
			}

			if (pagedRules.itemCount == 0) {
				Box(
					contentAlignment = Alignment.Center,
					modifier = Modifier.fillMaxSize().padding(32.dp),
				) {
					Text(
						text = "No custom rules found. Tap + to create Exact, Wildcard, Regex, or URL Route rules.",
						color = MaterialTheme.colorScheme.onSurfaceVariant,
						fontSize = 14.sp,
					)
				}
			} else {
				LazyColumn(
					modifier = Modifier.fillMaxSize(),
					contentPadding = PaddingValues(bottom = 84.dp),
				) {
					items(
						count = pagedRules.itemCount,
						key = { idx -> pagedRules.peek(idx)?.id ?: (-idx.toLong()) },
						contentType = { "custom_rule" },
					) { idx ->
						val rule = pagedRules[idx] ?: return@items
						CustomRuleRow(
							rule = rule,
							onEdit = { editingRule = rule },
							onToggle = { vm.toggleCustomRuleEnabled(rule) },
							onDelete = { vm.deleteCustomRule(rule.id) },
						)
						HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
					}
				}
			}
		}
	}

	if (isCreatingNew) {
		RuleEditorDialog(
			initialRule = null,
			prefillPattern = if (rf.tabIndex == 3) "example.com/ad*" else "",
			prefillIsAllow = rf.tabIndex == 2,
			onDismiss = { isCreatingNew = false },
			onSave = { r ->
				vm.saveCustomRule(r)
				isCreatingNew = false
			},
		)
	}

	editingRule?.let { existing ->
		RuleEditorDialog(
			initialRule = existing,
			onDismiss = { editingRule = null },
			onSave = { updated ->
				vm.saveCustomRule(updated)
				editingRule = null
			},
		)
	}
}

@Composable
private fun CustomRuleRow(
	rule: CustomRule,
	onEdit: () -> Unit,
	onToggle: () -> Unit,
	onDelete: () -> Unit,
) {
	val modeLabel = when (rule.matchMode) {
		MODE_WILDCARD -> "WILDCARD"
		MODE_REGEX -> "REGEX"
		else -> "EXACT"
	}

	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.clickable(onClick = onEdit)
			.padding(horizontal = 12.dp, vertical = 8.dp),
	) {
		Icon(
			imageVector = if (rule.isAllow) Icons.Default.Shield else Icons.Default.Block,
			contentDescription = null,
			tint = if (rule.isAllow) ShieldGreen else ShieldRed,
			modifier = Modifier.size(22.dp),
		)
		Spacer(Modifier.width(10.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(
				text = rule.pattern,
				fontWeight = FontWeight.Medium,
				fontSize = 13.5.sp,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
			val sub = buildString {
				append(if (rule.isAllow) "ALLOW • " else "BLOCK • ")
				append(modeLabel)
				if (rule.isRoute)
					append(" • ROUTE")
				if (rule.note.isNotBlank())
					append(" • ").append(rule.note)
			}
			Text(
				text = sub,
				fontSize = 11.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				maxLines = 1,
				overflow = TextOverflow.Ellipsis,
			)
		}
		IconButton(onClick = onEdit) {
			Icon(Icons.Default.Edit, contentDescription = "Edit", modifier = Modifier.size(19.dp))
		}
		Switch(checked = rule.isEnabled, onCheckedChange = { onToggle() })
		IconButton(onClick = onDelete) {
			Icon(Icons.Default.DeleteOutline, contentDescription = "Remove", tint = ShieldRed, modifier = Modifier.size(20.dp))
		}
	}
}

@Composable
private fun HttpsSetupSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
	onSaveCaFile: () -> Unit,
	onOpenSystemSecuritySettings: () -> Unit,
) {
	val cfg by vm.config.collectAsState()
	val ca by vm.caStatus.collectAsState()
	val accent = MaterialTheme.colorScheme.primary
	var pinnedHosts by remember { mutableStateOf(AdBlockVpnService.instance?.pinnedHosts() ?: emptySet()) }

	val lifecycleOwner = LocalLifecycleOwner.current
	DisposableEffect(lifecycleOwner) {
		val obs = LifecycleEventObserver { _, event ->
			if (event == Lifecycle.Event.ON_RESUME) {
				vm.ca.refreshInstallState()
				pinnedHosts = AdBlockVpnService.instance?.pinnedHosts() ?: emptySet()
			}
		}
		lifecycleOwner.lifecycle.addObserver(obs)
		onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
	}

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState()),
	) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("HTTPS & Route Filtering", fontSize = 20.sp, fontWeight = FontWeight.Bold)
		}

		Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
			SettingSwitchCard(
				title = "Enable HTTPS & URL Route Filtering",
				subtitle = "Decrypts HTTPS for selected browser apps to block routes (e.g. xxx.com/ad) with uBlock noop stubs & WebSocket termination",
				isChecked = cfg.isHttpsFiltering,
				onToggle = { enabled ->
					if (enabled && !ca.isReady)
						vm.generateCa()
					vm.prefs.update { it.copy(isHttpsFiltering = enabled) }
				},
			)

			Spacer(Modifier.height(10.dp))

			SettingSwitchCard(
				title = "Strip DNS HTTPS/SVCB Hints (Block QUIC Bypass)",
				subtitle = "Returns NODATA for DNS type 64/65 so browsers route HTTPS over HTTP/1.1 proxy instead of UDP QUIC",
				isChecked = cfg.isStripHttpsDnsRecord,
				onToggle = { enabled ->
					vm.prefs.update { it.copy(isStripHttpsDnsRecord = enabled) }
				},
			)

			Spacer(Modifier.height(16.dp))

			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(14.dp))
					.background(MaterialTheme.colorScheme.surface)
					.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
					.padding(16.dp),
			) {
				Text("Local Root CA Certificate", fontWeight = FontWeight.Bold, fontSize = 16.sp)
				Spacer(Modifier.height(6.dp))
				if (ca.isReady) {
					Text(
						text = if (ca.isInstalledInSystem) {
							"Android User CA Store: INSTALLED & TRUSTED BY CHROME"
						} else {
							"Android User CA Store: NOT INSTALLED (or regenerated — reinstall .crt)"
						},
						color = if (ca.isInstalledInSystem) ShieldGreen else ShieldRed,
						fontSize = 12.5.sp,
						fontWeight = FontWeight.Bold,
					)
					val exp = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(ca.validUntilMillis))
					Text("Valid until: $exp", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
					Text("SHA-256: ${ca.sha256Fingerprint}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
				} else {
					Text("Status: Not generated yet", color = ShieldRed, fontSize = 13.sp)
				}

				Spacer(Modifier.height(12.dp))
				Text(
					text = "Manual install steps (Android 11–17 forbids one-click app CA install):\n1. Tap '1. Generate / Reset CA' (only once), then '2. Save .crt File'.\n2. Tap '3. Open Security Settings' -> More security & privacy -> Encryption & credentials -> Install a certificate -> CA certificate (NOT VPN/user cert!).\n3. Tap 'Install anyway' and select TrueBlock-Root-CA.crt.\n4. In Chrome Settings -> Privacy & security -> turn OFF 'Use secure DNS' if Chrome bypasses local DNS.",
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)

				Spacer(Modifier.height(14.dp))
				Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
					OutlinedButton(onClick = { vm.generateCa() }) {
						Text(if (ca.isReady) "1. Regenerate CA" else "1. Generate CA")
					}
					if (ca.isReady) {
						Button(onClick = onSaveCaFile) {
							Text("2. Save .crt File")
						}
					}
				}
				if (ca.isReady) {
					Spacer(Modifier.height(8.dp))
					Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
						Button(onClick = onOpenSystemSecuritySettings) {
							Text("3. Open Security Settings")
						}
						OutlinedButton(onClick = { vm.ca.refreshInstallState() }) {
							Text("Re-check Store")
						}
					}
				}
			}

			Spacer(Modifier.height(16.dp))

			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(14.dp))
					.background(MaterialTheme.colorScheme.surface)
					.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))
					.padding(16.dp),
			) {
				Text("SSL-Pinned Auto-Bypass Cache", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
				Text(
					text = "${pinnedHosts.size} hosts bypassed automatically after TLS handshake rejection",
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
				if (pinnedHosts.isNotEmpty()) {
					Spacer(Modifier.height(8.dp))
					Text(
						text = pinnedHosts.take(15).joinToString(", "),
						fontSize = 11.sp,
						color = accent,
					)
					Spacer(Modifier.height(8.dp))
					OutlinedButton(onClick = {
						AdBlockVpnService.instance?.clearPinnedHosts()
						pinnedHosts = emptySet()
					}) {
						Text("Clear Pinned Cache")
					}
				}
			}
		}
	}
}

@Composable
private fun AppsSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
	onOpenProxies: () -> Unit,
) {
	LaunchedEffect(Unit) {
		vm.loadInstalledAppsIfNeeded()
	}

	val apps by vm.installedApps.collectAsState()
	val installedSet by vm.installedPkgSet.collectAsState()
	val isLoading by vm.isAppsLoading.collectAsState()
	val cfg by vm.config.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var tabIdx by remember { mutableIntStateOf(0) }
	var query by remember { mutableStateOf("") }
	var filterMode by remember { mutableIntStateOf(0) }

	val proxiedAppSet = remember(cfg.proxies) {
		val s = HashSet<String>()
		for (p in cfg.proxies) {
			if (p.isEnabled && !p.isAllApps)
				s.addAll(p.appPackages)
		}
		s
	}

	val bypassedCnt = remember(cfg.bypassedApps, installedSet) {
		if (installedSet.isEmpty()) cfg.bypassedApps.size else cfg.bypassedApps.count { installedSet.contains(it) }
	}
	val httpsCnt = remember(cfg.httpsInspectedApps, installedSet) {
		if (installedSet.isEmpty()) cfg.httpsInspectedApps.size else cfg.httpsInspectedApps.count { installedSet.contains(it) }
	}
	val fwCnt = remember(cfg.firewallWifiApps, cfg.firewallMobileApps, installedSet) {
		val union = cfg.firewallWifiApps + cfg.firewallMobileApps
		if (installedSet.isEmpty()) union.size else union.count { installedSet.contains(it) }
	}
	val proxyCnt = remember(proxiedAppSet, installedSet) {
		if (installedSet.isEmpty()) proxiedAppSet.size else proxiedAppSet.count { installedSet.contains(it) }
	}

	val filtered = remember(
		apps,
		tabIdx,
		query,
		filterMode,
		cfg.bypassedApps,
		cfg.httpsInspectedApps,
		cfg.firewallWifiApps,
		cfg.firewallMobileApps,
		proxiedAppSet,
	) {
		apps.filter { a ->
			val tabMatch = if (tabIdx == 0) !a.isSystem else a.isSystem
			val qMatch = query.isBlank() ||
				a.label.contains(query, ignoreCase = true) ||
				a.packageName.contains(query, ignoreCase = true)
			val fMatch = when (filterMode) {
				1 -> cfg.bypassedApps.contains(a.packageName)
				2 -> cfg.httpsInspectedApps.contains(a.packageName)
				3 -> cfg.firewallWifiApps.contains(a.packageName) || cfg.firewallMobileApps.contains(a.packageName)
				4 -> proxiedAppSet.contains(a.packageName)
				else -> true
			}
			tabMatch && qMatch && fMatch
		}
	}

	Column(modifier = Modifier.fillMaxSize()) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("Apps & Firewall", fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
			TextButton(onClick = onOpenProxies) {
				Text("Proxies", fontSize = 12.5.sp)
			}
		}

		OutlinedTextField(
			value = query,
			onValueChange = { query = it },
			placeholder = { Text("Search installed or system apps...") },
			leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
			singleLine = true,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
		)

		Row(
			horizontalArrangement = Arrangement.spacedBy(8.dp),
			modifier = Modifier
				.horizontalScroll(rememberScrollState())
				.padding(horizontal = 16.dp, vertical = 4.dp),
		) {
			FilterChip(
				selected = filterMode == 0,
				onClick = { filterMode = 0 },
				label = { Text("All (${apps.size})", maxLines = 1, softWrap = false) },
			)
			FilterChip(
				selected = filterMode == 1,
				onClick = { filterMode = 1 },
				label = { Text("Bypass ($bypassedCnt)", maxLines = 1, softWrap = false) },
			)
			FilterChip(
				selected = filterMode == 2,
				onClick = { filterMode = 2 },
				label = { Text("HTTPS ($httpsCnt)", maxLines = 1, softWrap = false) },
			)
			FilterChip(
				selected = filterMode == 3,
				onClick = { filterMode = 3 },
				label = { Text("Firewall ($fwCnt)", maxLines = 1, softWrap = false) },
			)
			FilterChip(
				selected = filterMode == 4,
				onClick = { filterMode = 4 },
				label = { Text("Proxy ($proxyCnt)", maxLines = 1, softWrap = false) },
			)
		}

		TabRow(
			selectedTabIndex = tabIdx,
			containerColor = Color.Transparent,
			contentColor = accent,
			indicator = { pos ->
				TabRowDefaults.SecondaryIndicator(Modifier.tabIndicatorOffset(pos[tabIdx]), color = accent)
			},
		) {
			Tab(selected = tabIdx == 0, onClick = { tabIdx = 0 }, text = { Text("INSTALLED") })
			Tab(selected = tabIdx == 1, onClick = { tabIdx = 1 }, text = { Text("SYSTEM") })
		}

		if (isLoading) {
			Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
				CircularProgressIndicator()
			}
		} else {
			LazyColumn(modifier = Modifier.fillMaxSize()) {
				items(filtered, key = { it.packageName }, contentType = { "app_row" }) { appItem ->
					val isBypassed = cfg.bypassedApps.contains(appItem.packageName)
					val isHttps = cfg.httpsInspectedApps.contains(appItem.packageName)
					val isFwWifi = cfg.firewallWifiApps.contains(appItem.packageName)
					val isFwMob = cfg.firewallMobileApps.contains(appItem.packageName)
					val isProxied = proxiedAppSet.contains(appItem.packageName)
					val iconBmp by produceState<ImageBitmap?>(initialValue = null, key1 = appItem.packageName) {
						value = vm.getAppIcon(appItem.packageName)
					}

					Column(
						modifier = Modifier
							.fillMaxWidth()
							.padding(horizontal = 14.dp, vertical = 8.dp),
					) {
						Row(verticalAlignment = Alignment.CenterVertically) {
							val bmp = iconBmp
							if (bmp != null) {
								Image(
									bitmap = bmp,
									contentDescription = null,
									modifier = Modifier.size(34.dp).clip(RoundedCornerShape(8.dp)),
								)
							} else {
								Box(
									modifier = Modifier
										.size(34.dp)
										.clip(RoundedCornerShape(8.dp))
										.background(MaterialTheme.colorScheme.surface),
								)
							}
							Spacer(Modifier.width(10.dp))
							Column(modifier = Modifier.weight(1f)) {
								Text(appItem.label, fontWeight = FontWeight.Medium, fontSize = 13.5.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
								Text(appItem.packageName, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
							}
						}

						Spacer(Modifier.height(6.dp))
						Row(
							horizontalArrangement = Arrangement.spacedBy(6.dp),
							modifier = Modifier.horizontalScroll(rememberScrollState()),
						) {
							AppPolicyPill(
								label = "Bypass",
								isActive = isBypassed,
								activeColor = accent,
								onClick = { vm.toggleAppBypass(appItem.packageName) },
							)
							AppPolicyPill(
								label = "HTTPS",
								isActive = isHttps,
								activeColor = ShieldGreen,
								onClick = { vm.toggleAppHttpsInspect(appItem.packageName) },
							)
							AppPolicyPill(
								label = "FW Wi-Fi",
								isActive = isFwWifi,
								activeColor = ShieldRed,
								onClick = { vm.toggleAppFirewallWifi(appItem.packageName) },
							)
							AppPolicyPill(
								label = "FW Mobile",
								isActive = isFwMob,
								activeColor = ShieldRed,
								onClick = { vm.toggleAppFirewallMobile(appItem.packageName) },
							)
							AppPolicyPill(
								label = "Proxy",
								isActive = isProxied,
								activeColor = accent,
								onClick = {
									if (!vm.toggleAppInPrimaryProxy(appItem.packageName))
										onOpenProxies()
								},
							)
						}
					}
					HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
				}
			}
		}
	}
}

@Composable
private fun AppPolicyPill(
	label: String,
	isActive: Boolean,
	activeColor: Color,
	onClick: () -> Unit,
) {
	val bg = if (isActive) activeColor.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surface
	val borderCol = if (isActive) activeColor else MaterialTheme.colorScheme.outline
	val txtCol = if (isActive) activeColor else MaterialTheme.colorScheme.onSurfaceVariant

	Box(
		modifier = Modifier
			.clip(RoundedCornerShape(8.dp))
			.background(bg)
			.border(1.dp, borderCol, RoundedCornerShape(8.dp))
			.clickable(onClick = onClick)
			.padding(horizontal = 10.dp, vertical = 4.dp),
	) {
		Text(
			text = label,
			fontSize = 11.sp,
			fontWeight = if (isActive) FontWeight.Bold else FontWeight.Medium,
			color = txtCol,
			maxLines = 1,
			softWrap = false,
		)
	}
}

@Composable
private fun NetworksSubView(
	vm: MainViewModel,
	onBack: () -> Unit,
) {
	val cfg by vm.config.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState()),
	) {
		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
		) {
			IconButton(onClick = onBack) {
				Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
			}
			Text("Networks & DNS", fontSize = 20.sp, fontWeight = FontWeight.Bold)
		}

		Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
			Text("Upstream DNS Provider", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = accent)
			Spacer(Modifier.height(8.dp))

			for (preset in DNS_PRESETS) {
				Row(
					verticalAlignment = Alignment.CenterVertically,
					modifier = Modifier
						.fillMaxWidth()
						.padding(vertical = 4.dp)
						.clip(RoundedCornerShape(10.dp))
						.background(MaterialTheme.colorScheme.surface)
						.border(
							width = 1.dp,
							color = if (cfg.dnsPresetKey == preset.key) accent else MaterialTheme.colorScheme.outline,
							shape = RoundedCornerShape(10.dp),
						)
						.clickable { vm.prefs.update { it.copy(dnsPresetKey = preset.key) } }
						.padding(12.dp),
				) {
					Icon(Icons.Default.Dns, contentDescription = null, tint = accent)
					Spacer(Modifier.width(12.dp))
					Column(modifier = Modifier.weight(1f)) {
						Text(preset.name, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
						Text("${preset.primaryIp} • ${preset.dohUrl}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
					}
				}
			}

			Row(
				verticalAlignment = Alignment.CenterVertically,
				modifier = Modifier
					.fillMaxWidth()
					.padding(vertical = 4.dp)
					.clip(RoundedCornerShape(10.dp))
					.background(MaterialTheme.colorScheme.surface)
					.border(
						width = 1.dp,
						color = if (cfg.dnsPresetKey == "custom") accent else MaterialTheme.colorScheme.outline,
						shape = RoundedCornerShape(10.dp),
					)
					.clickable { vm.prefs.update { it.copy(dnsPresetKey = "custom") } }
					.padding(12.dp),
			) {
				Icon(Icons.Default.Dns, contentDescription = null, tint = accent)
				Spacer(Modifier.width(12.dp))
				Text("Custom Upstream DNS / DoH", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
			}

			if (cfg.dnsPresetKey == "custom") {
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = cfg.customDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(customDnsIp = ip) } },
					label = { Text("Primary DNS IPv4 (e.g. 9.9.9.9)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = cfg.customSecondaryDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(customSecondaryDnsIp = ip) } },
					label = { Text("Secondary DNS IPv4 (optional — leave blank for none)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(8.dp))
				OutlinedTextField(
					value = cfg.customDohUrl,
					onValueChange = { u -> vm.prefs.update { it.copy(customDohUrl = u) } },
					label = { Text("Custom DoH Endpoint (https://.../dns-query)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
			}

			Spacer(Modifier.height(10.dp))
			SettingSwitchCard(
				title = "Use Encrypted DNS-over-HTTPS (DoH)",
				subtitle = "Encrypts upstream DNS resolution via HTTPS (RFC 8484)",
				isChecked = cfg.isUseDoh,
				onToggle = { v -> vm.prefs.update { it.copy(isUseDoh = v) } },
			)

			val isAnyDohActive = cfg.isUseDoh ||
				(cfg.isWifiCustomOverride && cfg.isWifiUseDoh) ||
				(cfg.isMobileCustomOverride && cfg.isMobileUseDoh)
			if (isAnyDohActive) {
				Spacer(Modifier.height(6.dp))
				SettingSwitchCard(
					title = "Strict DoH Mode (Never Fall Back to Plain DNS)",
					subtitle = "Blocks unencrypted port 53 fallback if DoH is unreachable. Keep off if captive portals fail to load.",
					isChecked = cfg.isStrictDoh,
					onToggle = { v -> vm.prefs.update { it.copy(isStrictDoh = v) } },
				)
			}

			Spacer(Modifier.height(18.dp))
			Text("Wi-Fi Networks", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = accent)
			Spacer(Modifier.height(6.dp))
			SettingSwitchCard(
				title = "Active Protection on Wi-Fi",
				subtitle = "Automatically keep blocking enabled when connected to Wi-Fi",
				isChecked = cfg.isWifiProtection,
				onToggle = { v -> vm.prefs.update { it.copy(isWifiProtection = v) } },
			)
			Spacer(Modifier.height(6.dp))
			SettingSwitchCard(
				title = "Custom DNS Override on Wi-Fi",
				subtitle = "Use dedicated DNS / DoH servers specifically on Wi-Fi (e.g. home router / Pi-hole)",
				isChecked = cfg.isWifiCustomOverride,
				onToggle = { v -> vm.prefs.update { it.copy(isWifiCustomOverride = v) } },
			)
			if (cfg.isWifiCustomOverride) {
				Spacer(Modifier.height(6.dp))
				OutlinedTextField(
					value = cfg.wifiDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(wifiDnsIp = ip) } },
					label = { Text("Wi-Fi Primary DNS IPv4") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(6.dp))
				OutlinedTextField(
					value = cfg.wifiSecondaryDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(wifiSecondaryDnsIp = ip) } },
					label = { Text("Wi-Fi Secondary DNS IPv4 (optional)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(6.dp))
				SettingSwitchCard(
					title = "Use DoH on Wi-Fi",
					subtitle = "Encrypt DNS over HTTPS while connected to Wi-Fi",
					isChecked = cfg.isWifiUseDoh,
					onToggle = { v -> vm.prefs.update { it.copy(isWifiUseDoh = v) } },
				)
				if (cfg.isWifiUseDoh) {
					Spacer(Modifier.height(6.dp))
					OutlinedTextField(
						value = cfg.wifiDohUrl,
						onValueChange = { u -> vm.prefs.update { it.copy(wifiDohUrl = u) } },
						label = { Text("Wi-Fi DoH URL (optional — blank uses main DoH)") },
						singleLine = true,
						modifier = Modifier.fillMaxWidth(),
					)
				}
			}

			Spacer(Modifier.height(18.dp))
			Text("Mobile Networks", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = accent)
			Spacer(Modifier.height(6.dp))
			SettingSwitchCard(
				title = "Active Protection on Mobile Data",
				subtitle = "Automatically filter traffic on 4G / 5G cellular networks",
				isChecked = cfg.isMobileProtection,
				onToggle = { v -> vm.prefs.update { it.copy(isMobileProtection = v) } },
			)
			Spacer(Modifier.height(6.dp))
			SettingSwitchCard(
				title = "Custom DNS Override on Mobile Data",
				subtitle = "Use dedicated DNS / DoH servers on cellular networks",
				isChecked = cfg.isMobileCustomOverride,
				onToggle = { v -> vm.prefs.update { it.copy(isMobileCustomOverride = v) } },
			)
			if (cfg.isMobileCustomOverride) {
				Spacer(Modifier.height(6.dp))
				OutlinedTextField(
					value = cfg.mobileDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(mobileDnsIp = ip) } },
					label = { Text("Mobile Primary DNS IPv4") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(6.dp))
				OutlinedTextField(
					value = cfg.mobileSecondaryDnsIp,
					onValueChange = { ip -> vm.prefs.update { it.copy(mobileSecondaryDnsIp = ip) } },
					label = { Text("Mobile Secondary DNS IPv4 (optional)") },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)
				Spacer(Modifier.height(6.dp))
				SettingSwitchCard(
					title = "Use DoH on Mobile Data",
					subtitle = "Encrypt DNS over HTTPS on cellular networks",
					isChecked = cfg.isMobileUseDoh,
					onToggle = { v -> vm.prefs.update { it.copy(isMobileUseDoh = v) } },
				)
				if (cfg.isMobileUseDoh) {
					Spacer(Modifier.height(6.dp))
					OutlinedTextField(
						value = cfg.mobileDohUrl,
						onValueChange = { u -> vm.prefs.update { it.copy(mobileDohUrl = u) } },
						label = { Text("Mobile DoH URL (optional — blank uses main DoH)") },
						singleLine = true,
						modifier = Modifier.fillMaxWidth(),
					)
				}
			}

			Spacer(Modifier.height(24.dp))
		}
	}
}

@Composable
fun SettingsScreen(
	vm: MainViewModel,
	onExportBackup: () -> Unit,
	onImportBackup: () -> Unit,
	onOpenEngineConfig: () -> Unit = {},
) {
	val cfg by vm.config.collectAsState()
	val stats by vm.engineStats.collectAsState()
	val accent = MaterialTheme.colorScheme.primary

	var isColorPickerOpen by remember { mutableStateOf(false) }

	Column(
		modifier = Modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState())
			.padding(horizontal = 16.dp, vertical = 12.dp),
	) {
		Text("Settings", fontSize = 24.sp, fontWeight = FontWeight.Bold)
		Spacer(Modifier.height(16.dp))

		Text("Appearance", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = accent)
		Spacer(Modifier.height(8.dp))

		Row(
			verticalAlignment = Alignment.CenterVertically,
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(12.dp))
				.background(MaterialTheme.colorScheme.surface)
				.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
				.clickable { isColorPickerOpen = true }
				.padding(14.dp),
		) {
			Icon(Icons.Default.Palette, contentDescription = null, tint = accent)
			Spacer(Modifier.width(14.dp))
			Column(modifier = Modifier.weight(1f)) {
				Text("Accent Color", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
				Text("#%06X".format(cfg.accentArgb and 0xFFFFFF), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
			}
			Box(
				modifier = Modifier
					.size(28.dp)
					.clip(CircleShape)
					.background(Color(cfg.accentArgb))
					.border(1.5.dp, MaterialTheme.colorScheme.outline, CircleShape),
			)
		}

		Spacer(Modifier.height(8.dp))
		Column(
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(12.dp))
				.background(MaterialTheme.colorScheme.surface)
				.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
				.padding(14.dp),
		) {
			Text("Theme Mode", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
			Text(
				text = "Switch between pure AMOLED black (#000000), dark slate, or light theme",
				fontSize = 12.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
			)
			Spacer(Modifier.height(8.dp))
			Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
				FilterChip(
					selected = cfg.themeMode == THEME_OLED,
					onClick = { vm.prefs.update { it.copy(themeMode = THEME_OLED) } },
					label = { Text("OLED Black", fontSize = 12.sp, maxLines = 1, softWrap = false) },
				)
				FilterChip(
					selected = cfg.themeMode == THEME_DARK,
					onClick = { vm.prefs.update { it.copy(themeMode = THEME_DARK) } },
					label = { Text("Dark", fontSize = 12.sp, maxLines = 1, softWrap = false) },
				)
				FilterChip(
					selected = cfg.themeMode == THEME_LIGHT,
					onClick = { vm.prefs.update { it.copy(themeMode = THEME_LIGHT) } },
					label = { Text("Light", fontSize = 12.sp, maxLines = 1, softWrap = false) },
				)
			}
		}

		Spacer(Modifier.height(18.dp))
		Text("Automation & Database Optimization", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = accent)
		Spacer(Modifier.height(8.dp))

		SettingSwitchCard(
			title = "Start on Device Boot",
			subtitle = "Automatically launch VPN protection after Android restarts (BOOT_COMPLETED)",
			isChecked = cfg.isStartOnBoot,
			onToggle = { v -> vm.prefs.update { it.copy(isStartOnBoot = v) } },
		)
		Spacer(Modifier.height(8.dp))
		SettingSwitchCard(
			title = "Auto-Update Blocklists (Every ${cfg.autoUpdateIntervalHours}h)",
			subtitle = "Configure custom timer or manual sync under Advanced -> Blocklists -> Auto-Sync",
			isChecked = cfg.isAutoUpdateLists,
			onToggle = { v -> vm.prefs.update { it.copy(isAutoUpdateLists = v) } },
		)
		Spacer(Modifier.height(8.dp))
		SettingSwitchCard(
			title = "Record Live Raw Request Stream",
			subtitle = "Keep per-request raw log alongside aggregated domain/route counters",
			isChecked = cfg.isRawLoggingEnabled,
			onToggle = { v -> vm.prefs.update { it.copy(isRawLoggingEnabled = v) } },
		)

		Spacer(Modifier.height(10.dp))
		Column(
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(12.dp))
				.background(MaterialTheme.colorScheme.surface)
				.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
				.padding(14.dp),
		) {
			Text("Aggregated DB Retention Limit", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
			Text(
				text = "Compact (domain/route, count, firstSeen, lastSeen) rows kept locally",
				fontSize = 12.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
			)
			Spacer(Modifier.height(8.dp))
			Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
				for (cap in listOf(100_000, 250_000, 500_000, 1_000_000)) {
					FilterChip(
						selected = cfg.maxAggEntries == cap,
						onClick = { vm.prefs.update { it.copy(maxAggEntries = cap) } },
						label = { Text("${cap / 1000}K", fontSize = 12.sp) },
					)
				}
			}
		}

		Spacer(Modifier.height(10.dp))
		HubCardRow(
			icon = Icons.Default.Tune,
			accent = accent,
			title = "Open Full Live Engine Config",
			subtitle = "Edit VPN IPs, MTU, L3 capture, CNAME uncloaking, \$removeparam, Cosmetic CSS & timeouts",
			onClick = onOpenEngineConfig,
		)

		Spacer(Modifier.height(14.dp))
		Text("Backup & Restore", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = accent)
		Spacer(Modifier.height(8.dp))

		Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
			OutlinedButton(
				onClick = onExportBackup,
				modifier = Modifier.weight(1f),
			) {
				Icon(Icons.Default.FileDownload, contentDescription = null, modifier = Modifier.size(18.dp))
				Spacer(Modifier.width(6.dp))
				Text("Export Backup")
			}
			OutlinedButton(
				onClick = onImportBackup,
				modifier = Modifier.weight(1f),
			) {
				Icon(Icons.Default.FileUpload, contentDescription = null, modifier = Modifier.size(18.dp))
				Spacer(Modifier.width(6.dp))
				Text("Import Backup")
			}
		}

		Spacer(Modifier.height(18.dp))
		Text("About", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = accent)
		Spacer(Modifier.height(8.dp))

		Column(
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(12.dp))
				.background(MaterialTheme.colorScheme.surface)
				.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
				.padding(14.dp),
		) {
			Text("TrueBlock v${BuildConfig.VERSION_NAME}", fontWeight = FontWeight.Bold, fontSize = 15.sp)
			Spacer(Modifier.height(4.dp))
			Text(
				text = "100% local two-tier VPN DNS + CNAME uncloaking + HTTPS/WebSocket route blocker + Cosmetic CSS + \$removeparam cleaner + Per-App SOCKS5/HTTP proxy & firewall.",
				fontSize = 12.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
			)
			Spacer(Modifier.height(6.dp))
			Text(
				text = "Loaded in RAM: ${stats.totalDomainRules} domains • ${stats.totalRouteRules} routes • ${stats.totalCosmeticRules} CSS • ${stats.totalRemoveParamRules} param rules",
				fontSize = 12.sp,
				color = accent,
			)
		}

		Spacer(Modifier.height(24.dp))
	}

	if (isColorPickerOpen) {
		ColorPickerDialog(
			initialArgb = cfg.accentArgb,
			onDismiss = { isColorPickerOpen = false },
			onConfirm = { picked ->
				vm.prefs.update { it.copy(accentArgb = picked) }
				isColorPickerOpen = false
			},
		)
	}
}

@Composable
fun SettingSwitchCard(
	title: String,
	subtitle: String,
	isChecked: Boolean,
	onToggle: (Boolean) -> Unit,
) {
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(12.dp))
			.background(MaterialTheme.colorScheme.surface)
			.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
			.clickable { onToggle(!isChecked) }
			.padding(horizontal = 14.dp, vertical = 12.dp),
	) {
		Column(modifier = Modifier.weight(1f)) {
			Text(title, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
			Spacer(Modifier.height(2.dp))
			Text(subtitle, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
		}
		Spacer(Modifier.width(10.dp))
		Switch(checked = isChecked, onCheckedChange = onToggle)
	}
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun BackupSectionsDialog(
	isImportMode: Boolean,
	inspection: BackupInspection?,
	onDismiss: () -> Unit,
	onConfirm: (BackupSections) -> Unit,
) {
	val isHasGeneral = inspection?.hasGeneralConfig ?: true
	val isHasDns = inspection?.hasDnsAndNetworks ?: true
	val isHasApps = inspection?.hasAppsAndProxies ?: true
	val isHasRules = if (inspection != null) inspection.customRulesCount > 0 else true
	val isHasLists = if (inspection != null) inspection.blocklistsCount > 0 else true

	var isLists by remember(inspection) { mutableStateOf(isHasLists) }
	var isRules by remember(inspection) { mutableStateOf(isHasRules) }
	var isGeneral by remember(inspection) { mutableStateOf(isHasGeneral) }
	var isDns by remember(inspection) { mutableStateOf(isHasDns) }
	var isApps by remember(inspection) { mutableStateOf(isHasApps) }

	val current = BackupSections(
		isGeneralConfig = isGeneral && isHasGeneral,
		isDnsAndNetworks = isDns && isHasDns,
		isAppsAndProxies = isApps && isHasApps,
		isCustomRules = isRules && isHasRules,
		isBlocklists = isLists && isHasLists,
	)

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = {
			Text(
				text = if (isImportMode) "Select Sections to Import" else "Select Sections to Export",
				fontWeight = FontWeight.Bold,
			)
		},
		text = {
			Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
				Text(
					text = if (isImportMode) {
						"Choose whether to restore lists & custom rules, general configuration, or everything:"
					} else {
						"Export everything into one backup or share lists/rules separately from device configuration:"
					},
					fontSize = 12.sp,
					color = MaterialTheme.colorScheme.onSurfaceVariant,
				)
				Spacer(Modifier.height(8.dp))

				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalArrangement = Arrangement.spacedBy(4.dp),
				) {
					FilterChip(
						selected = isLists && isRules && isGeneral && isDns && isApps,
						onClick = {
							isLists = isHasLists
							isRules = isHasRules
							isGeneral = isHasGeneral
							isDns = isHasDns
							isApps = isHasApps
						},
						label = { Text("All", fontSize = 12.sp, maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = (isLists || isRules) && !isGeneral && !isDns && !isApps,
						onClick = {
							isLists = isHasLists
							isRules = isHasRules
							isGeneral = false
							isDns = false
							isApps = false
						},
						label = { Text("Lists & Rules Only", fontSize = 12.sp, maxLines = 1, softWrap = false) },
					)
					FilterChip(
						selected = !isLists && !isRules && (isGeneral || isDns || isApps),
						onClick = {
							isLists = false
							isRules = false
							isGeneral = isHasGeneral
							isDns = isHasDns
							isApps = isHasApps
						},
						label = { Text("Config Only", fontSize = 12.sp, maxLines = 1, softWrap = false) },
					)
				}

				Spacer(Modifier.height(8.dp))
				HorizontalDivider(color = MaterialTheme.colorScheme.outline)
				Spacer(Modifier.height(4.dp))

				BackupSectionCheckRow(
					title = if (inspection != null) "Blocklists (${inspection.blocklistsCount})" else "Blocklists",
					subtitle = "Subscribed & custom remote filter list sources",
					isChecked = isLists && isHasLists,
					isEnabled = isHasLists,
					onToggle = { isLists = it },
				)
				BackupSectionCheckRow(
					title = if (inspection != null) "Custom Rules (${inspection.customRulesCount})" else "Custom Rules",
					subtitle = "Exact, wildcard, regex & URL route rules",
					isChecked = isRules && isHasRules,
					isEnabled = isHasRules,
					onToggle = { isRules = it },
				)
				BackupSectionCheckRow(
					title = "General & Engine Configuration",
					subtitle = "Theme, HTTPS filtering, \$removeparam, Cosmetic CSS & engine tuning",
					isChecked = isGeneral && isHasGeneral,
					isEnabled = isHasGeneral,
					onToggle = { isGeneral = it },
				)
				BackupSectionCheckRow(
					title = "DNS & Network Policies",
					subtitle = "Upstream DNS, DoH, Strict DoH & Wi-Fi / Mobile overrides",
					isChecked = isDns && isHasDns,
					isEnabled = isHasDns,
					onToggle = { isDns = it },
				)
				BackupSectionCheckRow(
					title = if (inspection != null && inspection.proxyCount > 0) {
						"Apps, Firewall & Proxies (${inspection.proxyCount} proxies)"
					} else {
						"Apps, Firewall & Proxies"
					},
					subtitle = "Bypassed apps, HTTPS-inspected apps, firewall & SOCKS5/HTTP proxies",
					isChecked = isApps && isHasApps,
					isEnabled = isHasApps,
					onToggle = { isApps = it },
				)
			}
		},
		confirmButton = {
			Button(
				enabled = current.hasAnySelected,
				onClick = { onConfirm(current) },
			) {
				Text(if (isImportMode) "Import Selected" else "Export Selected")
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) {
				Text("Cancel")
			}
		},
	)
}

@Composable
private fun BackupSectionCheckRow(
	title: String,
	subtitle: String,
	isChecked: Boolean,
	isEnabled: Boolean,
	onToggle: (Boolean) -> Unit,
) {
	Row(
		verticalAlignment = Alignment.CenterVertically,
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.clickable(enabled = isEnabled) { onToggle(!isChecked) }
			.padding(vertical = 6.dp),
	) {
		Checkbox(
			checked = isChecked,
			enabled = isEnabled,
			onCheckedChange = onToggle,
		)
		Spacer(Modifier.width(6.dp))
		Column(modifier = Modifier.weight(1f)) {
			Text(
				text = title,
				fontWeight = FontWeight.SemiBold,
				fontSize = 13.5.sp,
				color = if (isEnabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
			)
			Text(
				text = if (isEnabled) subtitle else "Not present in this backup file",
				fontSize = 11.sp,
				color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (isEnabled) 1f else 0.5f),
			)
		}
	}
}
