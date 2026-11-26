package com.renwixx.trueadblocker

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.PieChart
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.renwixx.trueadblocker.data.BackupSections
import com.renwixx.trueadblocker.data.THEME_LIGHT
import com.renwixx.trueadblocker.net.AdBlockVpnService
import com.renwixx.trueadblocker.ui.ActivityScreen
import com.renwixx.trueadblocker.ui.AdvancedScreen
import com.renwixx.trueadblocker.ui.AdvancedSubScreen
import com.renwixx.trueadblocker.ui.AnalyticsScreen
import com.renwixx.trueadblocker.ui.BackupSectionsDialog
import com.renwixx.trueadblocker.ui.HomeScreen
import com.renwixx.trueadblocker.ui.MainViewModel
import com.renwixx.trueadblocker.ui.SettingsScreen
import com.renwixx.trueadblocker.ui.theme.TrueAdBlockerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
	override fun onCreate(savedInstanceState: Bundle?) {
		enableEdgeToEdge(
			statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
			navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.BLACK),
		)
		super.onCreate(savedInstanceState)

		setContent {
			val vm: MainViewModel = viewModel()
			val cfg by vm.config.collectAsState()
			val vpn by vm.vpnState.collectAsState()
			val stagedImport by vm.stagedImport.collectAsState()
			val scope = rememberCoroutineScope()

			var selectedTab by rememberSaveable { mutableIntStateOf(0) }
			var advancedSub by rememberSaveable { mutableStateOf(AdvancedSubScreen.HUB) }
			var isPendingVpnStart by remember { mutableStateOf(false) }
			var isExportDialogOpen by remember { mutableStateOf(false) }
			var pendingExportSections by remember { mutableStateOf(BackupSections()) }

			LaunchedEffect(vm) {
				vm.toastEvents.collect { msg ->
					if (msg.isNotEmpty())
						Toast.makeText(this@MainActivity, msg, Toast.LENGTH_SHORT).show()
				}
			}

			val vpnPrepareLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.StartActivityForResult()
			) { res ->
				if (res.resultCode == RESULT_OK)
					AdBlockVpnService.start(this@MainActivity)
				else
					vm.postMessage("VPN permission denied")
			}

			fun launchVpnConsentOrStart() {
				val prepIntent = VpnService.prepare(this@MainActivity)
				if (prepIntent != null)
					vpnPrepareLauncher.launch(prepIntent)
				else
					AdBlockVpnService.start(this@MainActivity)
			}

			val notifLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.RequestPermission()
			) { _ ->
				if (isPendingVpnStart) {
					isPendingVpnStart = false
					launchVpnConsentOrStart()
				}
			}

			val saveCaLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")
			) { uri ->
				if (uri != null) {
					scope.launch(Dispatchers.IO) {
						runCatching {
							val bytes = vm.ca.getPemBytes() ?: throw IllegalStateException("CA certificate is not generated")
							val out = contentResolver.openOutputStream(uri) ?: throw IllegalStateException("Cannot open output file")
							out.use { it.write(bytes) }
							vm.postMessage("Saved CA certificate")
						}.onFailure { e ->
							vm.postMessage("Save failed: ${e.message}")
						}
					}
				}
			}

			val exportJsonLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.CreateDocument("application/json")
			) { uri ->
				if (uri != null) {
					val chosen = pendingExportSections
					scope.launch(Dispatchers.IO) {
						runCatching {
							val json = vm.buildBackupJson(chosen)
							val out = contentResolver.openOutputStream(uri) ?: throw IllegalStateException("Cannot open output file")
							out.use { it.write(json.toByteArray(Charsets.UTF_8)) }
							vm.postMessage("Backup exported")
						}.onFailure { e ->
							vm.postMessage("Export failed: ${e.message}")
						}
					}
				}
			}

			val importBackupLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.OpenDocument()
			) { uri ->
				if (uri != null) {
					scope.launch(Dispatchers.IO) {
						runCatching {
							val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
							if (!text.isNullOrBlank())
								vm.stageBackupImport(text)
							else
								vm.postMessage("Selected file is empty")
						}.onFailure { e ->
							vm.postMessage("Import error: ${e.message}")
						}
					}
				}
			}

			val importTxtListLauncher = rememberLauncherForActivityResult(
				ActivityResultContracts.OpenDocument()
			) { uri ->
				if (uri != null) {
					val displayName = resolveDocumentDisplayName(uri)
					vm.importLocalBlocklistStream(displayName) {
						contentResolver.openInputStream(uri)
					}
				}
			}

			fun handleToggleVpn() {
				if (vpn.isRunning) {
					AdBlockVpnService.stop(this@MainActivity)
					return
				}

				if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
					ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
				) {
					isPendingVpnStart = true
					notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
					return
				}

				launchVpnConsentOrStart()
			}

			TrueAdBlockerTheme(
				accentArgb = cfg.accentArgb,
				themeMode = cfg.themeMode,
			) {
				val isLightTheme = cfg.themeMode == THEME_LIGHT
				val navBarBg = if (isLightTheme) MaterialTheme.colorScheme.surface else Color(0xFF07090D)
				val view = LocalView.current
				if (!view.isInEditMode) {
					SideEffect {
						val insetsCtrl = WindowCompat.getInsetsController(window, view)
						insetsCtrl.isAppearanceLightStatusBars = isLightTheme
						insetsCtrl.isAppearanceLightNavigationBars = isLightTheme
						@Suppress("DEPRECATION")
						window.navigationBarColor = navBarBg.toArgb()
					}
				}

				val accent = MaterialTheme.colorScheme.primary

				Scaffold(
					containerColor = MaterialTheme.colorScheme.background,
					bottomBar = {
						Column {
							HorizontalDivider(color = MaterialTheme.colorScheme.outline)
							NavigationBar(
								containerColor = navBarBg,
							) {
								val unselectedNavCol = MaterialTheme.colorScheme.onSurfaceVariant
								val navColors = NavigationBarItemDefaults.colors(
									selectedIconColor = accent,
									selectedTextColor = accent,
									indicatorColor = accent.copy(alpha = 0.14f),
									unselectedIconColor = unselectedNavCol,
									unselectedTextColor = unselectedNavCol,
								)

								NavigationBarItem(
									selected = selectedTab == 0,
									onClick = { selectedTab = 0 },
									icon = { Icon(Icons.Default.Shield, contentDescription = "Home") },
									label = { Text("Home", fontSize = 11.sp, maxLines = 1) },
									colors = navColors,
								)
								NavigationBarItem(
									selected = selectedTab == 1,
									onClick = { selectedTab = 1 },
									icon = { Icon(Icons.Default.BarChart, contentDescription = "Activity") },
									label = { Text("Activity", fontSize = 11.sp, maxLines = 1) },
									colors = navColors,
								)
								NavigationBarItem(
									selected = selectedTab == 2,
									onClick = { selectedTab = 2 },
									icon = { Icon(Icons.Default.PieChart, contentDescription = "Analytics") },
									label = { Text("Analytics", fontSize = 11.sp, maxLines = 1) },
									colors = navColors,
								)
								NavigationBarItem(
									selected = selectedTab == 3,
									onClick = { selectedTab = 3 },
									icon = { Icon(Icons.Default.Tune, contentDescription = "Advanced") },
									label = { Text("Advanced", fontSize = 11.sp, maxLines = 1) },
									colors = navColors,
								)
								NavigationBarItem(
									selected = selectedTab == 4,
									onClick = { selectedTab = 4 },
									icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
									label = { Text("Settings", fontSize = 11.sp, maxLines = 1) },
									colors = navColors,
								)
							}
						}
					},
				) { innerPadding ->
					Box(
						modifier = Modifier
							.fillMaxSize()
							.padding(innerPadding),
					) {
						when (selectedTab) {
							0 -> HomeScreen(
								vm = vm,
								onToggleVpn = { handleToggleVpn() },
								onOpenHttpsSetup = {
									advancedSub = AdvancedSubScreen.HTTPS_SETUP
									selectedTab = 3
								},
								onOpenActivity = { selectedTab = 1 },
								onOpenSettings = { selectedTab = 4 },
								onOpenEngineConfig = {
									advancedSub = AdvancedSubScreen.ENGINE_CONFIG
									selectedTab = 3
								},
							)
							1 -> ActivityScreen(vm = vm)
							2 -> AnalyticsScreen(vm = vm)
							3 -> AdvancedScreen(
								vm = vm,
								currentSub = advancedSub,
								onNavigateSub = { advancedSub = it },
								onSaveCaFile = {
									saveCaLauncher.launch("TrueBlock-Root-CA.crt")
								},
								onOpenSystemSecuritySettings = {
									val isOpened = runCatching {
										startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
										true
									}.getOrDefault(false)
									if (!isOpened)
										runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) }
								},
								onImportLocalFilterTxt = {
									importTxtListLauncher.launch(arrayOf("text/*", "application/octet-stream", "*/*"))
								},
							)
							4 -> SettingsScreen(
								vm = vm,
								onExportBackup = { isExportDialogOpen = true },
								onImportBackup = { importBackupLauncher.launch(arrayOf("application/json", "text/*", "*/*")) },
								onOpenEngineConfig = {
									advancedSub = AdvancedSubScreen.ENGINE_CONFIG
									selectedTab = 3
								},
							)
						}
					}
				}

				if (isExportDialogOpen) {
					BackupSectionsDialog(
						isImportMode = false,
						inspection = null,
						onDismiss = { isExportDialogOpen = false },
						onConfirm = { sections ->
							isExportDialogOpen = false
							pendingExportSections = sections
							val isListsOnly = !sections.isGeneralConfig && !sections.isDnsAndNetworks && !sections.isAppsAndProxies
							val isConfigOnly = !sections.isCustomRules && !sections.isBlocklists
							val fileName = when {
								isListsOnly -> "trueblock-lists-rules.json"
								isConfigOnly -> "trueblock-config.json"
								else -> "trueblock-backup.json"
							}
							exportJsonLauncher.launch(fileName)
						},
					)
				}

				stagedImport?.let { (_, inspection) ->
					BackupSectionsDialog(
						isImportMode = true,
						inspection = inspection,
						onDismiss = { vm.dismissStagedImport() },
						onConfirm = { sections -> vm.confirmStagedImport(sections) },
					)
				}
			}
		}
	}

	private fun resolveDocumentDisplayName(uri: Uri): String {
		runCatching {
			contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
				if (cursor.moveToFirst()) {
					val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
					if (idx >= 0) {
						val name = cursor.getString(idx)
						if (!name.isNullOrBlank())
							return name
					}
				}
			}
		}

		return uri.lastPathSegment?.substringAfterLast('/')?.substringAfterLast(':')?.ifBlank { "Local_Blocklist" }
			?: "Local_Blocklist"
	}
}
