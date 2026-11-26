package com.renwixx.trueadblocker.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.renwixx.trueadblocker.data.CustomRule
import com.renwixx.trueadblocker.data.MODE_EXACT
import com.renwixx.trueadblocker.data.MODE_REGEX
import com.renwixx.trueadblocker.data.MODE_WILDCARD
import com.renwixx.trueadblocker.engine.RuleEngine
import com.renwixx.trueadblocker.ui.theme.ShieldGreen
import com.renwixx.trueadblocker.ui.theme.ShieldRed

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RuleEditorDialog(
	initialRule: CustomRule?,
	prefillPattern: String = "",
	prefillIsAllow: Boolean = false,
	onDismiss: () -> Unit,
	onSave: (CustomRule) -> Unit,
) {
	val startPattern = initialRule?.pattern ?: prefillPattern
	var pattern by remember { mutableStateOf(startPattern) }
	var matchMode by remember {
		mutableIntStateOf(
			initialRule?.matchMode ?: if (startPattern.contains('*') || startPattern.contains('?')) MODE_WILDCARD else MODE_EXACT
		)
	}
	var isAllow by remember { mutableStateOf(initialRule?.isAllow ?: prefillIsAllow) }
	var isRoute by remember { mutableStateOf(initialRule?.isRoute ?: startPattern.contains('/')) }
	var note by remember { mutableStateOf(initialRule?.note ?: "") }
	var testSample by remember {
		mutableStateOf(
			if (startPattern.isNotBlank() && !startPattern.contains('*')) "https://$startPattern" else "https://example.com/ad/banner.js"
		)
	}

	val regexError = if (matchMode == MODE_REGEX && pattern.isNotBlank()) {
		RuleEngine.validateRegex(pattern)
	} else {
		null
	}

	val previewRule = CustomRule(
		id = initialRule?.id ?: 0L,
		pattern = pattern.trim(),
		matchMode = matchMode,
		isAllow = isAllow,
		isRoute = isRoute,
		isEnabled = initialRule?.isEnabled ?: true,
		note = note.trim(),
	)

	val isTestMatched = if (pattern.isNotBlank() && regexError == null && testSample.isNotBlank()) {
		RuleEngine.testSingleCustomRule(previewRule, testSample)
	} else {
		false
	}

	val accent = MaterialTheme.colorScheme.primary

	Dialog(
		onDismissRequest = onDismiss,
		properties = DialogProperties(usePlatformDefaultWidth = false),
	) {
		Surface(
			shape = RoundedCornerShape(20.dp),
			color = MaterialTheme.colorScheme.surface,
			tonalElevation = 6.dp,
			modifier = Modifier
				.fillMaxWidth(0.94f)
				.padding(vertical = 16.dp),
		) {
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.verticalScroll(rememberScrollState())
					.padding(horizontal = 18.dp, vertical = 16.dp),
			) {
				Text(
					text = if (initialRule != null) "Edit Custom Rule" else "New Custom Rule",
					fontSize = 19.sp,
					fontWeight = FontWeight.Bold,
				)

				Spacer(Modifier.height(12.dp))
				Text("Action", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalArrangement = Arrangement.spacedBy(4.dp),
				) {
					FilterChip(
						selected = !isAllow,
						onClick = { isAllow = false },
						label = { Text("Block", maxLines = 1, softWrap = false, fontSize = 13.sp) },
						colors = FilterChipDefaults.filterChipColors(
							selectedContainerColor = ShieldRed.copy(alpha = 0.22f),
							selectedLabelColor = ShieldRed,
						),
					)
					FilterChip(
						selected = isAllow,
						onClick = { isAllow = true },
						label = { Text("Allow (Exception)", maxLines = 1, softWrap = false, fontSize = 13.sp) },
						colors = FilterChipDefaults.filterChipColors(
							selectedContainerColor = ShieldGreen.copy(alpha = 0.22f),
							selectedLabelColor = ShieldGreen,
						),
					)
				}

				Spacer(Modifier.height(8.dp))
				Text("Target Scope", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalArrangement = Arrangement.spacedBy(4.dp),
				) {
					FilterChip(
						selected = !isRoute,
						onClick = { isRoute = false },
						label = { Text("Domain", maxLines = 1, softWrap = false, fontSize = 13.sp) },
						colors = FilterChipDefaults.filterChipColors(
							selectedContainerColor = accent.copy(alpha = 0.22f),
							selectedLabelColor = accent,
						),
					)
					FilterChip(
						selected = isRoute,
						onClick = { isRoute = true },
						label = { Text("URL / Route", maxLines = 1, softWrap = false, fontSize = 13.sp) },
						colors = FilterChipDefaults.filterChipColors(
							selectedContainerColor = accent.copy(alpha = 0.22f),
							selectedLabelColor = accent,
						),
					)
				}

				Spacer(Modifier.height(8.dp))
				Text("Match Mode", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(8.dp),
					verticalArrangement = Arrangement.spacedBy(4.dp),
				) {
					FilterChip(
						selected = matchMode == MODE_EXACT,
						onClick = { matchMode = MODE_EXACT },
						label = { Text("Exact", maxLines = 1, softWrap = false, fontSize = 13.sp) },
					)
					FilterChip(
						selected = matchMode == MODE_WILDCARD,
						onClick = { matchMode = MODE_WILDCARD },
						label = { Text("Wildcard (*, ?)", maxLines = 1, softWrap = false, fontSize = 13.sp) },
					)
					FilterChip(
						selected = matchMode == MODE_REGEX,
						onClick = { matchMode = MODE_REGEX },
						label = { Text("Regex", maxLines = 1, softWrap = false, fontSize = 13.sp) },
					)
				}

				Spacer(Modifier.height(10.dp))
				OutlinedTextField(
					value = pattern,
					onValueChange = { txt ->
						pattern = txt
						if (txt.contains('/') && matchMode != MODE_REGEX)
							isRoute = true
					},
					textStyle = TextStyle(fontSize = 13.sp),
					label = {
						val hint = when {
							matchMode == MODE_REGEX -> "Regex (e.g. ^https?://xxx\\.com/ad/.*$)"
							isRoute && matchMode == MODE_WILDCARD -> "Route pattern (e.g. xxx.com/ad*)"
							isRoute -> "Exact route (e.g. xxx.com/ad)"
							matchMode == MODE_WILDCARD -> "Wildcard host (e.g. *.doubleclick.net)"
							else -> "Exact domain (e.g. ads.example.com)"
						}
						Text(hint, fontSize = 12.sp, maxLines = 1)
					},
					isError = regexError != null,
					supportingText = {
						if (regexError != null) {
							Text(regexError, color = ShieldRed, fontSize = 11.sp)
						} else if (isRoute) {
							Text("DNS allows resolving the host so HTTPS/HTTP proxy selectively blocks matching routes.", fontSize = 11.sp)
						}
					},
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)

				Spacer(Modifier.height(4.dp))
				OutlinedTextField(
					value = note,
					onValueChange = { note = it },
					textStyle = TextStyle(fontSize = 13.sp),
					label = { Text("Optional comment / note", fontSize = 12.sp) },
					singleLine = true,
					modifier = Modifier.fillMaxWidth(),
				)

				Spacer(Modifier.height(12.dp))
				Column(
					modifier = Modifier
						.fillMaxWidth()
						.clip(RoundedCornerShape(12.dp))
						.background(MaterialTheme.colorScheme.surfaceVariant)
						.padding(12.dp),
				) {
					Text("Live Pattern Tester", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
					Spacer(Modifier.height(6.dp))
					OutlinedTextField(
						value = testSample,
						onValueChange = { testSample = it },
						textStyle = TextStyle(fontSize = 13.sp),
						label = { Text("Test URL or Domain", fontSize = 11.sp) },
						singleLine = true,
						modifier = Modifier.fillMaxWidth(),
					)
					Spacer(Modifier.height(6.dp))
					val statusText = when {
						pattern.isBlank() -> "Enter a rule pattern above"
						regexError != null -> "Invalid regex syntax"
						isTestMatched && isAllow -> "MATCH -> Request will be ALLOWED"
						isTestMatched -> "MATCH -> Request will be BLOCKED"
						else -> "NO MATCH -> Rule does not trigger"
					}
					val statusCol = when {
						!isTestMatched -> MaterialTheme.colorScheme.onSurfaceVariant
						isAllow -> ShieldGreen
						else -> ShieldRed
					}
					Text(statusText, color = statusCol, fontSize = 12.sp, fontWeight = FontWeight.Medium)
				}

				Spacer(Modifier.height(12.dp))
				Row(
					horizontalArrangement = Arrangement.End,
					modifier = Modifier.fillMaxWidth(),
				) {
					TextButton(onClick = onDismiss) {
						Text("Cancel")
					}
					TextButton(
						enabled = pattern.isNotBlank() && regexError == null,
						onClick = { onSave(previewRule) },
					) {
						Text("Save", color = accent, fontWeight = FontWeight.Bold)
					}
				}
			}
		}
	}
}
