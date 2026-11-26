package com.renwixx.trueadblocker.ui

import android.graphics.Color as AndroidColor
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp

private val PRESET_SWATCHES = listOf(
	0xFF2979FF.toInt(),
	0xFF00B0FF.toInt(),
	0xFF00E5FF.toInt(),
	0xFF1DE9B6.toInt(),
	0xFF2ECC71.toInt(),
	0xFFFF9100.toInt(),
	0xFFFF5252.toInt(),
	0xFFE040FB.toInt(),
	0xFF7C4DFF.toInt(),
	0xFF536DFE.toInt(),
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ColorPickerDialog(
	initialArgb: Int,
	onDismiss: () -> Unit,
	onConfirm: (Int) -> Unit,
) {
	val initHsv = remember(initialArgb) {
		FloatArray(3).also { AndroidColor.colorToHSV(initialArgb, it) }
	}
	var hue by remember { mutableFloatStateOf(initHsv[0]) }
	var sat by remember { mutableFloatStateOf(initHsv[1]) }
	var value by remember { mutableFloatStateOf(initHsv[2]) }
	var hexInput by remember { mutableStateOf("%06X".format(initialArgb and 0xFFFFFF)) }

	val currentColor = Color.hsv(hue, sat, value)

	fun syncHexFromHsv(h: Float, s: Float, v: Float) {
		val argb = Color.hsv(h, s, v).toArgb()
		hexInput = "%06X".format(argb and 0xFFFFFF)
	}

	AlertDialog(
		onDismissRequest = onDismiss,
		containerColor = MaterialTheme.colorScheme.surface,
		title = { Text("Accent Color") },
		text = {
			Column(modifier = Modifier.fillMaxWidth()) {
				Canvas(
					modifier = Modifier
						.fillMaxWidth()
						.height(170.dp)
						.clip(RoundedCornerShape(12.dp))
						.pointerInput(Unit) {
							detectTapGestures { pos ->
								sat = (pos.x / size.width).coerceIn(0f, 1f)
								value = (1f - pos.y / size.height).coerceIn(0f, 1f)
								syncHexFromHsv(hue, sat, value)
							}
						}
						.pointerInput(Unit) {
							detectDragGestures { change, _ ->
								change.consume()
								sat = (change.position.x / size.width).coerceIn(0f, 1f)
								value = (1f - change.position.y / size.height).coerceIn(0f, 1f)
								syncHexFromHsv(hue, sat, value)
							}
						},
				) {
					val pureHue = Color.hsv(hue, 1f, 1f)
					drawRect(brush = Brush.horizontalGradient(listOf(Color.White, pureHue)))
					drawRect(brush = Brush.verticalGradient(listOf(Color.Transparent, Color.Black)))

					val cx = sat * size.width
					val cy = (1f - value) * size.height
					drawCircle(Color.White, radius = 9.dp.toPx(), center = Offset(cx, cy), style = Stroke(width = 2.5.dp.toPx()))
					drawCircle(Color.Black, radius = 11.dp.toPx(), center = Offset(cx, cy), style = Stroke(width = 1.dp.toPx()))
				}

				Spacer(Modifier.height(14.dp))

				Canvas(
					modifier = Modifier
						.fillMaxWidth()
						.height(24.dp)
						.clip(RoundedCornerShape(12.dp))
						.pointerInput(Unit) {
							detectTapGestures { pos ->
								hue = ((pos.x / size.width) * 360f).coerceIn(0f, 360f)
								syncHexFromHsv(hue, sat, value)
							}
						}
						.pointerInput(Unit) {
							detectDragGestures { change, _ ->
								change.consume()
								hue = ((change.position.x / size.width) * 360f).coerceIn(0f, 360f)
								syncHexFromHsv(hue, sat, value)
							}
						},
				) {
					val stops = listOf(
						Color.Red,
						Color.Yellow,
						Color.Green,
						Color.Cyan,
						Color.Blue,
						Color.Magenta,
						Color.Red,
					)
					drawRect(brush = Brush.horizontalGradient(stops))
					val hx = (hue / 360f) * size.width
					drawCircle(Color.White, radius = 10.dp.toPx(), center = Offset(hx, size.height / 2f), style = Stroke(width = 3.dp.toPx()))
				}

				Spacer(Modifier.height(14.dp))

				Row(
					verticalAlignment = Alignment.CenterVertically,
					modifier = Modifier.fillMaxWidth(),
				) {
					Box(
						modifier = Modifier
							.size(44.dp)
							.clip(CircleShape)
							.background(currentColor)
							.border(1.dp, MaterialTheme.colorScheme.outline, CircleShape),
					)
					Spacer(Modifier.width(12.dp))
					OutlinedTextField(
						value = hexInput,
						onValueChange = { txt ->
							val clean = txt.uppercase().filter { it in '0'..'9' || it in 'A'..'F' }.take(6)
							hexInput = clean
							if (clean.length == 6) {
								val parsed = clean.toIntOrNull(16)
								if (parsed != null) {
									val argb = (0xFF000000.toInt() or parsed)
									val hsv = FloatArray(3)
									AndroidColor.colorToHSV(argb, hsv)
									hue = hsv[0]
									sat = hsv[1]
									value = hsv[2]
								}
							}
						},
						prefix = { Text("#") },
						label = { Text("HEX") },
						singleLine = true,
						modifier = Modifier.weight(1f),
					)
				}

				Spacer(Modifier.height(14.dp))

				FlowRow(
					horizontalArrangement = Arrangement.spacedBy(10.dp),
					verticalArrangement = Arrangement.spacedBy(10.dp),
				) {
					for (swatch in PRESET_SWATCHES) {
						Box(
							modifier = Modifier
								.size(30.dp)
								.clip(CircleShape)
								.background(Color(swatch))
								.border(
									width = if ((currentColor.toArgb() and 0xFFFFFF) == (swatch and 0xFFFFFF)) 2.5.dp else 1.dp,
									color = if ((currentColor.toArgb() and 0xFFFFFF) == (swatch and 0xFFFFFF)) {
										MaterialTheme.colorScheme.onSurface
									} else {
										MaterialTheme.colorScheme.outline
									},
									shape = CircleShape,
								)
								.clickable {
									val hsv = FloatArray(3)
									AndroidColor.colorToHSV(swatch, hsv)
									hue = hsv[0]
									sat = hsv[1]
									value = hsv[2]
									syncHexFromHsv(hue, sat, value)
								},
						)
					}
				}
			}
		},
		confirmButton = {
			TextButton(onClick = { onConfirm(currentColor.toArgb()) }) {
				Text("Apply", color = MaterialTheme.colorScheme.primary)
			}
		},
		dismissButton = {
			TextButton(onClick = onDismiss) {
				Text("Cancel")
			}
		},
	)
}
