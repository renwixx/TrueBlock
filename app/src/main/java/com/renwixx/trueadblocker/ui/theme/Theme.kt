package com.renwixx.trueadblocker.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import com.renwixx.trueadblocker.data.THEME_LIGHT
import com.renwixx.trueadblocker.data.THEME_OLED

val LocalAccentColor = staticCompositionLocalOf { DefaultAccentBlue }

@Composable
fun TrueAdBlockerTheme(
	accentArgb: Int = 0xFF2979FF.toInt(),
	themeMode: Int = THEME_OLED,
	content: @Composable () -> Unit,
) {
	val accent = Color(accentArgb)
	val onPrimaryColor = if (accent.luminance() > 0.45f) Color(0xFF0B0E14) else Color.White

	val scheme = if (themeMode == THEME_LIGHT) {
		lightColorScheme(
			primary = accent,
			onPrimary = onPrimaryColor,
			primaryContainer = accent.copy(alpha = 0.14f),
			onPrimaryContainer = accent,
			secondary = accent,
			background = LightBackground,
			onBackground = LightTextPrimary,
			surface = LightSurface,
			onSurface = LightTextPrimary,
			surfaceVariant = LightSurfaceVariant,
			onSurfaceVariant = LightTextSecondary,
			outline = LightCardBorder,
			error = ShieldRed,
		)
	} else {
		val isOled = themeMode == THEME_OLED
		val bg = if (isOled) OledBlack else DarkBackground
		val surf = if (isOled) OledSurface else DarkSurface
		val surfVar = if (isOled) DarkSurface else Color(0xFF1C2230)
		darkColorScheme(
			primary = accent,
			onPrimary = onPrimaryColor,
			primaryContainer = accent.copy(alpha = 0.18f),
			onPrimaryContainer = accent,
			secondary = accent,
			background = bg,
			onBackground = TextPrimary,
			surface = surf,
			onSurface = TextPrimary,
			surfaceVariant = surfVar,
			onSurfaceVariant = TextSecondary,
			outline = CardBorder,
			error = ShieldRed,
		)
	}

	CompositionLocalProvider(LocalAccentColor provides accent) {
		MaterialTheme(
			colorScheme = scheme,
			typography = Typography,
			content = content,
		)
	}
}
