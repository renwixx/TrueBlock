package com.renwixx.trueadblocker.net

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import com.renwixx.trueadblocker.BuildConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class UpdateInfo(
	val versionCode: Int,
	val versionName: String,
	val commit: String,
	val notes: String,
	val apkUrl: String,
	val sha256: String,
)

object AppUpdater {
	private const val REPO_BASE = "https://github.com/renwixx/TrueBlock/releases"
	private const val ROLLING_MANIFEST_URL = "$REPO_BASE/download/latest-build/update.json"
	private const val STABLE_MANIFEST_URL = "$REPO_BASE/latest/download/update.json"

	private val _http = OkHttpClient.Builder()
		.connectTimeout(12, TimeUnit.SECONDS)
		.readTimeout(60, TimeUnit.SECONDS)
		.followRedirects(true)
		.build()

	fun checkForUpdate(): Result<UpdateInfo?> {
		return runCatching {
			val manifest = fetchManifest(ROLLING_MANIFEST_URL) ?: fetchManifest(STABLE_MANIFEST_URL) ?: return@runCatching null
			val isNewer = isRemoteNewer(
				remoteVersionCode = manifest.versionCode,
				remoteCommit = manifest.commit,
				localVersionCode = BuildConfig.VERSION_CODE,
				localCommit = BuildConfig.BUILD_COMMIT,
			)
			if (isNewer) manifest else null
		}
	}

	internal fun isRemoteNewer(
		remoteVersionCode: Int,
		remoteCommit: String,
		localVersionCode: Int,
		localCommit: String,
	): Boolean {
		if (remoteVersionCode > localVersionCode)
			return true
		if (remoteVersionCode == localVersionCode && remoteCommit.isNotEmpty() && localCommit.isNotEmpty() && localCommit != "local")
			return !remoteCommit.equals(localCommit, ignoreCase = true)

		return false
	}

	private fun fetchManifest(url: String): UpdateInfo? {
		val req = Request.Builder()
			.url(url)
			.header("User-Agent", "TrueBlock-Updater/${BuildConfig.VERSION_NAME}")
			.header("Cache-Control", "no-cache")
			.build()

		return _http.newCall(req).execute().use { resp ->
			if (!resp.isSuccessful)
				return null
			val body = resp.body?.string()?.trim() ?: return null
			val obj = JSONObject(body)
			val apkUrl = obj.optString("apkUrl", "").trim()
			if (!apkUrl.startsWith("https://"))
				return null

			UpdateInfo(
				versionCode = obj.optInt("versionCode", 0),
				versionName = obj.optString("versionName", ""),
				commit = obj.optString("commit", ""),
				notes = obj.optString("notes", ""),
				apkUrl = apkUrl,
				sha256 = obj.optString("sha256", "").trim().lowercase(),
			)
		}
	}

	fun downloadAndVerifyApk(
		ctx: Context,
		info: UpdateInfo,
		onProgress: (Float) -> Unit,
	): Result<File> {
		return runCatching {
			if (!info.apkUrl.startsWith("https://"))
				throw IllegalArgumentException("Only HTTPS update URLs are allowed")

			val dir = File(ctx.cacheDir, "updates").apply { mkdirs() }
			val partFile = File(dir, "TrueBlock-update.apk.part")
			val targetFile = File(dir, "TrueBlock-update.apk")

			val req = Request.Builder()
				.url(info.apkUrl)
				.header("User-Agent", "TrueBlock-Updater/${BuildConfig.VERSION_NAME}")
				.build()

			_http.newCall(req).execute().use { resp ->
				if (!resp.isSuccessful)
					throw IllegalStateException("HTTP ${resp.code}")
				val body = resp.body ?: throw IllegalStateException("Empty APK response")
				val total = body.contentLength()
				val md = MessageDigest.getInstance("SHA-256")
				val buf = ByteArray(16 * 1024)
				var readTotal = 0L

				FileOutputStream(partFile).use { fos ->
					body.byteStream().use { inp ->
						while (true) {
							val n = inp.read(buf)
							if (n <= 0)
								break
							fos.write(buf, 0, n)
							md.update(buf, 0, n)
							readTotal += n
							if (total > 0L)
								onProgress((readTotal.toFloat() / total.toFloat()).coerceIn(0f, 1f))
						}
					}
				}

				if (info.sha256.isNotEmpty()) {
					val actualHex = md.digest().joinToString("") { "%02x".format(it) }
					if (!actualHex.equals(info.sha256, ignoreCase = true)) {
						partFile.delete()
						throw SecurityException("APK SHA-256 checksum mismatch")
					}
				}
			}

			if (targetFile.exists())
				targetFile.delete()
			if (!partFile.renameTo(targetFile))
				throw IllegalStateException("Failed to finalize downloaded APK")

			targetFile
		}
	}

	fun canInstallPackages(ctx: Context): Boolean {
		return ctx.packageManager.canRequestPackageInstalls()
	}

	fun openUnknownSourcesSettings(ctx: Context) {
		val intent = Intent(
			Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
			Uri.parse("package:${ctx.packageName}"),
		).apply {
			flags = Intent.FLAG_ACTIVITY_NEW_TASK
		}
		ctx.startActivity(intent)
	}

	fun launchApkInstaller(ctx: Context, apkFile: File) {
		val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", apkFile)
		val intent = Intent(Intent.ACTION_VIEW).apply {
			setDataAndType(uri, "application/vnd.android.package-archive")
			flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
		}
		ctx.startActivity(intent)
	}
}
