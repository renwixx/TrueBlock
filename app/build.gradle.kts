import java.util.Properties

plugins {
	alias(libs.plugins.android.application)
	alias(libs.plugins.kotlin.android)
	alias(libs.plugins.kotlin.compose)
	alias(libs.plugins.ksp)
}

val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
	if (keystorePropsFile.exists())
		keystorePropsFile.inputStream().use { load(it) }
}

fun signingProp(propKey: String, envKey: String): String? {
	return keystoreProps.getProperty(propKey)?.takeIf { it.isNotBlank() }
		?: System.getenv(envKey)?.takeIf { it.isNotBlank() }
}

val releaseStorePath = signingProp("storeFile", "SIGNING_STORE_FILE")
val releaseStorePassword = signingProp("storePassword", "SIGNING_STORE_PASSWORD")
val releaseKeyAlias = signingProp("keyAlias", "SIGNING_KEY_ALIAS")
val releaseKeyPassword = signingProp("keyPassword", "SIGNING_KEY_PASSWORD")
val isReleaseKeystoreConfigured = releaseStorePath != null &&
	releaseStorePassword != null &&
	releaseKeyAlias != null &&
	releaseKeyPassword != null &&
	rootProject.file(releaseStorePath).exists()

android {
	namespace = "com.renwixx.trueadblocker"
	compileSdk = 35

	defaultConfig {
		applicationId = "com.renwixx.trueadblocker"
		minSdk = 29
		targetSdk = 35
		versionCode = 3
		versionName = "1.3.0"

		testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
	}

	signingConfigs {
		if (isReleaseKeystoreConfigured) {
			create("release") {
				storeFile = rootProject.file(releaseStorePath!!)
				storePassword = releaseStorePassword
				keyAlias = releaseKeyAlias
				keyPassword = releaseKeyPassword
				enableV1Signing = false
				enableV2Signing = true
				enableV3Signing = true
			}
		}
	}

	buildTypes {
		release {
			isMinifyEnabled = true
			isShrinkResources = true
			signingConfig = if (isReleaseKeystoreConfigured) {
				signingConfigs.getByName("release")
			} else {
				signingConfigs.getByName("debug")
			}
			proguardFiles(
				getDefaultProguardFile("proguard-android-optimize.txt"),
				"proguard-rules.pro",
			)
		}
	}

	compileOptions {
		sourceCompatibility = JavaVersion.VERSION_17
		targetCompatibility = JavaVersion.VERSION_17
	}

	kotlinOptions {
		jvmTarget = "17"
	}

	buildFeatures {
		compose = true
		buildConfig = true
	}

	packaging {
		resources {
			excludes += "/META-INF/{AL2.0,LGPL2.1}"
			excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
		}
	}
}

dependencies {
	implementation(libs.androidx.core.ktx)
	implementation(libs.androidx.lifecycle.runtime.ktx)
	implementation(libs.androidx.lifecycle.runtime.compose)
	implementation(libs.androidx.lifecycle.viewmodel.compose)
	implementation(libs.androidx.activity.compose)
	implementation(platform(libs.androidx.compose.bom))
	implementation(libs.androidx.ui)
	implementation(libs.androidx.ui.graphics)
	implementation(libs.androidx.ui.tooling.preview)
	implementation(libs.androidx.material3)
	implementation(libs.androidx.material.icons.extended)
	implementation(libs.androidx.room.runtime)
	implementation(libs.androidx.room.ktx)
	implementation(libs.androidx.room.paging)
	ksp(libs.androidx.room.compiler)
	implementation(libs.androidx.paging.runtime)
	implementation(libs.androidx.paging.compose)
	implementation(libs.okhttp)
	implementation(libs.bcprov)
	implementation(libs.bcpkix)
	implementation(libs.kotlinx.coroutines.android)

	testImplementation(libs.junit)
	androidTestImplementation(libs.androidx.junit)
	androidTestImplementation(libs.androidx.espresso.core)
	androidTestImplementation(platform(libs.androidx.compose.bom))
	androidTestImplementation(libs.androidx.ui.test.junit4)
	debugImplementation(libs.androidx.ui.tooling)
	debugImplementation(libs.androidx.ui.test.manifest)
}
