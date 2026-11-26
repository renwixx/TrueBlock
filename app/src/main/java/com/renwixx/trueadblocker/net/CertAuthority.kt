package com.renwixx.trueadblocker.net

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProtection
import android.security.keystore.KeyProperties
import android.util.LruCache
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal

data class CaStatus(
	val isReady: Boolean = false,
	val isInstalledInSystem: Boolean = false,
	val subject: String = "",
	val sha256Fingerprint: String = "",
	val validUntilMillis: Long = 0L,
	val pemFilePath: String = "",
)

private class CachedLeafSsl(
	val ctx: SSLContext,
	val expiresAtMs: Long,
)

class CertAuthority(ctx: Context, isAutoLoad: Boolean = true) {
	private val _certDir = File(ctx.applicationContext.filesDir, "certs").apply { mkdirs() }
	private val _legacyP12File = File(_certDir, "trueadblocker_ca.p12")
	private val _pemFile = File(_certDir, "TrueBlock-Root-CA.crt")
	private val _legacyPwd = "trueadblocker_local_ca".toCharArray()
	private val _memKsPwd = "leaf_mem_ks".toCharArray()
	private val _rng = SecureRandom()

	@Volatile
	private var _caKey: PrivateKey? = null

	@Volatile
	private var _caCert: X509Certificate? = null

	@Volatile
	private var _leafKeyPair: KeyPair? = null

	private val _sslCache = LruCache<String, CachedLeafSsl>(512)
	private val _status = MutableStateFlow(CaStatus())
	val status: StateFlow<CaStatus> = _status.asStateFlow()

	init {
		if (isAutoLoad)
			loadExistingIfPresent()
	}

	val isReady: Boolean
		get() = _caKey != null && _caCert != null

	fun refreshInstallState() {
		val cert = _caCert ?: return
		publishStatus(cert)
	}

	@Synchronized
	fun loadExistingIfPresent(): Boolean {
		if (_caKey != null && _caCert != null)
			return true

		if (loadFromAndroidKeyStore())
			return true

		if (migrateLegacyP12ToKeyStore())
			return true

		return false
	}

	private fun loadFromAndroidKeyStore(): Boolean {
		return runCatching {
			val aks = KeyStore.getInstance(ANDROID_KEYSTORE)
			aks.load(null)
			val key = aks.getKey(KEYSTORE_ALIAS, null) as? PrivateKey ?: return false
			val ksCert = aks.getCertificate(KEYSTORE_ALIAS) as? X509Certificate ?: return false

			val pemCert = readPemCertificateFile()
			val effectiveCert = if (pemCert != null && pemCert.publicKey.encoded.contentEquals(ksCert.publicKey.encoded)) {
				pemCert
			} else if (ksCert.basicConstraints >= 0) {
				writePemFile(ksCert)
				ksCert
			} else {
				return false
			}

			_caKey = key
			_caCert = effectiveCert
			ensureLeafKey()
			if (_legacyP12File.exists())
				_legacyP12File.delete()
			publishStatus(effectiveCert)
			true
		}.getOrDefault(false)
	}

	private fun migrateLegacyP12ToKeyStore(): Boolean {
		if (!_legacyP12File.exists())
			return false

		return runCatching {
			val p12 = KeyStore.getInstance("PKCS12")
			_legacyP12File.inputStream().use { p12.load(it, _legacyPwd) }
			val key = p12.getKey("root_ca", _legacyPwd) as? PrivateKey ?: return false
			val cert = p12.getCertificate("root_ca") as? X509Certificate ?: return false

			val aks = KeyStore.getInstance(ANDROID_KEYSTORE)
			aks.load(null)
			val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
				.setDigests(KeyProperties.DIGEST_SHA256)
				.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
				.build()
			aks.setEntry(KEYSTORE_ALIAS, KeyStore.PrivateKeyEntry(key, arrayOf(cert)), protection)

			val importedKey = aks.getKey(KEYSTORE_ALIAS, null) as? PrivateKey ?: return false
			_caKey = importedKey
			_caCert = cert
			ensureLeafKey()
			writePemFile(cert)
			_legacyP12File.delete()
			publishStatus(cert)
			true
		}.getOrDefault(false)
	}

	@Synchronized
	fun generateOrRegenerateCa(): CaStatus {
		_sslCache.evictAll()
		val now = System.currentTimeMillis()
		val aks = KeyStore.getInstance(ANDROID_KEYSTORE)
		aks.load(null)
		if (aks.containsAlias(KEYSTORE_ALIAS))
			runCatching { aks.deleteEntry(KEYSTORE_ALIAS) }

		val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
		val spec = KeyGenParameterSpec.Builder(
			KEYSTORE_ALIAS,
			KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
		)
			.setKeySize(2048)
			.setDigests(KeyProperties.DIGEST_SHA256)
			.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
			.setCertificateSubject(X500Principal("CN=TrueBlock Local Root CA, O=TrueBlock"))
			.setCertificateNotBefore(Date(now - 86_400_000L))
			.setCertificateNotAfter(Date(now + 10L * 365L * 86_400_000L))
			.build()
		kpg.initialize(spec)
		val caPair = kpg.generateKeyPair()
		val cert = buildRootCaCertificate(caPair, _rng)

		_caKey = caPair.private
		_caCert = cert
		ensureLeafKey()
		writePemFile(cert)
		if (_legacyP12File.exists())
			_legacyP12File.delete()
		publishStatus(cert)

		return _status.value
	}

	fun getPemBytes(): ByteArray? {
		if (!_pemFile.exists())
			_caCert?.let { writePemFile(it) }

		return if (_pemFile.exists()) _pemFile.readBytes() else null
	}

	fun sslContextForHost(rawHost: String, validityDays: Int = 89): SSLContext {
		val host = rawHost.trim().lowercase().removeSurrounding("[", "]").trimEnd('.')
		val days = validityDays.coerceIn(1, 397)
		val cacheKey = "$host:$days"
		val now = System.currentTimeMillis()

		_sslCache.get(cacheKey)?.let { hit ->
			if (now + 3_600_000L < hit.expiresAtMs)
				return hit.ctx
		}

		synchronized(this) {
			_sslCache.get(cacheKey)?.let { hit ->
				if (now + 3_600_000L < hit.expiresAtMs)
					return hit.ctx
			}

			val caKey = _caKey ?: throw IllegalStateException("Root CA not initialized")
			val caCert = _caCert ?: throw IllegalStateException("Root CA cert missing")
			val leafPair = ensureLeafKey()
			val leafCert = buildLeafCertificate(host, caCert, caKey, leafPair, _rng, days)

			val ks = KeyStore.getInstance("PKCS12")
			ks.load(null, _memKsPwd)
			ks.setKeyEntry("leaf", leafPair.private, _memKsPwd, arrayOf(leafCert, caCert))

			val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
			kmf.init(ks, _memKsPwd)

			val sslCtx = SSLContext.getInstance("TLS")
			sslCtx.init(kmf.keyManagers, null, _rng)
			_sslCache.put(cacheKey, CachedLeafSsl(sslCtx, leafCert.notAfter.time))

			return sslCtx
		}
	}

	private fun ensureLeafKey(): KeyPair {
		_leafKeyPair?.let { return it }
		val generated = generateRsaPair(_rng)
		_leafKeyPair = generated

		return generated
	}

	private fun readPemCertificateFile(): X509Certificate? {
		if (!_pemFile.exists())
			return null

		return runCatching {
			_pemFile.inputStream().use { inp ->
				CertificateFactory.getInstance("X.509").generateCertificate(inp) as? X509Certificate
			}
		}.getOrNull()
	}

	private fun writePemFile(cert: X509Certificate) {
		val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded)
		val pem = "-----BEGIN CERTIFICATE-----\n${b64.trim()}\n-----END CERTIFICATE-----\n"
		_pemFile.writeText(pem)
	}

	private fun checkInstalledInAndroidCaStore(target: X509Certificate): Boolean {
		return runCatching {
			val store = KeyStore.getInstance("AndroidCAStore")
			store.load(null)
			val targetBytes = target.encoded
			val aliases = store.aliases()
			while (aliases.hasMoreElements()) {
				val alias = aliases.nextElement()
				if (!alias.startsWith("user:"))
					continue
				val c = store.getCertificate(alias) as? X509Certificate ?: continue
				if (c.encoded.contentEquals(targetBytes))
					return true
			}
			false
		}.getOrDefault(false)
	}

	private fun publishStatus(cert: X509Certificate) {
		val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
		val fp = digest.joinToString(":") { "%02X".format(it) }
		val isTrustedByOs = checkInstalledInAndroidCaStore(cert)
		_status.value = CaStatus(
			isReady = true,
			isInstalledInSystem = isTrustedByOs,
			subject = "TrueBlock Local Root CA (Android Keystore)",
			sha256Fingerprint = fp,
			validUntilMillis = cert.notAfter.time,
			pemFilePath = _pemFile.absolutePath,
		)
	}

	companion object {
		private const val ANDROID_KEYSTORE = "AndroidKeyStore"
		private const val KEYSTORE_ALIAS = "trueblock_root_ca_key"

		fun generateRsaPair(rng: SecureRandom = SecureRandom()): KeyPair {
			val kpg = KeyPairGenerator.getInstance("RSA")
			kpg.initialize(2048, rng)

			return kpg.generateKeyPair()
		}

		fun buildRootCaCertificate(caPair: KeyPair, rng: SecureRandom = SecureRandom()): X509Certificate {
			val now = System.currentTimeMillis()
			val notBefore = Date(now - 86_400_000L)
			val notAfter = Date(now + 10L * 365L * 86_400_000L)
			val serial = BigInteger(128, rng).add(BigInteger.ONE)
			val subject = X500Name("CN=TrueBlock Local Root CA, O=TrueBlock")

			val extUtils = JcaX509ExtensionUtils()
			val builder = JcaX509v3CertificateBuilder(
				subject,
				serial,
				notBefore,
				notAfter,
				subject,
				caPair.public,
			)
			builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
			builder.addExtension(
				Extension.keyUsage,
				true,
				KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign),
			)
			builder.addExtension(
				Extension.subjectKeyIdentifier,
				false,
				extUtils.createSubjectKeyIdentifier(caPair.public),
			)

			val signer = JcaContentSignerBuilder("SHA256withRSA").build(caPair.private)

			return JcaX509CertificateConverter().getCertificate(builder.build(signer))
		}

		// Preserves exact ASN.1 DER RDN sequence from caCert via JcaX509CertificateHolder so BoringSSL/Chrome matches Issuer == Subject byte-for-byte
		fun buildLeafCertificate(
			host: String,
			caCert: X509Certificate,
			caKey: PrivateKey,
			leafPair: KeyPair,
			rng: SecureRandom = SecureRandom(),
			validityDays: Int = 89,
		): X509Certificate {
			val cleanHost = host.removeSurrounding("[", "]")
			val now = System.currentTimeMillis()
			val notBefore = Date(now - 86_400_000L)
			val notAfter = Date(now + validityDays.coerceIn(1, 397).toLong() * 86_400_000L)
			val serial = BigInteger(128, rng).add(BigInteger.TWO)

			val caHolder = JcaX509CertificateHolder(caCert)
			val issuer = caHolder.subject
			val safeCn = if (cleanHost.length <= 60) cleanHost else cleanHost.takeLast(60)
			val subject = X500Name("CN=$safeCn")

			val extUtils = JcaX509ExtensionUtils()
			val builder = JcaX509v3CertificateBuilder(
				issuer,
				serial,
				notBefore,
				notAfter,
				subject,
				leafPair.public,
			)
			builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
			builder.addExtension(
				Extension.keyUsage,
				true,
				KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment),
			)
			builder.addExtension(
				Extension.extendedKeyUsage,
				false,
				ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
			)

			val sanTag = if (isIpLiteral(cleanHost)) GeneralName.iPAddress else GeneralName.dNSName
			builder.addExtension(
				Extension.subjectAlternativeName,
				false,
				GeneralNames(GeneralName(sanTag, cleanHost)),
			)
			builder.addExtension(
				Extension.authorityKeyIdentifier,
				false,
				extUtils.createAuthorityKeyIdentifier(caHolder),
			)
			builder.addExtension(
				Extension.subjectKeyIdentifier,
				false,
				extUtils.createSubjectKeyIdentifier(leafPair.public),
			)

			val signer = JcaContentSignerBuilder("SHA256withRSA").build(caKey)

			return JcaX509CertificateConverter().getCertificate(builder.build(signer))
		}

		internal fun isIpLiteral(s: String): Boolean {
			val clean = s.removeSurrounding("[", "]")
			if (isIpv4Literal(clean))
				return true
			if (!clean.contains(':'))
				return false

			return runCatching {
				val parts = clean.split("::", limit = 2)
				if (clean.indexOf("::") != clean.lastIndexOf("::"))
					return false
				val left = if (parts[0].isEmpty()) emptyList() else parts[0].split(':')
				val right = if (parts.size == 2 && parts[1].isNotEmpty()) parts[1].split(':') else emptyList()
				val hasDoubleColon = parts.size == 2
				val totalGroups = left.size + right.size
				val isCountValid = if (hasDoubleColon) totalGroups in 0..7 else totalGroups == 8
				isCountValid && (left + right).all { g -> g.length in 1..4 && g.all { c -> c.digitToIntOrNull(16) != null } }
			}.getOrDefault(false)
		}

		internal fun isIpv4Literal(s: String): Boolean {
			val parts = s.split('.')
			if (parts.size != 4)
				return false

			return parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true }
		}
	}
}
