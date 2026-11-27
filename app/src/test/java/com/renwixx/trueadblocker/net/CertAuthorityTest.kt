package com.renwixx.trueadblocker.net

import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CertAuthorityTest {
	@Test
	fun isIpv4LiteralAndIsIpLiteralValidateEdgeCases() {
		assertTrue(CertAuthority.isIpv4Literal("0.0.0.0"))
		assertTrue(CertAuthority.isIpv4Literal("127.0.0.1"))
		assertTrue(CertAuthority.isIpv4Literal("255.255.255.255"))
		assertFalse(CertAuthority.isIpv4Literal("256.0.0.1"))
		assertFalse(CertAuthority.isIpv4Literal("-1.0.0.1"))
		assertFalse(CertAuthority.isIpv4Literal("1.2.3"))
		assertFalse(CertAuthority.isIpv4Literal("1.2.3.4.5"))
		assertFalse(CertAuthority.isIpv4Literal("a.b.c.d"))
		assertFalse(CertAuthority.isIpv4Literal(""))

		assertTrue(CertAuthority.isIpLiteral("1.1.1.1"))
		assertTrue(CertAuthority.isIpLiteral("::1"))
		assertTrue(CertAuthority.isIpLiteral("::"))
		assertTrue(CertAuthority.isIpLiteral("[2606:4700:4700::1111]"))
		assertTrue(CertAuthority.isIpLiteral("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
		assertFalse(CertAuthority.isIpLiteral("2001::85a3::7334"))
		assertFalse(CertAuthority.isIpLiteral("2001:db8:1:2:3:4:5:6:7"))
		assertFalse(CertAuthority.isIpLiteral("2001:zzzz::1"))
		assertFalse(CertAuthority.isIpLiteral("2001:12345::1"))
		assertFalse(CertAuthority.isIpLiteral("example.com"))
	}

	@Test
	fun rootCaAndLeafCertificatesPassStrictPkixAndCoverDnsIpv4Ipv6AndLongHostnames() {
		val caPair = CertAuthority.generateRsaPair()
		val caCert = CertAuthority.buildRootCaCertificate(caPair)
		assertTrue("Root CA must have CA BasicConstraints", caCert.basicConstraints >= 0)
		assertTrue(caCert.keyUsage[5]) // keyCertSign
		assertTrue(caCert.keyUsage[6]) // cRLSign
		caCert.verify(caCert.publicKey)

		val leafPair = CertAuthority.generateRsaPair()
		val dnsLeaf = CertAuthority.buildLeafCertificate("www.google.com", caCert, caPair.private, leafPair, validityDays = 89)
		assertArrayEquals(caCert.subjectX500Principal.encoded, dnsLeaf.issuerX500Principal.encoded)
		assertEquals(-1, dnsLeaf.basicConstraints)
		assertTrue(dnsLeaf.extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1"))
		dnsLeaf.verify(caCert.publicKey)

		val dnsSans = dnsLeaf.subjectAlternativeNames
		assertNotNull(dnsSans)
		assertEquals(2, dnsSans.first()[0]) // dNSName
		assertEquals("www.google.com", dnsSans.first()[1])

		val cf = CertificateFactory.getInstance("X.509")
		val params = PKIXParameters(setOf(TrustAnchor(caCert, null))).apply {
			isRevocationEnabled = false
		}
		CertPathValidator.getInstance("PKIX").validate(cf.generateCertPath(listOf(dnsLeaf)), params)

		// IPv4 SAN
		val ipv4Leaf = CertAuthority.buildLeafCertificate("1.1.1.1", caCert, caPair.private, leafPair)
		assertEquals(7, ipv4Leaf.subjectAlternativeNames.first()[0]) // iPAddress
		assertEquals("1.1.1.1", ipv4Leaf.subjectAlternativeNames.first()[1])
		ipv4Leaf.verify(caCert.publicKey)

		// IPv6 SAN (with brackets stripped)
		val ipv6Leaf = CertAuthority.buildLeafCertificate("[2606:4700:4700::1111]", caCert, caPair.private, leafPair)
		assertEquals(7, ipv6Leaf.subjectAlternativeNames.first()[0]) // iPAddress
		ipv6Leaf.verify(caCert.publicKey)

		// Long hostname (> 60 chars) truncates CN to 60 chars while keeping full SAN
		val longHost = "a".repeat(50) + ".subdomain.example.com"
		val longLeaf = CertAuthority.buildLeafCertificate(longHost, caCert, caPair.private, leafPair, validityDays = 999)
		assertEquals(longHost, longLeaf.subjectAlternativeNames.first()[1])
		val validityMs = longLeaf.notAfter.time - longLeaf.notBefore.time
		// notBefore = now - 1 day, notAfter = now + 397 days => ~398 days
		assertTrue(validityMs in (397L * 86_400_000L)..(399L * 86_400_000L))
	}
}
