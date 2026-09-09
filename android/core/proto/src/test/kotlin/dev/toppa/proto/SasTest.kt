package dev.toppa.proto

import com.google.gson.Gson
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

data class SasVector(
    val protocol: String = "",
    val version: Int = 0,
    val cases: List<SasCase> = emptyList(),
)

data class SasCase(
    val name: String = "",
    val handshakeHashHex: String = "",
    val sas: String = "",
)

/**
 * Consumes protocol/vectors/sas.json — identical to the Go SAS test, keeping
 * the two SAS derivations provably in sync (SPEC §2.4).
 */
class SasTest {

    @Test
    fun `sas vectors`() {
        val file = File("../../../protocol/vectors/sas.json")
        assumeTrue(file.exists(), "golden vectors not found; full checkout required")
        val vectors = Gson().fromJson(file.readText(), SasVector::class.java)
        for (case in vectors.cases) {
            assertEquals(64, case.handshakeHashHex.length, case.name)
            val hash = case.handshakeHashHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertEquals(case.sas, Sas.shortAuthString(hash), case.name)
        }
    }
}
