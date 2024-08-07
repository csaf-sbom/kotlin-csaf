package fhg.aisec.csaf

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.cio.*
import io.ktor.utils.io.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.pwall.json.schema.codegen.CodeGenerator
import java.nio.file.Path
import java.nio.file.Paths

val SCHEMA_TARGET_DIR: Path = Paths.get("src/main/resources")
const val CSAF_SCHEMAS_BASE_URL = "https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/"
// TODO: csaf_json_schema.json currently excluded due to unsupported recursive ref in branches_t
val SCHEMA_FILES = listOf("aggregator_json_schema.json", "provider_json_schema.json")

fun main() {
    val httpClient = HttpClient()
    val ioScope = CoroutineScope(Dispatchers.IO)
    runBlocking {
        SCHEMA_FILES.map { file ->
            ioScope.launch {
                val res = httpClient.get(CSAF_SCHEMAS_BASE_URL + file)
                if (res.status.isSuccess()) {
                    res.bodyAsChannel().copyAndClose(SCHEMA_TARGET_DIR.resolve(file).toFile().writeChannel())
                    println("Refreshed file $file from ${CSAF_SCHEMAS_BASE_URL + file}")
                }
            }
        }.forEach { it.join() }
    }

    val codeGenerator = CodeGenerator()
    codeGenerator.baseDirectoryName = "../csaf-import/src/main/kotlin"
    codeGenerator.basePackageName = "fhg.aisec.csaf.generated"
    codeGenerator.generate(SCHEMA_TARGET_DIR.toFile())
}