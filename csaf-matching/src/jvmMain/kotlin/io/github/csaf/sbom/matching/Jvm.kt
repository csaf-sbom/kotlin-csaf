/*
 * Copyright (c) 2025, The Authors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.github.csaf.sbom.matching

import com.github.packageurl.PackageURL
import io.github.nscuro.versatile.Vers
import io.github.nscuro.versatile.VersException
import us.springett.parsers.cpe.CpeParser
import us.springett.parsers.cpe.ICpe

actual typealias Cpe = ICpe

actual fun parseCpe(cpe: String): Cpe = CpeParser.parse(cpe)

actual typealias Purl = PackageURL

actual typealias Vers = Vers

actual fun parseVers(versString: String): Vers? {
    return try {
        Vers.parse(versString)
    } catch (_: VersException) {
        null
    }
}
