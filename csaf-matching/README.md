# CSAF Matching

This module provides helpers to implement a CSAF Asset/SBOM Matching System. Since the exact specification of such a matching is not yet defined, this README will serve as a pseudo-specification to understand how the matching is currently implements.

## Matching Interface / API

The matching interface defines several data structures. Its intention is to match the information on a CSAF data structure against a defined SBOM format. The data structure of the SBOM or asset format is not strictly defined. However, the [ProtoBOM](http://github.com/protobom/protobom) format can be used as a reference, since it aims to be a common transport format for SBOMs, allowing conversion to other formats such as CycloneDX or SPDX. Therefore, for the rest of this document, we will refer to two types of ProtoBOM datastructures:
- `Document`, which comprises the whole SBOM
- `Node`, which represents one particular component within an SBOM 

| Name                 | Properties                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Matcher`            | The main interface for matching. It provides methods to match a CSAF document against a list of SBOMs. It contains the following properties: <br/>- `advisory`: The CSAF security advisory to match against. <br/>The following operations MUST be supported:<br/>- `match(node, threshold)`: Matches the `advisory` against one `node` in the SBOM<br/>- `matchAll(document, threshold`: Matches the `advisory` against the complete SBOM `document` |
| `Match`              | The result of a matching operation. It contains the matched SBOMs and their corresponding CSAF document. It contains the following properties:<br/>- `advisory`: The CSAF security advisory this match was generated from<br/>-`vulnerableProduct`: The CSAF product that generated the match<br/>-`affectedNode`: The node (component) that is affected by this advisory                                                                             |
| `MatchingConfidence` |                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## Confidence Levels

## Matching Properties

## Matching Algorithm



