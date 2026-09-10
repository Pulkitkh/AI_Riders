# COMPLIANCE-VISION — Full System Workflow

**SIH 2026 · PS ID SIH26034 · Team AI Riders**
Software system to check compliance of packaged commodities under the Legal Metrology
(Packaged Commodities) Rules, 2011 by scanning products, images and labels.

---

## 0. The one-sentence model

> Pixels (a pack photo, a barcode, or a rendered e-commerce page) → structured LM(PC)R
> fields → measured against a **versioned, machine-readable rule-set** → a verdict that
> **cites the exact clause**, plus tamper-evident evidence routed into enforcement.

Everything below is an elaboration of that single sentence.

---

## 1. Actors and entry points

| Actor | Entry point | What they get back |
|---|---|---|
| Consumer / retailer | Mobile app (Flutter) — barcode scan or pack photo | Plain-language verdict, option to file a complaint |
| Manufacturer / brand | Web portal — upload label artwork + pack dimensions **before printing** | Fix-list, then a signed QR self-certification reference |
| E-commerce shopper | Browser extension (Manifest V3) | In-page badge on the listing being viewed |
| Crawler (unattended) | Scheduled Playwright jobs over marketplace listings | Bulk violations → regulator feed + public index |
| LM inspector / regulator | Tablet console (offline-capable) | Prioritised cases with litigation-ready evidence packets |

All five hit the **same backend** through the API gateway. There is one brain, five faces.

---

## 2. Path A — physical package scan

This is the core loop. Nine stages.

### A1. Capture
- App prompts for the shots it needs: **front panel, back/declaration panel, barcode**.
- Multi-frame burst rather than a single photo — later stages vote across frames, which is
  the main defence against glare, blur and curvature.
- Device metadata captured at source: GPS geo-tag, timestamp, device ID, app version.
  These become part of the evidence record and cannot be added later.

### A2. Pre-processing
`OpenCV` pipeline, runs on-device for the fast path and server-side for the accurate path:
- perspective **de-skew** (the pack is never photographed flat),
- **glare / specular-reflection removal** (plastic and foil packaging),
- **de-blur** + **super-resolution** upscaling for low-end phone cameras,
- contrast normalisation for faded thermal-printed dates.

### A3. Label-region detection
- A **YOLOv8** (Ultralytics) detector locates the *declaration block(s)* on the pack —
  not the whole image. Packages are cylindrical, multi-panel and wrap-around; the
  declarations are rarely one clean rectangle.
- Output: bounding boxes for each candidate declaration region + the barcode region.

### A4. OCR
- **PaddleOCR / Tesseract 5**, fine-tuned for Indic scripts, run per region.
- Output per text line: `{text, bbox, pixel_height, confidence, script}`.
- `pixel_height` is retained deliberately — stage A6 needs it. Most OCR pipelines throw
  this away; ours cannot.
- Indian labels are routinely bilingual (English + Hindi + a regional language), so the
  same declaration appears two or three times in different scripts.

### A5. Field extraction (layout-aware NLP)
- A **LayoutLMv3-class** model plus a regex/NER hybrid classifies each OCR line into the
  **LM(PC)R field taxonomy**:
  `manufacturer_packer_importer`, `generic_name`, `net_quantity`, `mrp`,
  `date_of_manufacture`, `best_before`, `consumer_care`, `country_of_origin`,
  `unit_sale_price`, `dimensions`.
- Layout-aware matters: the model uses *spatial position*, not just token order, so a
  Hindi net-quantity string is recognised as the **same** declaration as its English
  counterpart rather than a second, separate field.
- Output: a structured `DeclarationSet` with per-field provenance (which bbox, which frame,
  what confidence).

### A6. Font-size & prominence measurement — *the differentiator*
1. Establish real-world scale. Preferred source: the **barcode's known module width**
   (a GS1 symbol has a defined X-dimension); fallbacks are a reference object in frame or
   user-entered pack surface area.
2. Convert every declaration's `pixel_height` → **millimetres**.
3. Look up the **Rule 8 minimum letter-height slab** for this pack's surface area / net
   quantity.
4. Cross-validate the mm estimate across the multi-frame burst; only flag when the frames
   agree, to avoid perspective artefacts producing false violations.

This catches the *technically-present-but-illegible* class of violation, which today is
detectable only by a human with a ruler.

### A7. Rules-engine evaluation
- The `DeclarationSet` + measurements are evaluated against the **rule-set**: LM(PC)R 2011
  clauses stored as **versioned JSON/YAML data**, each with an `effective_from` date.
- Each clause returns `{status: pass|fail|not_applicable, citation, human_message, evidence_ref}`.
- Because rules are data with effective dates, the engine can evaluate a pack against
  *today's* law or against the law as it stood on the date of packing — which matters in
  prosecution.
- **No redeploy when the law changes.** An LM official edits the clause in the admin
  console and the next scan uses it.

### A8. GTIN cross-verification *(optional, when a barcode is present)*
- Look up the GTIN in a product-master registry (**GS1 India DataKart / National Product
  Catalogue**-type).
- Compare *declared master data* vs *printed label data*. A mismatch is the signature of
  relabelling, repacking or MRP-tampering fraud — a violation neither source catches alone.

### A9. Verdict, evidence and routing
- **Verdict**: compliance score + colour band — Compliant / Minor Issue / Major Violation.
- **Report**: itemised, each line naming the clause, e.g.
  `Rule 6(1)(f) — MRP declaration not found`
  `Rule 8 — declared letter height 1.1 mm; minimum for this pack size is 4 mm`
- **Evidence packet** (only on failure): original image, OCR text, extracted fields,
  measurements, rule-set version, geo-tag, timestamp — **hash-chained** into an
  append-only ledger so the record is tamper-evident and admissible.
- **Routing**: user may file it; the case is assigned to the correct jurisdiction's LM
  office and can be pushed into NCH / INGRAM / e-Daakhil.

---

## 3. Path B — e-commerce listing scan

Same brain, different eyes.

1. **Fetch** — headless Chromium (Playwright) renders the product page, or the browser
   extension reads the DOM of the page the shopper is already on.
2. **Extract** — a hybrid DOM-selector + vision extractor pulls the fields Rule 10 requires
   the platform to display: manufacturer/importer, generic name, net quantity, MRP,
   country of origin, best-before where relevant. Vision is the fallback when the value is
   baked into a listing image rather than the HTML.
3. **Evaluate** — the *same* rules engine as A7. This is the point: one law, one engine,
   two input pipelines.
4. **Record** — misses are logged with screenshot, URL, seller ID, platform and timestamp.
5. **Aggregate** — results roll up two ways:
   - a **public Marketplace Compliance Index** by platform, category and large seller;
   - a **private regulator feed** for targeted enforcement.

Layout churn is expected, so extractors are modular and retrained frequently; official
platform APIs are the preferred path over scraping wherever a partnership exists.

---

## 4. Path C — manufacturer pre-certification ("shift-left")

1. Brand uploads planned label artwork (PDF/AI/PNG) **plus pack dimensions** — dimensions
   are supplied rather than estimated, so the Rule 8 check is exact here.
2. The identical rules engine runs on the artwork.
3. Returns a **fix-list**, not just a verdict: which declaration is missing, which font is
   below threshold, by how many millimetres.
4. On pass, the system issues a **digitally-signed, QR-coded self-certification reference**
   that can be printed on the pack — so any later Path A scan instantly sees the label was
   pre-vetted, and by which rule-set version.

This converts the tool from a policing instrument into a compliance-assistance one, which
is what makes MSMEs adopt it voluntarily.

---

## 5. The feedback loop

```
scan → verdict → user/inspector correction → labelled example → retraining queue
                                          ↘ reporter reputation score
```

- Every low-confidence extraction goes to a **human review queue** rather than out as a
  verdict.
- Every correction becomes new labelled training data (**active learning**), so accuracy
  improves with usage instead of decaying.
- Citizen reports carry a **reputation score**; a fraud-detection layer filters spam and
  malicious reporting before anything reaches an officer's queue.
- **Confidence-based triage** is what protects a ~3,500-officer workforce from being buried
  in false positives.

---

## 6. Service architecture

API-first microservices; every client is a thin caller.

```
Clients        Mobile app · PWA · Browser extension · Inspector console (offline-capable)
                                   │
API Gateway    auth (OAuth2/JWT · DigiLocker e-KYC for brands) · rate limit · REST+GraphQL
                                   │
   ┌───────────────┬───────────────┼───────────────┬────────────────┐
Pre-processing  Detection       OCR            Field extraction   Measurement
   └───────────────┴───────────────┼───────────────┴────────────────┘
                                   │
                          RULES ENGINE  (versioned rule-set + admin console)
                                   │
   ┌───────────────┬───────────────┼───────────────┬────────────────┐
GTIN cross-check  Crawler   Case management   Evidence ledger   Analytics
   └───────────────┴───────────────┴───────────────┴────────────────┘
                                   │
Data           PostgreSQL (cases) · MongoDB (OCR/image metadata) · Elasticsearch (audit
               search) · Redis (cache/queues) · object store (label images)
```

**Deployment.** Containerised (Docker/Kubernetes) on an empanelled Government Cloud
(MeghRaj/NIC-type) for data sovereignty; horizontal scaling for festive-season e-commerce
surges; a quantised **TensorFlow Lite / ONNX** model bundled into the mobile app so
inspectors keep basic OCR + completeness checks working fully offline, syncing on
reconnect.

---

## 7. Phased build plan

| Phase | Scope | Proves |
|---|---|---|
| **V1** (hackathon PoC) | Barcode scan → master-data lookup → completeness check on a rule subset; rules already stored as data | The rules-as-data architecture and the end-to-end loop |
| **V2** | Full OCR + layout-aware field extraction on pack photos; Rule 8 font-height measurement via barcode calibration | The genuinely novel capability |
| **V3** | E-commerce crawler + browser extension + Marketplace Compliance Index | Scale and the e-commerce gap the 2026 amendments target |
| **V4** | Inspector console, hash-chained evidence ledger, e-Daakhil/NCH integration, AR shelf-scan | Closing detection → enforcement |

---

## 8. Why each hard part is tractable

| Risk | Handling |
|---|---|
| OCR on curved / faded / low-light labels | Multi-frame capture, super-resolution, human review queue on low confidence, active-learning retraining |
| Law changes (three amendments in 2026 alone) | Versioned rules-as-data with effective dates, edited via admin console — live in hours, zero redeploy |
| Measuring mm without a ruler | Barcode module-width calibration, cross-validated across frames before flagging |
| Marketplace layout churn / scraping blocks | Modular retrained DOM extractors; official API partnerships preferred |
| False positives swamping officers | Confidence triage + reporter reputation + mandatory reviewer step before escalation |
| Privacy and rural connectivity | RBAC, encryption in transit and at rest, DPDP Act 2023 alignment; offline TFLite with deferred sync |

---

## 9. Future extension

The same OCR/CV backbone with a different rule-set covers **FSSAI** labelling, **BIS**
ISI/Hallmark and the **Drugs Rules** — a single scan, multiple regulators. Beyond that:
predictive risk-scoring on historical violation patterns, direct platform API partnerships,
customs cross-check for Country-of-Origin claims, and a public API so third-party consumer
apps can call the same verified compliance engine.
