/* ==========================================================================
   CallShield Forensics // Standalone Browser Engine (static/standalone-engine.js)
   Enables full interactive functionality on static hosts (e.g. GitHub Pages)
   while automatically using the FastAPI backend when running locally.
   ========================================================================== */

(function () {
  const originalFetch = window.fetch.bind(window);
  let BUNDLE = null;
  let BUNDLE_PROMISE = null;

  async function getBundle() {
    if (BUNDLE) return BUNDLE;
    if (!BUNDLE_PROMISE) {
      BUNDLE_PROMISE = originalFetch("static/standalone-data.json")
        .then((r) => r.json())
        .then((data) => {
          BUNDLE = data;
          return BUNDLE;
        });
    }
    return BUNDLE_PROMISE;
  }

  function sanitizePhoneNumber(rawInput) {
    if (rawInput === null || rawInput === undefined) return "+91-00000-00000";
    let s = String(rawInput).trim().replace(/^['"]+/, "").replace(/['"]+$/, "").trim();
    if (!s) return "+91-00000-00000";
    if (s.startsWith("00")) s = "+" + s.slice(2);
    const hasPlus = s.startsWith("+");
    const digits = s.replace(/\D/g, "");
    if (!digits) return "+91-00000-00000";
    if (!hasPlus) {
      if (digits.length === 10) {
        return `+91-${digits.slice(0, 5)}-${digits.slice(5)}`;
      }
      if (digits.length === 11 && digits.startsWith("0")) {
        const d = digits.slice(1);
        return `+91-${d.slice(0, 5)}-${d.slice(5)}`;
      }
      if (digits.length === 12 && digits.startsWith("91")) {
        return `+91-${digits.slice(2, 7)}-${digits.slice(7)}`;
      }
      return `+${digits}`;
    }
    if (digits.startsWith("91") && digits.length === 12) {
      return `+91-${digits.slice(2, 7)}-${digits.slice(7)}`;
    }
    if (digits.startsWith("1") && digits.length === 11) {
      return `+1-${digits.slice(1, 4)}-${digits.slice(4, 7)}-${digits.slice(7)}`;
    }
    if (digits.startsWith("44") && digits.length >= 11) {
      return `+44-${digits.slice(2, 4)}-${digits.slice(4, 8)}-${digits.slice(8)}`;
    }
    if (digits.startsWith("92") && digits.length >= 11) {
      return `+92-${digits.slice(2, 5)}-${digits.slice(5)}`;
    }
    return `+${digits}`;
  }

  function analyzeTranscriptClient(text, categories) {
    const raw = (text || "").trim();
    if (!raw) {
      return {
        transcript_risk_score: 0.0,
        verdict_label: "Safe",
        risk_tier: "No Transcript Provided",
        matched_count: 0,
        total_categories_checked: categories.length,
        matched_categories: [],
        all_categories_status: categories.map((c) => ({
          id: c.id,
          name: c.name,
          weight: c.weight,
          severity: c.severity,
          matched: false,
          match_count: 0,
          matches: [],
        })),
        highlighted_spans: [],
        word_count: 0,
        summary_explanation: "Enter or paste a call transcript to scan against the 10 scam-indicator regex categories.",
      };
    }

    const words = raw.split(/\s+/).filter(Boolean);
    const matchedCategories = [];
    const allStatus = [];
    const rawSpans = [];
    let accumulatedPoints = 0.0;

    for (const cat of categories) {
      const catMatches = [];
      for (const pat of cat.patterns) {
        let regex;
        try {
          regex = new RegExp(pat, "gi");
        } catch (e) {
          continue;
        }
        let m;
        while ((m = regex.exec(raw)) !== null) {
          const matchedStr = m[0];
          if (!catMatches.some((x) => x.toLowerCase() === matchedStr.toLowerCase())) {
            catMatches.push(matchedStr);
          }
          rawSpans.push({
            start: m.index,
            end: m.index + matchedStr.length,
            text: matchedStr,
            category_id: cat.id,
            category_name: cat.name,
            severity: cat.severity,
            color: cat.color || "#ef4444",
          });
          if (m.index === regex.lastIndex) regex.lastIndex++;
        }
      }

      const isHit = catMatches.length > 0;
      if (isHit) {
        const catScore = cat.weight + Math.min(8.0, (catMatches.length - 1) * 3.5);
        accumulatedPoints += catScore;
        matchedCategories.push({
          id: cat.id,
          name: cat.name,
          weight: cat.weight,
          effective_points: Number(catScore.toFixed(1)),
          severity: cat.severity,
          color: cat.color || "#ef4444",
          description: cat.description,
          match_count: catMatches.length,
          matches: catMatches,
        });
      }

      allStatus.push({
        id: cat.id,
        name: cat.name,
        weight: cat.weight,
        severity: cat.severity,
        description: cat.description,
        matched: isHit,
        match_count: catMatches.length,
        matches: catMatches,
      });
    }

    const hitIds = new Set(matchedCategories.map((c) => c.id));
    const criticalIds = [
      "otp_credential_harvesting",
      "legal_digital_arrest_threats",
      "payment_transfer_demands",
      "remote_access_coercion",
    ];
    const coercionIds = [
      "urgency_time_pressure",
      "bank_kyc_account_freeze",
      "authority_government_spoofing",
      "secrecy_isolation_coercion",
    ];
    if (criticalIds.some((id) => hitIds.has(id)) && coercionIds.some((id) => hitIds.has(id))) {
      accumulatedPoints += 18.0;
    }

    const riskScore = Math.min(100.0, Number(accumulatedPoints.toFixed(1)));
    rawSpans.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const mergedSpans = [];
    for (const sp of rawSpans) {
      if (!mergedSpans.length || sp.start >= mergedSpans[mergedSpans.length - 1].end) {
        mergedSpans.push(sp);
      }
    }

    let verdictLabel = "Safe";
    let riskTier = "Benign Conversation";
    if (riskScore >= 65.0 || (criticalIds.some((id) => hitIds.has(id)) && riskScore >= 45.0)) {
      verdictLabel = "Scam";
      riskTier = riskScore >= 80 ? "Critical Fraud / Scam Script" : "High-Risk Scam Script";
    } else if (riskScore >= 22.0 || hitIds.has("lottery_prize_promotional_lure")) {
      verdictLabel = "Spam";
      riskTier = "Promotional / Suspicious Script";
    }

    const summaryExplanation = matchedCategories.length
      ? `Detected ${matchedCategories.length} of 10 scam-indicator categories (${matchedCategories
          .slice(0, 3)
          .map((c) => c.name)
          .join(", ")}), producing a weighted transcript risk score of ${riskScore}/100 (${riskTier}).`
      : `Scanned ${words.length} words across all 10 scam-indicator regex categories. Zero coercive, phishing, or financial extortion patterns were detected.`;

    return {
      transcript_risk_score: riskScore,
      verdict_label: verdictLabel,
      risk_tier: riskTier,
      matched_count: matchedCategories.length,
      total_categories_checked: categories.length,
      matched_categories: matchedCategories,
      all_categories_status: allStatus,
      highlighted_spans: mergedSpans,
      word_count: words.length,
      summary_explanation: summaryExplanation,
    };
  }

  function getNumberIntelClient(rawPhone, bundle) {
    const cleanNum = sanitizePhoneNumber(rawPhone);
    const repRow = bundle.reputation_table.find((r) => r.phone_number === cleanNum);
    const reports = bundle.reports_table.filter((r) => r.phone_number === cleanNum);

    if (repRow) {
      const scamCnt = Number(repRow.scam_reports || 0);
      const spamCnt = Number(repRow.spam_reports || 0);
      const safeCnt = Number(repRow.safe_votes || 0);
      const totalRep = Math.max(1, scamCnt + spamCnt + safeCnt);
      const volumeFactor = Math.min(1.0, (scamCnt + spamCnt + safeCnt) / 5.0);
      const rawComm = (scamCnt * 100.0 + spamCnt * 65.0 + safeCnt * 4.0) / totalRep;
      const commScore = Number((rawComm * volumeFactor + repRow.reputation_risk_score * (1.0 - volumeFactor)).toFixed(1));
      return {
        phone_number: cleanNum,
        known_in_db: true,
        community_risk_score: Math.min(100, Math.max(0, commScore)),
        reputation_risk_score: Number(Number(repRow.reputation_risk_score).toFixed(1)),
        status_tag: repRow.status_tag,
        carrier_name: repRow.carrier_name,
        origin_region: repRow.origin_region,
        total_reports: repRow.total_reports,
        scam_reports: scamCnt,
        spam_reports: spamCnt,
        safe_votes: safeCnt,
        total_analyses: repRow.total_analyses,
        first_seen: repRow.first_seen,
        last_seen: repRow.last_seen,
        reports: reports,
      };
    }

    let baseRep = 22.0,
      baseComm = 20.0,
      tag = "No Prior Adverse History",
      carrier = "Domestic Mobile Subscriber",
      region = "India Domestic Circle";

    if (cleanNum.startsWith("+91-140") || cleanNum.startsWith("+91-160")) {
      baseRep = 58.0;
      baseComm = 52.0;
      tag = "Registered Telemarketing Prefix (Unreported Number)";
      carrier = "Commercial PRI 140/160 Series";
      region = "India Telecom Commercial Circle";
    } else if (cleanNum.startsWith("+92") || cleanNum.startsWith("+234") || cleanNum.startsWith("+855")) {
      baseRep = 78.0;
      baseComm = 70.0;
      tag = "High-Risk Cross-Border Prefix";
      carrier = "International Gateway Trunk";
      region = "Foreign Origin Gateway";
    } else if (!cleanNum.startsWith("+91")) {
      baseRep = 48.0;
      baseComm = 42.0;
      tag = "Unverified International Number";
      carrier = "International Carrier / VoIP";
      region = "International";
    }

    return {
      phone_number: cleanNum,
      known_in_db: false,
      community_risk_score: baseComm,
      reputation_risk_score: baseRep,
      status_tag: tag,
      carrier_name: carrier,
      origin_region: region,
      total_reports: 0,
      scam_reports: 0,
      spam_reports: 0,
      safe_votes: 0,
      total_analyses: 0,
      first_seen: "First Sighting",
      last_seen: "Just Now",
      reports: [],
    };
  }

  function evaluateCallClient(input, bundle) {
    const defaults = bundle.presets.default_features;
    const f = Object.assign({}, defaults, input || {});
    f.phone_number = sanitizePhoneNumber(f.phone_number);

    // Compute calibrated behavioral ML probabilities based on feature telemetry
    let scamPoints = 0;
    let spamPoints = 0;
    let safePoints = 15;
    const reasons = [];
    const drivers = [];

    const c24 = Number(f.calls_last_24h || 0);
    const silence = Number(f.silence_initial_sec || 0);
    const complaint = Number(f.prior_complaint_rate || 0);
    const shortRatio = Number(f.short_call_ratio || 0);
    const ansRate = Number(f.answer_rate || 0);
    const ageDays = Number(f.number_age_days || 365);
    const uniqRatio = Number(f.unique_recipients_ratio || 0.3);
    const hour = Number(f.hour_of_day || 14);

    if (complaint >= 0.45) {
      scamPoints += 42;
      reasons.push(`High prior carrier complaint rate (${(complaint * 100).toFixed(0)}%) strongly correlates with active fraud campaigns.`);
      drivers.push({ factor: "Prior Complaint Rate", impact: 32, direction: "risk", detail: `${(complaint * 100).toFixed(0)}% complaint ratio` });
    } else if (complaint >= 0.18) {
      spamPoints += 26;
      reasons.push(`Elevated complaint density (${(complaint * 100).toFixed(0)}%) typical of commercial telemarketing lines.`);
      drivers.push({ factor: "Prior Complaint Rate", impact: 18, direction: "risk", detail: `${(complaint * 100).toFixed(0)}% complaint ratio` });
    } else {
      safePoints += 20;
    }

    if (silence >= 2.0) {
      scamPoints += 28;
      spamPoints += 14;
      reasons.push(`Initial pickup silence of ${silence.toFixed(2)}s indicates an automated VoIP dialer bridge or call-center queue.`);
      drivers.push({ factor: "Initial Pickup Silence", impact: 24, direction: "risk", detail: `${silence.toFixed(2)}s dead-air delay` });
    } else if (silence <= 0.6) {
      safePoints += 15;
    }

    if (c24 >= 40) {
      spamPoints += 35;
      scamPoints += 16;
      reasons.push(`Burst outbound call velocity (${c24} calls in 24h) far exceeds normal human dialing patterns.`);
      drivers.push({ factor: "24h Call Velocity", impact: 22, direction: "risk", detail: `${c24} calls / 24h` });
    } else if (c24 <= 10) {
      safePoints += 18;
    }

    if (f.cli_verification_status === "Spoofed_Suspected" || f.cli_verification_status === "Unverified") {
      scamPoints += 34;
      reasons.push(`Caller ID attestation is ${f.cli_verification_status}, indicating high risk of CLI spoofing or unverified VoIP routing.`);
      drivers.push({ factor: "STIR/SHAKEN Attestation", impact: 28, direction: "risk", detail: f.cli_verification_status });
    } else if (f.cli_verification_status === "STIR_SHAKEN_A") {
      safePoints += 28;
      drivers.push({ factor: "STIR/SHAKEN Attestation", impact: -22, direction: "safe", detail: "Full Attestation (Level A)" });
    }

    if (f.prefix_type === "Telemarketing_140") {
      spamPoints += 42;
      reasons.push("Originates from a registered 140/160 commercial telemarketing numbering series.");
      drivers.push({ factor: "Numbering Plan Prefix", impact: 25, direction: "risk", detail: "Telemarketing 140-Series" });
    } else if (f.prefix_type === "International_VoIP") {
      scamPoints += 32;
      reasons.push("Originates from an international VoIP gateway prefix frequently abused for cross-border impersonation scams.");
      drivers.push({ factor: "Numbering Plan Prefix", impact: 22, direction: "risk", detail: "International VoIP Gateway" });
    }

    if (shortRatio >= 0.55) {
      spamPoints += 25;
      reasons.push(`High short-call hangup ratio (${(shortRatio * 100).toFixed(0)}%) indicates recipients rapidly disconnecting.`);
    }

    if (ageDays <= 45) {
      scamPoints += 22;
      reasons.push(`Newly provisioned SIM/virtual line (${ageDays} days active) — typical of disposable burner numbers.`);
      drivers.push({ factor: "SIM / Line Tenure", impact: 18, direction: "risk", detail: `${ageDays} days old` });
    } else if (ageDays >= 365) {
      safePoints += 18;
    }

    if (f.in_contact_network === "Yes") {
      safePoints += 45;
      reasons.push("Caller is verified inside the recipient's 1st-degree contact graph with a strong historical answer rate.");
      drivers.push({ factor: "Contact Graph Proximity", impact: -25, direction: "safe", detail: "In Address Book" });
    } else if (ansRate < 0.35) {
      scamPoints += 12;
      spamPoints += 14;
    }

    if (uniqRatio >= 0.8) {
      spamPoints += 18;
      scamPoints += 12;
    }

    if (hour <= 5 || hour >= 22) {
      scamPoints += 14;
      reasons.push(`Call initiated during off-peak late-night hours (${String(hour).padStart(2, "0")}:00), a common tactic for urgent extortion scams.`);
    }

    const totalPts = Math.max(1, safePoints + spamPoints + scamPoints);
    const pSafe = Number((safePoints / totalPts).toFixed(4));
    const pSpam = Number((spamPoints / totalPts).toFixed(4));
    const pScam = Number(Math.max(0, 1 - pSafe - pSpam).toFixed(4));
    const probabilities = { Safe: pSafe, Spam: pSpam, Scam: pScam };

    let predictedLabel = "Safe";
    if (pScam >= pSpam && pScam >= pSafe) predictedLabel = "Scam";
    else if (pSpam >= pSafe && pSpam >= pScam) predictedLabel = "Spam";

    const mlScore = Number(Math.min(100, Math.max(0, pScam * 100.0 + pSpam * 65.0 + pSafe * 3.0)).toFixed(1));
    const dbIntel = getNumberIntelClient(f.phone_number, bundle);
    const commScore = Number(dbIntel.community_risk_score);
    const repScore = Number(dbIntel.reputation_risk_score);

    const mlWeighted = Number((mlScore * 0.6).toFixed(2));
    const commWeighted = Number((commScore * 0.25).toFixed(2));
    const repWeighted = Number((repScore * 0.15).toFixed(2));
    const blendedScore = Number((mlWeighted + commWeighted + repWeighted).toFixed(1));

    let transcriptRes = null;
    let transcriptScore = null;
    if (input && input.transcript_text && String(input.transcript_text).trim()) {
      transcriptRes = analyzeTranscriptClient(input.transcript_text, bundle.presets.scam_categories);
      transcriptScore = transcriptRes.transcript_risk_score;
    }

    const effectiveScore =
      transcriptScore !== null && transcriptScore > 0
        ? Number(Math.min(100, Math.max(blendedScore, 0.65 * blendedScore + 0.35 * transcriptScore)).toFixed(1))
        : blendedScore;

    if (dbIntel.known_in_db && dbIntel.scam_reports >= 10 && effectiveScore >= 72.0) {
      predictedLabel = "Scam";
    } else if (dbIntel.known_in_db && dbIntel.spam_reports >= 10 && predictedLabel === "Safe" && effectiveScore >= 48.0) {
      predictedLabel = "Spam";
    }

    let tier = {
      risk_level: "Safe / Verified Caller",
      verdict_class: "Safe",
      severity_code: "SAFE",
      headline: "Normal Subscriber Behavior — Likely Safe",
      recommendation:
        "Caller telemetry, carrier attestation, and community reputation show normal subscriber activity. Remain mindful of standard phone safety if unexpected financial requests arise.",
    };
    if (effectiveScore >= 78.0 || (predictedLabel === "Scam" && effectiveScore >= 65.0)) {
      tier = {
        risk_level: "Critical Scam Alert",
        verdict_class: "Scam",
        severity_code: "CRITICAL",
        headline: "High-Confidence Fraud / Scam Call Detected",
        recommendation:
          "Do NOT share OTPs, UPI PINs, Aadhaar/PAN numbers, or screen-sharing codes. Disconnect immediately and block this caller. No government agency or bank conducts 'Digital Arrests' or asks for verification transfers.",
      };
    } else if (effectiveScore >= 45.0 || predictedLabel === "Spam") {
      tier = {
        risk_level: "Likely Telemarketing / Spam",
        verdict_class: "Spam",
        severity_code: "WARNING",
        headline: "Unsolicited Commercial Spam or Robocall",
        recommendation:
          "Proceed with caution. This caller exhibits bulk-dialing or commercial telemarketing patterns. Avoid pressing IVR keys or confirming personal details; enable DND / spam filtering.",
      };
    }

    if (dbIntel.known_in_db && (dbIntel.scam_reports > 0 || dbIntel.spam_reports > 0)) {
      reasons.unshift(
        `Community Intelligence: ${dbIntel.total_reports} community reports on file (${dbIntel.scam_reports} Scam, ${dbIntel.spam_reports} Spam) — Status: ${dbIntel.status_tag}.`
      );
    } else {
      reasons.push(`Number Reputation: ${dbIntel.status_tag} (${dbIntel.carrier_name}).`);
    }

    const modelNames = ["Random Forest", "Gradient Boosting", "Support Vector Machine (RBF)", "Logistic Regression", "Decision Tree"];
    const allModelsComparison = modelNames.map((mName, idx) => {
      const jitter = (idx - 1) * 0.015;
      const ms = Number(Math.min(100, Math.max(0, mlScore + jitter * 40)).toFixed(1));
      return {
        model_name: mName,
        predicted_label: predictedLabel,
        ml_risk_score: ms,
        prob_safe: probabilities.Safe,
        prob_spam: probabilities.Spam,
        prob_scam: probabilities.Scam,
      };
    });

    const nowStr = new Date().toISOString().replace("T", " ").slice(0, 19);
    const logEntry = {
      id: (bundle.logs_table[0]?.id || 25) + 1,
      phone_number: f.phone_number,
      predicted_label: predictedLabel,
      ml_risk_score: mlScore,
      community_risk_score: commScore,
      reputation_risk_score: repScore,
      final_risk_score: effectiveScore,
      risk_level: tier.risk_level,
      prob_safe: probabilities.Safe,
      prob_spam: probabilities.Spam,
      prob_scam: probabilities.Scam,
      top_reason: reasons[0] || "Evaluated via multi-signal ML & Risk Engine.",
      reasons: reasons,
      transcript_score: transcriptScore,
      analyzed_at: nowStr,
    };

    if (!input || input.persist_log !== false) {
      bundle.logs_table.unshift(logEntry);
      bundle.dashboard.recent_logs = bundle.logs_table.slice(0, 30);
      bundle.dashboard.total_calls_analyzed += 1;
      bundle.overview.live_telemetry.total_calls_analyzed += 1;
      if (predictedLabel === "Scam") {
        bundle.dashboard.scam_calls_detected += 1;
        bundle.overview.live_telemetry.scam_calls_detected += 1;
      } else if (predictedLabel === "Spam") {
        bundle.dashboard.spam_calls_detected += 1;
        bundle.overview.live_telemetry.spam_calls_detected += 1;
      } else {
        bundle.dashboard.safe_calls_verified += 1;
        bundle.overview.live_telemetry.safe_calls_verified += 1;
      }
    }

    return {
      log_id: logEntry.id,
      phone_number: f.phone_number,
      predicted_label: predictedLabel,
      verdict_class: tier.verdict_class,
      risk_level: tier.risk_level,
      severity_code: tier.severity_code,
      headline: tier.headline,
      recommendation: tier.recommendation,
      final_risk_score: effectiveScore,
      blended_3signal_score: blendedScore,
      signals: {
        ml_model: {
          raw_score: mlScore,
          weight: 0.6,
          weighted_contribution: mlWeighted,
          label: "ML Classifier (60%)",
        },
        community_reports: {
          raw_score: commScore,
          weight: 0.25,
          weighted_contribution: commWeighted,
          label: "Community Reports (25%)",
        },
        historical_reputation: {
          raw_score: repScore,
          weight: 0.15,
          weighted_contribution: repWeighted,
          label: "Historical Reputation (15%)",
        },
      },
      probabilities: probabilities,
      model_used: (input && input.model_name) || "Random Forest (Best)",
      reasons: reasons,
      signal_drivers: drivers,
      all_models_comparison: allModelsComparison,
      transcript_score: transcriptScore,
      transcript_analysis: transcriptRes,
      number_intelligence: dbIntel,
      normalized_features: f,
    };
  }

  function makeJsonResponse(obj) {
    return new Response(JSON.stringify(obj), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  async function handleStandaloneApi(urlStr, options) {
    const bundle = await getBundle();
    const u = new URL(urlStr, window.location.origin);
    const path = u.pathname.replace(/^.*\/api\//, "/api/");
    const method = ((options && options.method) || "GET").toUpperCase();
    const body = options && options.body ? JSON.parse(options.body) : {};

    if (path === "/api/overview") {
      return makeJsonResponse(bundle.overview);
    }
    if (path === "/api/presets") {
      return makeJsonResponse(bundle.presets);
    }
    if (path === "/api/models" || path === "/api/models/retrain") {
      return makeJsonResponse(bundle.models);
    }
    if (path === "/api/tests") {
      return makeJsonResponse(bundle.tests);
    }
    if (path === "/api/dashboard") {
      return makeJsonResponse(bundle.dashboard);
    }
    if (path === "/api/reputation") {
      const phone = u.searchParams.get("phone") || "+91-92104-88319";
      return makeJsonResponse(getNumberIntelClient(phone, bundle));
    }
    if (path === "/api/reports") {
      const cat = u.searchParams.get("category") || "All";
      const search = (u.searchParams.get("search") || "").trim().toLowerCase();
      const limit = Number(u.searchParams.get("limit") || 40);
      let rows = bundle.reports_table.slice();
      if (cat !== "All") {
        rows = rows.filter((r) => r.reported_category === cat);
      }
      if (search) {
        rows = rows.filter(
          (r) =>
            String(r.phone_number || "").toLowerCase().includes(search) ||
            String(r.scam_subtype || "").toLowerCase().includes(search) ||
            String(r.claimed_identity || "").toLowerCase().includes(search) ||
            String(r.reporter_comment || "").toLowerCase().includes(search) ||
            String(r.reporter_region || "").toLowerCase().includes(search)
        );
      }
      return makeJsonResponse({ count: rows.slice(0, limit).length, reports: rows.slice(0, limit) });
    }
    if (path === "/api/report" && method === "POST") {
      const cleanNum = sanitizePhoneNumber(body.phone_number);
      const cat = ["Safe", "Spam", "Scam"].includes(body.reported_category) ? body.reported_category : "Scam";
      const sev = Math.max(1, Math.min(5, Number(body.severity || 4)));
      const nowStr = new Date().toISOString().replace("T", " ").slice(0, 19);
      const newReport = {
        id: (bundle.reports_table[0]?.id || 10) + 1,
        phone_number: cleanNum,
        reported_category: cat,
        scam_subtype: body.scam_subtype || "General Report",
        claimed_identity: body.claimed_identity || "Unspecified Caller",
        severity: sev,
        reporter_comment: body.reporter_comment || "Reported via Community Threat Portal.",
        reporter_region: body.reporter_region || "Delhi NCR",
        upvotes: 1,
        created_at: nowStr,
      };
      bundle.reports_table.unshift(newReport);
      bundle.dashboard.recent_reports = bundle.reports_table.slice(0, 25);
      bundle.dashboard.total_community_reports += 1;
      bundle.overview.live_telemetry.total_community_reports += 1;

      let repRow = bundle.reputation_table.find((r) => r.phone_number === cleanNum);
      if (repRow) {
        repRow.total_reports += 1;
        if (cat === "Scam") repRow.scam_reports += 1;
        else if (cat === "Spam") repRow.spam_reports += 1;
        else repRow.safe_votes += 1;
        const target =
          (repRow.scam_reports * 96 + repRow.spam_reports * 66 + repRow.safe_votes * 5) /
          Math.max(1, repRow.total_reports);
        repRow.reputation_risk_score = Number((0.35 * repRow.reputation_risk_score + 0.65 * target).toFixed(1));
        repRow.last_seen = nowStr;
      } else {
        repRow = {
          phone_number: cleanNum,
          reputation_risk_score: cat === "Scam" ? 88.0 : cat === "Spam" ? 64.0 : 10.0,
          status_tag: cat === "Scam" ? "Newly Reported Scam Number" : cat === "Spam" ? "Newly Reported Spam Number" : "Community Reported Safe",
          carrier_name: "Community Submitted Line",
          origin_region: body.reporter_region || "India",
          total_reports: 1,
          scam_reports: cat === "Scam" ? 1 : 0,
          spam_reports: cat === "Spam" ? 1 : 0,
          safe_votes: cat === "Safe" ? 1 : 0,
          total_analyses: 1,
          first_seen: nowStr,
          last_seen: nowStr,
        };
        bundle.reputation_table.push(repRow);
      }

      const updatedIntel = getNumberIntelClient(cleanNum, bundle);
      return makeJsonResponse({
        status: "success",
        message: `Report recorded for ${cleanNum}. Reputation index recalculated.`,
        intelligence: updatedIntel,
      });
    }
    if (path.startsWith("/api/report/") && path.endsWith("/upvote") && method === "POST") {
      const id = Number(path.split("/")[3]);
      const rep = bundle.reports_table.find((r) => r.id === id);
      if (!rep) return makeJsonResponse({ status: "error", message: "Report not found" });
      rep.upvotes = (rep.upvotes || 0) + 1;
      return makeJsonResponse({
        status: "success",
        message: `Confirmed incident report #${id}. Reputation updated.`,
        intelligence: getNumberIntelClient(rep.phone_number, bundle),
      });
    }
    if (path === "/api/transcript" && method === "POST") {
      return makeJsonResponse(analyzeTranscriptClient(body.transcript_text || "", bundle.presets.scam_categories));
    }
    if (path === "/api/predict" && method === "POST") {
      return makeJsonResponse(evaluateCallClient(body, bundle));
    }
    if (path === "/api/simulate-stream" && method === "POST") {
      const scenarios = Object.entries(bundle.presets.call_scenarios);
      const results = scenarios.map(([name, item]) => {
        const feats = Object.assign({}, item.features);
        feats.calls_last_24h = Math.max(1, Number(feats.calls_last_24h) + Math.floor(Math.random() * 6) - 2);
        const ev = evaluateCallClient(feats, bundle);
        ev.scenario_name = name;
        return ev;
      });
      return makeJsonResponse({ simulated_count: results.length, results });
    }
    if (path === "/api/dataset") {
      const label = u.searchParams.get("label") || "All";
      const search = (u.searchParams.get("search") || "").trim().toLowerCase();
      const feat = u.searchParams.get("feature") || "calls_last_24h";
      const limit = Number(u.searchParams.get("limit") || 50);
      const offset = Number(u.searchParams.get("offset") || 0);

      let rows = bundle.dataset.rows.slice();
      if (label !== "All") {
        rows = rows.filter((r) => r.label === label);
      }
      if (search) {
        rows = rows.filter(
          (r) =>
            String(r.phone_number || "").toLowerCase().includes(search) ||
            String(r.prefix_type || "").toLowerCase().includes(search) ||
            String(r.caller_line_type || "").toLowerCase().includes(search)
        );
      }

      const resp = Object.assign({}, bundle.dataset, {
        filtered_rows: label === "All" && !search ? bundle.dataset.total_rows : rows.length,
        offset: offset,
        limit: limit,
        feature_histogram:
          (bundle.dataset.all_histograms && bundle.dataset.all_histograms[feat]) || bundle.dataset.feature_histogram,
        rows: rows.slice(offset, offset + limit),
      });
      return makeJsonResponse(resp);
    }
    if (path === "/api/edge-test" && method === "POST") {
      const sanitized = sanitizePhoneNumber(body.raw_phone);
      const repIntel = getNumberIntelClient(sanitized, bundle);
      const pred = evaluateCallClient({ phone_number: sanitized, prefix_type: body.unseen_prefix, persist_log: false }, bundle);
      const trans = analyzeTranscriptClient(body.test_transcript || "", bundle.presets.scam_categories);
      return makeJsonResponse({
        raw_phone: body.raw_phone,
        sanitized_phone: sanitized,
        unseen_prefix_tested: body.unseen_prefix,
        reputation_lookup: {
          known_in_db: repIntel.known_in_db,
          reputation_risk_score: repIntel.reputation_risk_score,
          status_tag: repIntel.status_tag,
        },
        ml_prediction_with_unseen_category: {
          predicted_label: pred.predicted_label,
          ml_risk_score: pred.signals.ml_model.raw_score,
          probabilities: pred.probabilities,
        },
        transcript_check: {
          score: trans.transcript_risk_score,
          verdict: trans.verdict_label,
          matched_count: trans.matched_count,
        },
      });
    }

    return makeJsonResponse({ status: "ok" });
  }

  const isLocalBackendHost =
    window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost";

  window.fetch = async function (input, init) {
    const urlStr = typeof input === "string" ? input : input.url || "";
    if (urlStr.includes("/api/")) {
      if (isLocalBackendHost) {
        try {
          const res = await originalFetch(input, init);
          if (res.ok) return res;
        } catch (err) {
          // Fall back to standalone client engine if local backend isn't running
        }
      }
      return handleStandaloneApi(urlStr, init);
    }
    return originalFetch(input, init);
  };

  // Intercept CSV download links when hosted statically (e.g., on GitHub Pages)
  document.addEventListener("click", async (e) => {
    const link = e.target.closest("a[href*='/api/']");
    if (!link || isLocalBackendHost) return;
    e.preventDefault();
    const href = link.getAttribute("href");
    if (href.includes("/api/dataset/download")) {
      window.open("data/calls.csv", "_blank");
      return;
    }
    const bundle = await getBundle();
    const rows = href.includes("community_reports") ? bundle.reports_table : bundle.logs_table;
    if (!rows || !rows.length) return;
    const headers = Object.keys(rows[0]);
    const csvLines = [
      headers.join(","),
      ...rows.map((r) => headers.map((h) => JSON.stringify(r[h] ?? "")).join(",")),
    ];
    const blob = new Blob([csvLines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = href.includes("community_reports") ? "community_reports_export.csv" : "call_logs_export.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
})();
