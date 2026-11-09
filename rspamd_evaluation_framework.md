# rspamd Evaluation Framework for eFa5

## Evaluation Date: 2026-11-03
**Project**: eFa5 Perl→Python Migration  
**Sprint**: 17  
**Goal**: Evaluate rspamd as potential replacement for current mail security components (opendkim, opendmarc, pyspf)

---

## 1. CURRENT MAIL SECURITY ARCHITECTURE

### Components Currently in Use

| Component | Function | Version | Status |
|-----------|----------|---------|--------|
| **opendkim** | DKIM Signing/Verification | >= 2.10.x | ✅ Active |
| **opendmarc** | DMARC Validation/Reporting | >= 1.3.x | ✅ Active |
| **pyspf** | SPF Validation | >= 2.2.x | ✅ Active |
| **SpamAssassin** | Bayesian Filtering + Rules | >= 3.4.x | ✅ Active |
| **ClamAV** | Antivirus Scanning | >= 0.104.x | ✅ Active |
| **rspamd (current)** | Not installed | N/A | ❌ Not evaluated |

### eFa Integration Points

| Component | Integration Method | Configuration | Dependencies |
|-----------|-------------------|---------------|--------------|
| **opendkim** | Milter module | `/etc/opendkim/KeyTable`, `/etc/opendkim/SigningTable` | Perl-Carp, Perl-IO-Socket-SSL (via SPEC) |
| **opendmarc** | Milter module | `/etc/mailmarc.conf` | Perl-File-Handle, Perl-Socket |
| **pyspf** | SpamAssassin spf module | Integrated into SpamAssassin rules | python3-pyspf (Sprint 9 replaced php-json) |
| **SpamAssassin** | Primary MTA filtering | `/etc/mail/spamassassin/` | perl-Digest-MD5, perl-Digest-SHA (Sprints 17 cleanup) |

---

## 2. rspamd OVERVIEW

### What is rspamd?

**rspamd** is a fast, free, and open-source spam filtering system. It provides:

| Feature | Description |
|---------|-------------|
| **Spam Scoring** | Bayesian + adaptive scoring |
| **DKIM** | Built-in signing and verification |
| **SPF** | Built-in validation |
| **DMARC** | Built-in validation + reporting |
| **RBL** | Real-time blacklist checking |
| **OpenTags** | Standardized spam/ham reporting |
| **Multiple VPS support** | Shared reputation across servers |
| **Web UI** | Centralized configuration and monitoring |
| **Lua scripting** | Custom rule implementation |
| **Statistics** | Spam/ham learning statistics |

### rspamd Architecture

```
+----------------------+      +----------------------+
|   Mail User Agent    |      |   Mail Delivery Agent|
+----------+-----------+      +----------+-----------+
             |                          |
             v                          v
+----------------------+      +----------------------+
|   rspamd Worker      |      |   Postfix / OpenSMTPD|
+----------+-----------+      +----------------------+
             |                          |
             v                          v
+----------------------+      +----------------------+
|   Configuration      |      |   Logging/Statistics |
|   (local.d/)         |      |   (Redis / JSON)     |
+----------------------+      +----------------------+
                  \____________/
                           |
                                  v
                           +----------------------+
                           |   rspamd Web UI      |
                           |   (port 11334)       |
                           +----------------------+
```

---

## 3. FEATURE COMPARISON: rspamd vs. Current Solution

### DKIM Comparison

| Feature | opendkim | rspamd | Decision Notes |
|---------|----------|--------|---------------|
| **DKIM Signing** | ✅ Supported | ✅ Built-in | rspamd can replace opendkim |
| **DKIM Verification** | ✅ Supported | ✅ Built-in | rspamd can replace opendkim verification |
| **Key Management** | File-based (`KeyTable`) | Redis-backed + File-based | rspamd offers more flexible storage |
| **Selector Rotation** | Manual (`SigningTable`) | Automatic + Manual | rspamd easier to manage |
| **eFa Integration** | Currently configured | Would need configuration migration | Moderate effort |

### SPF Comparison

| Feature | pyspf | rspamd | Decision Notes |
|---------|-------|--------|---------------|
| **SPF Validation** | ✅ Supported (via perl-Mail-SPF → pyspf) | ✅ Built-in | rspamd eliminates need for separate pyspf |
| **SPF Error Handling** | Configuration-dependent | Built-in policies | rspamd more consistent |
| **eFa Integration** | Currently via SpamAssassin rules | Would replace SpamAssassin SPF checks | Low-Medium effort |

### DMARC Comparison

| Feature | opendmarc | rspamd | Decision Notes |
|---------|-----------|--------|---------------|
| **DMARC Validation** | ✅ Supported | ✅ Built-in | rspamd can replace opendmarc |
| **DMARC Reporting** | ✅ Supported (aggregate + forensic) | ✅ Built-in (much better) | **Major advantage** of rspamd |
| **Policy Enforcement** | Configuration-dependent | Built-in policies | rspamd more straightforward |
| **eFa Integration** | Currently configured | Would need configuration migration | Moderate effort |

### Bayesian Filtering Comparison

| Feature | SpamAssassin | rspamd | Decision Notes |
|---------|--------------|--------|---------------|
| **Bayesian Filtering** | ✅ Supported (core feature) | ✅ Built-in (integrated) | Similar functionality |
| **Training Mechanism** | Manual `sa-learn` | Automatic (user actions: spam/ham) | rspamd more automated |
| **Integration with MTA** | Well-established (Postfix/Exim) | Well-established (Postfix) | Both mature |
| **eFa Integration** | Core component | Would replace core filtering | High effort but potential benefit |

### RBL Comparison

| Feature | Current | rspamd | Decision Notes |
|---------|---------|--------|---------------|
| **RBL Checking** | ✅ Supported (via SpamAssassin rules) | ✅ Built-in | Both support, similar effectiveness |
| **Configuration** | Rule-based | Rule-based + built-in lists | Comparable |
| **eFa Integration** | Already configured | Would replace rule set | Low effort |

### Web UI Comparison

| Feature | Current (CLI only) | rspamd | Decision Notes |
|---------|-------------------|--------|---------------|
| **Configuration UI** | ❌ CLI only (complex scripts) | ✅ Built-in Web UI | **Major advantage** - non-technical admin possible |
| **Rule Management** | Via Perl/Python scripts | Via Web UI + Lua rules | rspamd more accessible |
| **Statistics Viewing** | Via CLI commands | Via Web dashboards | rspamd more user-friendly |
| **Mobile Access** | ❌ Difficult | ✅ Responsive Web UI | **Major advantage** |
| **eFa Integration** | Currently CLI-focused | Would add Web UI layer | High benefit, Medium implementation |

### Lua Scripting Comparison

| Feature | Current | rspamd | Decision Notes |
|---------|---------|--------|---------------|
| **Custom Rules** | Perl/Python scripts | Lua scripts (built-in) | Both Turing-complete |
| **Learning Capability** | Limited (manual sa-learn) | Built-in (Bayes + autolearning) | rspamd more automated |
| **eFa Integration** | Custom scripts exist | Would rewrite in Lua | Medium effort, long-term benefit |

---

## 4. MIGRATION PATH ANALYSIS

### Option A: Full rspamd Replacement

| Aspect | Details |
|--------|---------|
| **Components to Replace** | opendkim → rspamd DKIM, opendmarc → rspamd DMARC, pyspf → rspamd SPF, SpamAssassin Bayesian → rspamd integrated |
| **Complexity** | High (all mail security components migrate) |
| **Benefits** | - Single solution instead of 4-5 components<br>- Web UI for administration<br>- Built-in Bayes + RBL + DKIM + SPF + DMARC<br>- Better learning automation<br>- Modern architecture |
| **Risks** | - Migration of all rules/configurations<br>- Potential feature gaps during transition<br>- Testing required for all mail flows |
| **Timeline** | 2-3 weeks for evaluation + 4-6 weeks for implementation |
| **Go/No-Go Criteria** | - All existing rules must migrate successfully<br>- Web UI must provide equivalent functionality<br>- No spam score regression |

### Option B: rspamd + Current Components (Hybrid)

| Aspect | Details |
|--------|---------|
| **Components** | rspamd for new rules/learning, keep opendkim/opendmarc/pyspf for existing |
| **Complexity** | Medium (parallel operation during transition) |
| **Benefits** | - Lower risk - can revert if issues arise<br>- Gradual migration possible<br>- Web UI for new rules only |
| **Risks** | - Dual administration burden<br>- Potential conflicts between systems<br>- Inconsistent scoring |
| **Timeline** | 1-2 weeks for evaluation + 2-4 weeks for hybrid setup |
| **Go/No-Go Criteria** | - Both systems can coexist<br>- Web UI provides added value<br>- No significant performance impact |

### Option C: Keep Current Solution, Enhance

| Aspect | Details |
|--------|---------|
| **Components** | Keep opendkim/opendmarc/pyspf/SpamAssassin as-is |
| **Complexity** | Low (no migration) |
| **Benefits** | - No migration risk<br>- If it ain't broke, don't fix<br>- Stable, proven solution |
| **Risks** | - Missing Web UI advantage<br>- Missing modern features (autolearning, remoteespotting)<br>- Technical debt accumulation |
| **Timeline** | Evaluation only (no implementation) |
| **Go/No-Go Criteria** | - Decision documented for future consideration |

---

## 5. IMPLEMENTATION REQUIREMENTS

### If Option A (Full Replacement): Selected

| Requirement | Details |
|-------------|---------|
| **Postfix Configuration** | Integrate rspamd socket (`milter_rspamd`), update headers |
| **SpamAssassin Integration** | Decide: replace entirely or keep parallel for Bayesian |
| **rspamd Configuration** | `/etc/rspamd/local.d/` - adjust spam scores, add custom Lua rules |
| **DKIM Key Management** | Migrate existing keys from opendkim format to rspamd format |
| **DMARC Configuration** | Migrate existing opendmarc configuration to rspamd local.d/dmarc |
| **SPF Configuration** | Migrate existing pyspf/sa_spf_rules to rspamd configuration |
| **rspamd Web UI** | Enable and configure (`webui true` in local.d/settings.conf) |
| **rspamd Learning** | Configure autolearning (`learn ham`, `learn spam`) |
| **Testing Framework** | Set up test mail accounts, verify all mail flows |

### If Option B (Hybrid): Selected

| Requirement | Details |
|-------------|---------|
| **rspamd Installation** | Install alongside current components |
| **Parallel Operation** | Configure both systems to process same mail |
| **Rule Migration** | Migrate selected rules to rspamd, keep rest on current |
| **Web UI** | Enable rspamd Web UI for new rule management |
| **Transition Period** | 4-6 weeks with monitoring and validation |
| **Cutover Plan** | When to switch fully to rspamd or keep hybrid |

### If Option C (Keep Current): Selected

| Requirement | Details |
|-------------|---------|
| **No Migration** | Document evaluation, keep current solution |
| **Future Consideration** | Re-evaluate in 12-18 months |
| **Documentation** | Complete evaluation report for future reference |
| **No Implementation Costs** | Zero implementation effort |

---

## 6. EVALUATION CHECKLIST

### Must-Have Features (Pass/Fail)

- [ ] DKIM signing and verification functionality
- [ ] SPF validation functionality
- [ ] DMARC validation + reporting functionality
- [ ] Bayesian filtering capability
- [ ] RBL checking capability
- [ ] Compatibility with eFa's Postfix configuration
- [ ] Compatibility with eFa's SpamAssassin configuration
- [ ] Available in eFa's supported platform(s) (CentOS/RHEL/Debian/FreeBSD)
- [ ] Web UI administration interface
- [ ] Performance acceptable (no more than 2x current filtering latency)

### Nice-to-Have Features

- [ ] OpenTags support
- [ ] Remoteespotting (shared reputation)
- [ ] Advanced statistical learning
- [ ] Multiple VPS support
- [ ] Mobile-responsive Web UI
- [ ] Lua scripting for custom rules
- [ ] Integration with ticketing systems
- [ ] API access for automation

### Nice-to-Have But Not Essential

- [ ] Integration with ticketing systems
- [ ] API access for automation
- [ ] Advanced reporting beyond built-in statistics

---

## 7. EVALUATION TIMELINE

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Phase 1: Installation & Setup** | 3 days | rspamd installed, basic configuration |
| **Phase 2: Feature Testing** | 5 days | Test report for each feature (DKIM, SPF, DMARC, Bayes, RBL) |
| **Phase 3: Integration Testing** | 5 days | Test with actual eFa mail flows, verify no regressions |
| **Phase 4: Web UI Evaluation** | 3 days | Test Web UI usability, rule management |
| **Phase 5: Decision & Reporting** | 2 days | Complete evaluation report with go/no-go recommendation |

**Total Estimated Duration**: 18 working days (approximately 4.5 weeks)

---

## 7. RECOMMENDATION PROCESS

### Go/No-Go Criteria

| Criterion | Weight | Pass Condition |
|-----------|--------|----------------|
| **All Must-Have features functional** | 40% | Every must-have feature tested and working |
| **No significant spam score regression** | 25% | Spam/ham classification comparable to current solution |
| **Web UI provides clear advantage** | 20% | Web UI demonstrably easier than CLI for common tasks |
| **Migration complexity acceptable** | 10% | Migration can be completed within 6 weeks |
| **Cost (no additional licensing)** | 5% | Free/open-source, no new costs |

### Decision Matrix

| Scenario | Recommendation |
|----------|----------------|
| **All must-have pass + web UI advantage** | **Go - Full rspamd replacement** |
| **All must-have pass, no web UI advantage** | **Go - Hybrid (rspamd + current)** |
| **Some must-have fail, others pass** | **No-Go - Keep current, fix gaps, re-evaluate later** |
| **Uncertain due to testing limitations** | **No-Go - Additional 2-week testing, re-evaluate** |

---

## 8. NEXT STEPS

### Immediate (Next 3 Days)

1. **Install rspamd in test environment**
   - `pkg install rspamd` (FreeBSD) or appropriate package manager
   - Configure basic settings
   - Verify service starts

2. **Feature Testing Setup**
   - Create test mail accounts
   - Prepare test spam/ham messages
   - Document current scoring with current solution

3. **Initial Feature Comparison**
   - Test DKIM signing/verification
   - Test SPF validation
   - Test DMARC validation + reporting
   - Test Bayesian filtering

### Short-Term (Next 2 Weeks)

4. **Complete Feature Comparison Matrix**
   - Document all must-have and nice-to-have features
   - Score each feature (pass/fail or rating 1-5)
   - Compare side-by-side current vs. rspamd

5. **Integration Testing**
   - Configure rspamd with eFa Postfix
   - Test actual mail flow
   - Verify no regressions in spam detection
   - Document any issues or configuration requirements

6. **Decision Preparation**
   - Compile evaluation results
   - Draft go/no-go recommendation
   - Identify migration requirements if going forward

### Medium-Term (Next 4-6 Weeks)

7. **Implementation Planning**
   - Based on decision, create implementation plan
   - Schedule migration window
   - Prepare rollback plan

8. **Implementation (if Go selected)**
   - Migrate configurations
   - Test thoroughly
   - Cutover to rspamd
   - Monitor for 2-4 weeks

9. **Final Documentation**
   - Update SPEC files
   - Update Changelog
   - Document lessons learned
   - Plan future enhancements

---

## 9. ROLLBACK PLAN

### If Migration Fails

| Step | Action |
|--------|--------|
| **1. Immediate** | Disable rspamd milters in Postfix |
| **2. Re-enable** | Re-enable opendkim, opendmarc, pyspf, SpamAssassin |
| **3. Verify** | Confirm all mail flows resume normally |
| **4. Analyze** | Document what went wrong, what configuration issues |
| **5. Decision** | Re-evaluate: keep current, try hybrid, or different approach |
| **6. Documentation** | Lessons learned for future evaluation |

### Backup Preservation

| Item | Action |
|--------|--------|
| **Current configs** | Full backup of /etc/opendkim, /etc/opendmarc, /etc/mail/spamassassin |
| **Current rules** | Save all custom SpamAssassin rules, Bayes training |
| **Current scoring** | Document current spam/ham classification baseline |
| **Current performance** | Document current latency and resource usage |

---

## 10. CONCLUSION

### Evaluation Summary

The rspamd evaluation will determine if rspamd provides sufficient advantage over the current opendkim/opendmarc/pyspf/SpamAssassin solution to justify the migration effort.

### Key Success Factors

1. **Feature Parity**: All current functionality must be available in rspamd
2. **No Regression**: Spam detection must not worsen
3. **Usability Advantage**: Web UI must provide clear benefit over CLI-only
4. **Migration Acceptance**: Complexity must be within acceptable limits
5. **Cost**: Must be free/open-source (no new licensing costs)

### Next Steps After Evaluation

| Decision | Next Action |
|----------|-------------|
| **Go (Full Replacement)** | Begin implementation planning, schedule migration |
| **Go (Hybrid)** | Set up parallel operation, plan gradual migration |
| **No-Go** | Document evaluation, keep current solution, re-evaluate in 12-18 months |

---

*Evaluation Framework Created: 2026-11-03*  
*Sprint: 17 of 17+*  
*Project: eFa5 Perl→Python Migration*  
*Next Step: Begin Phase 1 - Installation & Setup*