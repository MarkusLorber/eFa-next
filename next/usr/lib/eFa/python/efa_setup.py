# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The setup variant of eFa-next (guided or manual): the texts A to F of the setup wizard and of Re-Setup, the digest of each
text that was confirmed, the frameworks with what each one raises, and the plan of a change (raise only, never lower).
Pure logic: efa-init.py, efactl and efa-web.py use it. English is the source, the German texts are in the catalog (de.po)."""
import hashlib
import html
import re
import time

import efa_harden

VARIANTS = ('guided', 'manual')
FILE = '/etc/eFa/setup-variant.json'

NOTICE_TITLE = 'Important note on presets and recommendations'
NOTICE = (
    'Based on what you enter in this wizard, eFa-next can offer you presets and recommendations, for example on encryption, login, '
    'logging, retention periods and external services. These suggestions are an aid, made to the best of our knowledge. To the maximum '
    'extent permitted by applicable law, eFa-next gives no warranty that they are correct, complete or up to date.',
    'The presets and recommendations are not legally binding. They are not legal advice and not a binding statement about which laws, '
    'standards or frameworks apply to your organisation or how to implement them technically. Selecting a framework in eFa-next does not '
    'mean that your system then complies with it or can be certified against it. Laws, standards and their interpretation change, and '
    'eFa-next cannot always reflect these changes completely or in time.',
    'You are responsible for operating the system and for checking whether the settings are suitable and sufficient for your organisation. '
    'For legally binding information on technical settings and frameworks, please consult appropriate experts, for example in information '
    'security and data protection, and have specialised lawyers advise you and review the implementation.')
NOTICE_CONFIRM = ('I have read this note and confirm it: the presets and recommendations of eFa-next are a non-binding aid and not legal '
                  'advice. For legally binding information on technical settings and frameworks, I will consult experts myself and obtain '
                  'specialised legal advice and review.')
VARIANT_TITLE = 'How do you want to set up eFa-next?'
VARIANT_TEXT = {
    'guided': ('Guided (recommended)', 'eFa-next asks about your environment (EU link and frameworks) and suggests matching, secure presets. '
                                       'Two-factor login is mandatory for the main administrator and the console administrator.'),
    'manual': ('Manual', 'You set everything yourself. eFa-next asks about the EU link here too. The eFa-next security minimum also applies '
                         'and cannot be lowered.')}
EULINK_TITLE = 'Is eFa-next used for a company or organisation with an EU link?'
EULINK_TEXT = ('There is an EU link, for example, if your organisation has its seat or a branch in the EU, if eFa-next runs in the EU, or if '
               'your organisation offers goods or services to people in the EU or monitors their behaviour (Art. 3 GDPR).')
EULINK_YES = 'eFa-next only allows settings it classifies as compatible with the GDPR and EU rules. You can always choose stricter settings.'
NOEU_TITLE = 'Confirmation: no EU link'
NOEU = (
    'You state that your organisation is not subject to the laws and regulations of the EU. You can then choose all eFa-next settings freely, '
    'including ones that are not compatible with the GDPR or other EU rules, for example backup targets or report services outside the EU. '
    'The eFa-next security minimum still applies and cannot be lowered.',
    'Please note: EU law can also apply to organisations outside the EU, for example if they offer goods or services to people in the EU '
    '(Art. 3(2) GDPR). As soon as an EU link arises, for example through a domain with an EU link, eFa-next locks the affected settings again.')
NOEU_CONFIRM = ('I confirm that my organisation is not subject to the laws and regulations of the EU. I am aware of the possible legal and '
                'technical risks and bear them myself.')
NOEU_TYPE = 'To confirm, type: {phrase}'
# The phrase is typed in the language of the page; either language counts.
PHRASES = {'en': 'at my own risk', 'de': 'auf eigenes Risiko'}
FRAMEWORKS_TITLE = 'Which frameworks apply to your organisation?'
FRAMEWORKS_TEXT = ('Click all that apply. You can change this later under "Security & admin". The selection only drives suggestions, for '
                   'example stricter presets and notes on the dashboard. It does not replace checking whether a framework applies to you.')
FRAMEWORKS_OTHER = 'Other (free text, as a note only)'
TOTP_TITLE = 'Two-factor login for the main administrator'
TOTP_TEXT = ('In the guided setup, two-factor login (TOTP) is mandatory for the main administrator and the console administrator. Scan the '
             'QR code with an authenticator app and enter the six-digit code shown. Keep the recovery codes in a safe place. Without the app '
             'and without these codes, login is only possible from the local console (efactl).')
NONBINDING = 'Non-binding suggestion'
# HARD-W: the security standards of the setup, the same list and texts as the hardening wizard (efa_harden, standards.json).
STANDARDS_TEXT = ('Choose the standards this server should meet. The setup sets the strictest value of all chosen ones: TLS, the '
                  'operating system and the switches of eFa-next. Port 25 stays opportunistic. None chosen: the defaults of eFa-next stay.')
SSH_LATER = ('SSH profile BSI: not set by the setup. Set it later in the hardening wizard (Security standards) and log in again over SSH '
             'within 10 minutes to confirm it.')

# Raises: admin_2fa (2FA required for every admin role), audit_days (keep the audit log at least so long), tls (the TLS profiles
# that count; any other becomes bsi), security_daily (security self check every day). A framework without a setting of its own
# in eFa-next has a note only: no pretended protection.
_NIS2 = {'admin_2fa': True, 'audit_days': 365, 'tls': ('bsi', 'mozilla-modern')}
_ISO = {'admin_2fa': True, 'security_daily': True}
_INTL = {'admin_2fa': True, 'audit_days': 365, 'tls': ('bsi', 'rfc9325', 'mozilla-modern')}
NIS2_NOTE = 'NIS2 incident records and reports: Users, NIS2 incidents.'
BSI_NOTE = 'SSH after BSI TR-02102-4: hardening report, efactl ssh-profile-set --mode bsi.'
ISO_NOTE = 'Record of processing and TOM: Users, Privacy evidence.'
RETENTION_NOTE = ('eFa-next is not an archive that meets the legal retention rules; keep business mail in an archive (Archive handover). '
                  'Do not set retention periods below the legal ones.')
NO_SETTING_NOTE = 'eFa-next has no own setting for this framework; the EU question and the security minimum apply.'
GROUPS = ('EU and countries', 'Standards and sectors', 'Retention', 'Outside the EU')
FRAMEWORKS = {
    'gdpr': ('GDPR', 0, {}, 'Always selected with an EU link.'),
    'nis2': ('NIS2 (Directive (EU) 2022/2555)', 0, _NIS2, NIS2_NOTE),
    'nisg2026': ('NISG 2026 (AT)', 0, _NIS2, NIS2_NOTE),
    'nis2umsucg': ('NIS2UmsuCG/BSIG (DE)', 0, _NIS2, NIS2_NOTE),
    'dora': ('DORA (Regulation (EU) 2022/2554)', 0, {**_NIS2, 'audit_days': 1825},
             'Suggested: admin access only from allowed addresses (Security, Admin access).'),
    'tkg2021': ('TKG 2021 (AT)', 0, {}, NO_SETTING_NOTE),
    'tdddg': ('TDDDG (DE)', 0, {}, NO_SETTING_NOTE),
    'kritis': ('KRITIS (DE)', 0, _NIS2, NIS2_NOTE),
    'bsi-grundschutz': ('BSI IT-Grundschutz', 1, {'tls': ('bsi',)}, BSI_NOTE),
    'bsi-tr02102': ('BSI TR-02102', 1, {'tls': ('bsi',)}, BSI_NOTE),
    'iso27001': ('ISO/IEC 27001', 1, _ISO, ISO_NOTE),
    'iso27701': ('ISO/IEC 27701', 1, _ISO, ISO_NOTE),
    'tisax': ('TISAX', 1, _ISO, ISO_NOTE),
    'enisa-ehealth': ('ENISA eHealth', 1, {}, NO_SETTING_NOTE),
    'bao-ugb': ('BAO/UGB (AT)', 2, {}, RETENTION_NOTE),
    'hgb-ao-gobd': ('HGB/AO/GoBD (DE)', 2, {}, RETENTION_NOTE),
    'revdsg': ('revDSG (CH)', 3, {}, NO_SETTING_NOTE),
    'uk-gdpr': ('UK GDPR', 3, {}, NO_SETTING_NOTE),
    'pci-dss': ('PCI DSS', 3, _INTL, ''),
    'hipaa': ('HIPAA (US)', 3, _INTL, ''),
    'soc2': ('SOC 2', 3, _INTL, ''),
    'nist-csf': ('NIST CSF', 3, _INTL, ''),
}
ADMIN_ROLES = ('super', 'tenant', 'domain', 'manager', 'helpdesk', 'readonly', 'auditor')
NOTE_RE = re.compile(r'^[\w .,;:()/&+\'-]{0,200}$')


def all_texts():
    """The texts to translate, for scripts/i18n_extract.py."""
    found = [NOTICE_TITLE, *NOTICE, NOTICE_CONFIRM, VARIANT_TITLE, EULINK_TITLE, EULINK_TEXT, EULINK_YES, NOEU_TITLE, *NOEU, NOEU_CONFIRM,
             NOEU_TYPE, FRAMEWORKS_TITLE, FRAMEWORKS_TEXT, FRAMEWORKS_OTHER, TOTP_TITLE, TOTP_TEXT, NONBINDING, *GROUPS, 'Yes', 'No',
             STANDARDS_TEXT, SSH_LATER]
    for title, text in VARIANT_TEXT.values():
        found += [title, text]
    found += [item[3] for item in FRAMEWORKS.values() if item[3]]
    return found


def digest(parts):
    """The first 16 hex digits of SHA-256 over the texts as shown, like the digest of the legal texts (efa_legal)."""
    found = hashlib.sha256()
    for part in parts:
        found.update(part.encode('utf-8') + b'\0')
    return found.hexdigest()[:16]


def notice_digest(tr):
    return digest([tr(NOTICE_TITLE), *map(tr, NOTICE), tr(NOTICE_CONFIRM)])


def noeu_digest(tr, lang):
    return digest([tr(NOEU_TITLE), *map(tr, NOEU), tr(NOEU_CONFIRM), tr(NOEU_TYPE).format(phrase=PHRASES.get(lang, PHRASES['en']))])


def phrase_ok(typed):
    """The typed phrase of Text D: either language, case and spaces do not count."""
    return ' '.join((typed or '').split()).lower() in {phrase.lower() for phrase in PHRASES.values()}


def confirmation(the_digest, now=None):
    """What goes to efa-apply and into the state: digest and time, digest/epoch."""
    return f'{the_digest}/{int(time.time() if now is None else now)}'


def confirmation_ok(value):
    return bool(re.fullmatch(r'[0-9a-f]{16}/\d{9,11}', value or ''))


def frameworks_clean(ids):
    """Known framework ids, in the order of the table, from a list or a text with commas; unknown ones are left out."""
    wanted = set(re.split(r'[\s,]+', ids) if isinstance(ids, str) else ids)
    return [key for key in FRAMEWORKS if key in wanted]


def targets(ids, variant, eulink):
    """What the guided setup and the frameworks ask for, before comparing it with the system."""
    wanted = {'admin_2fa': False, 'main_admin_2fa': variant == 'guided', 'audit_days': 0, 'tls': None, 'security_daily': False}
    if variant != 'guided':
        return wanted
    for key in frameworks_clean(ids) + (['gdpr'] if eulink == 'yes' else []):
        raises = FRAMEWORKS[key][2]
        wanted['admin_2fa'] |= raises.get('admin_2fa', False)
        wanted['security_daily'] |= raises.get('security_daily', False)
        wanted['audit_days'] = max(wanted['audit_days'], raises.get('audit_days', 0))
        if 'tls' in raises:
            wanted['tls'] = tuple(item for item in (wanted['tls'] or raises['tls']) if item in raises['tls']) or ('bsi',)
    return wanted


def plan(current, wanted):
    """The changes, each [setting, now, then]: only up, never down. current: policy (role: mode), audit_days, tls, security_daily."""
    changes = []
    roles = ADMIN_ROLES if wanted['admin_2fa'] else ()
    for role in roles:
        if current['policy'].get(role) != 'required':
            changes.append([f'2fa:{role}', current['policy'].get(role, 'optional'), 'required'])
    if wanted['main_admin_2fa'] and not current.get('main_admin_2fa'):
        changes.append(['2fa:main-admin', 'optional', 'required'])
    if wanted['audit_days'] > current['audit_days']:
        changes.append(['audit_days', current['audit_days'], wanted['audit_days']])
    if wanted['tls'] and current['tls'] not in wanted['tls']:
        changes.append(['tls_profile', current['tls'], 'bsi'])
    if wanted['security_daily'] and not current['security_daily']:
        changes.append(['security_daily', False, True])
    return changes


def notes(ids):
    """[(title, note)] of the chosen frameworks, each a non-binding suggestion."""
    return [(FRAMEWORKS[key][0], FRAMEWORKS[key][3]) for key in frameworks_clean(ids) if FRAMEWORKS[key][3]]


def state_problem(state):
    """Why a setup state is not one eFa-next writes, or None."""
    if state.get('variant') not in VARIANTS or state.get('eulink') not in ('yes', 'no'):
        return 'variant guided or manual, EU link yes or no'
    if not confirmation_ok(state.get('notice', '')):
        return 'the note on presets is not confirmed'
    if state['eulink'] == 'no' and not confirmation_ok(state.get('noeu', '')):
        return 'no EU link without the typed confirmation'
    if not NOTE_RE.match(state.get('note', '')):
        return 'the note on other frameworks: up to 200 letters, digits and punctuation'
    return None


def eu_locked(state):
    """With an EU link from the setup the EU rules apply hard: no typed transfer outside the EU."""
    return bool(state) and state.get('eulink') == 'yes'


# The questions as HTML for the setup wizard and the Re-Setup page; the caller puts them into its form. The chips are checkboxes in
# their labels: no script, keys and screen readers work as with any checkbox.
CHIPS_CSS = ('.chips label{display:inline-block;width:auto;margin:.2rem;padding:.25rem .8rem;border:1px solid #767676;border-radius:1rem;cursor:pointer}'
             '.chips input{position:absolute;opacity:0;width:1px;height:1px}.chips label:has(input:checked){background:#3b3d3a;color:#fff;border-color:#3b3d3a}'
             '.chips label:has(input:focus-visible){outline:2px solid #1a5fb4;outline-offset:2px}.chips fieldset{border:0;padding:0;margin:.5rem 0}')


def _paragraphs(tr, texts):
    # A long legal text scrolls in its own box (class legal), the box to confirm it stays in view below.
    return '<div class="legal">' + ''.join(f'<p>{html.escape(tr(text))}</p>' for text in texts) + '</div>'


def notice_html(tr, checked=False):
    return (f'<h2>{html.escape(tr(NOTICE_TITLE))}</h2>{_paragraphs(tr, NOTICE)}<p><label><input type="checkbox" name="notice" value="yes" required'
            f'{" checked" if checked else ""}> {html.escape(tr(NOTICE_CONFIRM))}</label></p>')


def variant_html(tr, chosen=''):
    options = ''.join(f'<p><label><input type="radio" name="variant" value="{key}" required{" checked" if chosen == key else ""}> '
                      f'<b>{html.escape(tr(title))}:</b> {html.escape(tr(text))}</label></p>' for key, (title, text) in VARIANT_TEXT.items())
    return f'<h2>{html.escape(tr(VARIANT_TITLE))}</h2>{options}'


def eulink_html(tr, chosen=''):
    options = (f'<p><label><input type="radio" name="eulink" value="yes" required{" checked" if chosen == "yes" else ""}> <b>{html.escape(tr("Yes"))}:</b> '
               f'{html.escape(tr(EULINK_YES))}</label></p><p><label><input type="radio" name="eulink" value="no" required'
               f'{" checked" if chosen == "no" else ""}> <b>{html.escape(tr("No"))}</b></label></p>')
    return f'<h2>{html.escape(tr(EULINK_TITLE))}</h2><p>{html.escape(tr(EULINK_TEXT))}</p>{options}'


def noeu_html(tr, lang, required=True, checked=False, typed=''):
    """Text D. Re-Setup shows it on the same page as the EU question: then not required, efactl checks it."""
    phrase = PHRASES.get(lang, PHRASES['en'])
    label = html.escape(tr(NOEU_TYPE)).replace('{phrase}', f'<code>{html.escape(phrase)}</code>')
    must = ' required' if required else ''
    return (f'<h2>{html.escape(tr(NOEU_TITLE))}</h2>{_paragraphs(tr, NOEU)}<p><label><input type="checkbox" name="noeu" value="yes"{must}'
            f'{" checked" if checked else ""}> {html.escape(tr(NOEU_CONFIRM))}</label></p><p><label>{label} <input name="phrase"{must} autocomplete="off" '
            f'value="{html.escape(typed)}"></label></p>')


def frameworks_html(tr, chosen=(), note=''):
    groups = ''
    for number, group in enumerate(GROUPS):
        chips = ''.join(f'<label><input type="checkbox" name="frameworks" value="{key}"{" checked" if key in chosen else ""}> {html.escape(title)}</label>'
                        for key, (title, where, _raises, _note) in FRAMEWORKS.items() if where == number)
        groups += f'<fieldset><legend>{html.escape(tr(group))}</legend>{chips}</fieldset>'
    return (f'<h2>{html.escape(tr(FRAMEWORKS_TITLE))}</h2><p>{html.escape(tr(FRAMEWORKS_TEXT))}</p><div class="chips">{groups}</div>'
            f'<p><label>{html.escape(tr(FRAMEWORKS_OTHER))} <input name="note" maxlength="200" value="{html.escape(note)}"></label></p>')


def standards_html(tr, chosen=(), titles=None):
    """The standards to choose in the step of the frameworks, grouped as in the hardening wizard, and which frameworks lead to which."""
    titles = titles or efa_harden.titles()
    groups = ''
    for group, ids in efa_harden.GROUPS:
        chips = ''.join(f'<label title="{html.escape(tr(efa_harden.SUMMARY[sid]))}"><input type="checkbox" name="standards" value="{sid}"'
                        f'{" checked" if sid in chosen else ""}> {html.escape(titles.get(sid, sid))}</label>' for sid in ids)
        groups += f'<fieldset><legend>{html.escape(tr(group))}</legend>{chips}</fieldset>'
    mapped = ''.join(f'<li>{html.escape(FRAMEWORKS[key][0])}: {html.escape(", ".join(titles.get(sid, sid) for sid in ids))}</li>'
                     for key, ids in efa_harden.FRAMEWORK_STANDARDS.items())
    return (f'<h2>{html.escape(tr("Security standards"))}</h2><p>{html.escape(tr(STANDARDS_TEXT))}</p><div class="chips">{groups}</div>'
            f'<p class="help">{html.escape(tr("Leads to these standards:"))}</p><ul class="help">{mapped}</ul>')


def standards_taken(form_ids, frameworks):
    """The chosen standards and those the chosen frameworks lead to (where documented), known ids only."""
    return efa_harden.clean(list(form_ids) + efa_harden.from_frameworks(frameworks))


def standards_summary(tr, chosen, titles=None):
    """[(title, what it sets)] per chosen standard for the check page, and the note on the SSH profile when one asks for it."""
    titles = titles or efa_harden.titles()
    rows = [(titles.get(sid, sid), ', '.join(tr(text) for text in efa_harden.what(sid, setup=True)) or tr(efa_harden.SUMMARY[sid]))
            for sid in efa_harden.clean(chosen)]
    if 'ssh-profile' in efa_harden.plan_for(chosen)['os']:
        rows.append(('SSH', tr(SSH_LATER)))
    return rows


def self_test():
    same = lambda text: text
    first = notice_digest(same)
    assert len(first) == 16 and first == notice_digest(same) and first != notice_digest(lambda text: text + ' ')
    assert noeu_digest(same, 'en') != noeu_digest(same, 'de'), 'the typed phrase is part of what was shown'
    assert phrase_ok(' At  my own RISK ') and phrase_ok('auf eigenes Risiko') and not phrase_ok('at my risk') and not phrase_ok('')
    assert confirmation_ok(confirmation(first, 1762600000)) and not confirmation_ok(first) and not confirmation_ok('x/1762600000')
    assert frameworks_clean('iso27001, nis2,unknown') == ['nis2', 'iso27001'] and frameworks_clean([]) == []
    manual = targets(['nis2', 'dora'], 'manual', 'yes')
    assert not manual['admin_2fa'] and not manual['main_admin_2fa'] and manual['tls'] is None, 'manual: no suggestions'
    wanted = targets(['nis2', 'pci-dss'], 'guided', 'yes')
    assert wanted['admin_2fa'] and wanted['audit_days'] == 365 and wanted['tls'] == ('bsi', 'mozilla-modern')
    assert targets(['dora', 'nis2'], 'guided', 'no')['audit_days'] == 1825
    assert targets(['bsi-tr02102', 'pci-dss'], 'guided', 'yes')['tls'] == ('bsi',)
    current = {'policy': {'super': 'required'}, 'main_admin_2fa': False, 'audit_days': 400, 'tls': 'rfc9325', 'security_daily': False}
    changes = plan(current, wanted)
    assert ['tls_profile', 'rfc9325', 'bsi'] in changes and ['2fa:tenant', 'optional', 'required'] in changes
    assert not [c for c in changes if c[0] in ('audit_days', '2fa:super')], 'never down, nothing already there'
    assert plan({**current, 'audit_days': 3000, 'tls': 'mozilla-modern'}, targets(['dora'], 'guided', 'no'))[-1][0] != 'audit_days'
    assert ['2fa:main-admin', 'optional', 'required'] in plan(current, targets([], 'guided', 'no'))
    assert plan(current, targets(['nis2'], 'manual', 'no')) == []
    assert ('BAO/UGB (AT)', RETENTION_NOTE) in notes(['bao-ugb']) and notes(['pci-dss']) == []
    good = {'variant': 'guided', 'eulink': 'no', 'notice': confirmation(first), 'noeu': confirmation(first), 'note': 'own rules'}
    assert state_problem(good) is None and state_problem({**good, 'noeu': ''}) and state_problem({**good, 'variant': 'x'})
    assert state_problem({**good, 'note': 'a\nKEY:x'}) and eu_locked({'eulink': 'yes'}) and not eu_locked({}) and not eu_locked(good)
    assert all(isinstance(text, str) and text for text in all_texts())
    page = notice_html(same) + variant_html(same, 'manual') + eulink_html(same, 'no') + noeu_html(same, 'de') + frameworks_html(same, ['nis2'], '<x>')
    assert page.count('required') == 7 and 'value="manual" required checked' in page and 'value="no" required checked' in page
    assert '<code>auf eigenes Risiko</code>' in page and 'value="nis2" checked' in page and 'value="dora">' in page and '&lt;x&gt;' in page
    assert page.count('<fieldset>') == len(GROUPS) and '<script' not in page
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
