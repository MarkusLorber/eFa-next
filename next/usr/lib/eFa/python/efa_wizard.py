# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Guided wizards of the web interface: their steps and fields, the values they start with (read from the configuration of
this host), the changes they show before applying, and the one efactl call they end in. efactl checks every value again with
the same rules as the manual cards; a wizard has no rights of its own. No Flask here: efa-web renders the steps."""
import base64
import io
import json
import re
import zipfile

import efa_harden

ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
MAX_TEXT = 100000
# A neutral example for a new disclaimer; the own text is typed on the own host.
EXAMPLE_TEXT = 'Your disclaimer: replace this text with your own.'
EXAMPLE_HTML = '<p>Your disclaimer: replace this text with your own.</p>'
NEW = '+new'
ALL = '+all'
CHOSEN = '+chosen'

# Texts the steps show besides the labels; all_texts() hands them to the translation.
TEXTS = ['Wizard', 'Manual', 'Back', 'Next', 'Apply', 'Start again', 'Step', 'of', 'Now', 'New', 'Nothing changes.', 'Done.',
         'Open the manual view', 'Test the connection', 'The test runs ...', 'Load the result', 'Connected', 'STARTTLS offered',
         'Certificate valid', 'not set', 'yes', 'no', 'A disclaimer is added to outgoing mail only, at its end.',
         'Text version', 'HTML version', 'The preview shows no pictures and runs no scripts.',
         'Wizard or manual view', 'The change was not applied:', 'Add these records to the DNS of the domain:',
         'Keys this domain has now:', 'none', 'Choose a value from the list.', 'This field is required.',
         'Small letters, digits and dashes, up to 40.', 'Check the format of this value.',
         # The hardening wizard and the frame for a change that needs the password again.
         'Your password, to confirm', '2FA code, if you set one up', 'Your password still counts for {} minutes: no new entry needed.',
         'Tick the box to go on.', 'Open the preview first.', 'now', 'on', 'off', 'Last check', 'Sessions on port 25 without TLS in the last 7 days:',
         'Setting', 'Then', 'Because', 'Warnings', 'What this wizard does not change', 'Hints, never switched here',
         'Services that are not part of eFa-next or the operating system', 'none found',
         'eFa-next runs alone on its server: a foreign service is only named here, never stopped or removed.',
         'Changed:', 'Check of the chosen standards:', 'Back to the settings before: the card "Security standards: back to the settings before" in the manual view.',
         'The hardening report', 'Hardening wizard', 'Admin access and firewall: Security page (a wrong address locks you out).']
HARDEN_PICK = [('on', 'Harden'), ('keep', 'Leave as it is')]


def _new(values):
    return values.get('id') == NEW


WIZARDS = {
    'disclaimer': {
        'page': 'disclaimer', 'title': 'Set up a disclaimer', 'command': 'disclaimer-template-set', 'reads': ['disclaimer-status'],
        'steps': [
            {'id': 'pick', 'title': 'Which disclaimer', 'fields': [
                {'name': 'id', 'label': 'Disclaimer', 'kind': 'select', 'source': 'templates', 'resets': True}]},
            {'id': 'scope', 'title': 'For whom', 'fields': [
                {'name': 'new_id', 'label': 'Id of the new disclaimer', 'kind': 'text', 'when': _new, 'pattern': ID_RE},
                {'name': 'scope', 'label': 'For', 'kind': 'pick', 'choices': [('global', 'All domains'), ('tenant', 'One tenant'), ('domain', 'One domain')]},
                {'name': 'tenant', 'label': 'Tenant', 'kind': 'select', 'source': 'tenants', 'when': lambda v: v.get('scope') == 'tenant'},
                {'name': 'domain', 'label': 'Domain', 'kind': 'select', 'source': 'domains', 'when': lambda v: v.get('scope') == 'domain'}]},
            {'id': 'text', 'title': 'Text', 'fields': [
                {'name': 'name', 'label': 'Name', 'kind': 'text', 'optional': True},
                {'name': 'format', 'label': 'Format', 'kind': 'pick', 'choices': [('html', 'HTML and text'), ('text', 'Text only')]},
                {'name': 'text', 'label': 'Text version', 'kind': 'textarea', 'optional': True},
                {'name': 'html', 'label': 'HTML version', 'kind': 'textarea', 'when': lambda v: v.get('format') == 'html'}]},
            {'id': 'preview', 'title': 'Preview', 'preview': True, 'fields': [
                {'name': 'enabled', 'label': 'Active', 'kind': 'pick', 'choices': [('on', 'yes'), ('off', 'no')]}]},
            {'id': 'summary', 'title': 'Check and apply', 'fields': []}]},
    'archive': {
        'page': 'archive', 'title': 'Set up a mail archive', 'command': 'archive-set', 'reads': ['archive-status'], 'test': 'archive-test',
        'steps': [
            {'id': 'pick', 'title': 'Which archive', 'fields': [
                {'name': 'target', 'label': 'Archive target', 'kind': 'select', 'source': 'targets', 'resets': True},
                {'name': 'template', 'label': 'Archive', 'kind': 'pick',
                 'choices': [('mailstore', 'MailStore'), ('piler', 'piler'), ('smtp', 'Other (SMTP)')]}]},
            {'id': 'where', 'title': 'Where the copies go', 'fields': [
                {'name': 'name', 'label': 'Name, such as mailstore', 'kind': 'text', 'when': lambda v: v.get('target') == NEW, 'pattern': re.compile(r'^[a-z0-9_]{1,32}$')},
                {'name': 'address', 'label': 'Journal address of the archive', 'kind': 'text'},
                {'name': 'host', 'label': 'Host that takes the copies by SMTP', 'kind': 'text'},
                {'name': 'port', 'label': 'Port', 'kind': 'text', 'pattern': re.compile(r'^[0-9]{1,5}$')},
                {'name': 'format', 'label': 'What the archive gets', 'kind': 'pick',
                 'choices': [('copy', 'A copy of each mail'), ('journal', 'A journal report')]}]},
            {'id': 'which', 'title': 'Which mail', 'fields': [
                {'name': 'direction', 'label': 'Which mail', 'kind': 'pick', 'choices': [('both', 'In and out'), ('in', 'Incoming'), ('out', 'Outgoing')]},
                {'name': 'all', 'label': 'Domains', 'kind': 'pick', 'choices': [(ALL, 'All domains'), (CHOSEN, 'Chosen domains')]},
                {'name': 'domains', 'label': 'Chosen domains', 'kind': 'multi', 'source': 'domains', 'when': lambda v: v.get('all') == CHOSEN}]},
            {'id': 'tls', 'title': 'Encryption', 'test': True, 'fields': [
                {'name': 'tls', 'label': 'TLS', 'kind': 'pick',
                 'choices': [('verify', 'Required, certificate checked'), ('encrypt', 'Required, certificate not checked'), ('may', 'When offered')]}]},
            {'id': 'summary', 'title': 'Check and apply', 'fields': []}]},
    'dkim': {
        'page': 'dkim', 'title': 'Create a DKIM key', 'command': 'dkim-create', 'reads': ['dkim-check'],
        'steps': [
            {'id': 'domain', 'title': 'Domain', 'fields': [
                {'name': 'domain', 'label': 'Domain', 'kind': 'select', 'source': 'domains', 'resets': True}]},
            {'id': 'key', 'title': 'Key', 'fields': [
                {'name': 'kind', 'label': 'Key type', 'kind': 'pick', 'choices': [('both', 'RSA and Ed25519'), ('rsa', 'RSA only'), ('ed25519', 'Ed25519 only')]},
                {'name': 'bits', 'label': 'RSA key size', 'kind': 'pick', 'choices': [('2048', '2048'), ('3072', '3072'), ('4096', '4096')],
                 'when': lambda v: v.get('kind') != 'ed25519'}]},
            {'id': 'summary', 'title': 'Check and apply', 'fields': []}]},
    'route': {
        'page': 'flow', 'title': 'Add a domain and its mail server', 'command': 'transport-set', 'reads': [],
        'steps': [
            {'id': 'domain', 'title': 'Domain', 'fields': [
                {'name': 'domain', 'label': 'Domain', 'kind': 'text', 'resets': True, 'pattern': re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$')}]},
            {'id': 'server', 'title': 'Mail server', 'fields': [
                {'name': 'destination', 'label': 'Internal mail server, such as mail.example.org or 192.0.2.10:25', 'kind': 'text'}]},
            {'id': 'summary', 'title': 'Check and apply', 'fields': []}]},
}


def _std_choices(context):
    """The standards to choose: (id, title, version, group, status of the last check), in the groups of efa_harden."""
    status = context.get('loaded', {}).get('standards-status', (False, {}))
    known = {item['id']: item for item in (status[1] or {}).get('standards', [])} if status[0] and isinstance(status[1], dict) else {}
    shown = context.get('loaded', {}).get('standards-show', (False, {}))
    checked = (shown[1] or {}).get('standards', {}) if shown[0] and isinstance(shown[1], dict) else {}
    return [(sid, known.get(sid, {}).get('title', sid), known.get(sid, {}).get('version', ''), group, checked.get(sid, {}).get('status', ''))
            for group, ids in efa_harden.GROUPS for sid in ids if not known or sid in known]


def _harden_state(context, table, key):
    """Whether an item is hardened now (os-harden-status), None while that is not read yet."""
    status = context.get('loaded', {}).get('os-harden-status', (False, None))
    if not status[0] or not isinstance(status[1], dict):
        return None
    rows = status[1].get('efa' if table is efa_harden.EFA_ITEMS else 'items', [])
    return next((bool(item.get('on')) for item in rows if item.get('id') == key), None)


def _harden_prefill(values, now, context):
    """Preselected what a chosen standard asks for (efa_harden.plan_for), once the state of the items is read."""
    plan = efa_harden.plan_for(efa_harden.clean(values.get('select', '')))
    found = {}
    for prefix, table, chosen in (('os_', efa_harden.OS_ITEMS, plan['os']), ('efa_', efa_harden.EFA_ITEMS, plan['efa'])):
        for key in table:
            if _harden_state(context, table, key) is not None:
                found[prefix + key] = 'on' if key in chosen else 'keep'
    return found


def _harden_fields(prefix, table):
    return [{'name': prefix + key, 'label': item['title'], 'kind': 'pick', 'choices': HARDEN_PICK, 'late': True, 'item': key}
            for key, item in table.items()]


def _harden_items(values, prefix, table):
    return ','.join(key for key in table if values.get(prefix + key) == 'on') or 'none'


def harden_args(values):
    """The arguments of standards-preview and standards-set for a draft of the hardening wizard."""
    return [f"--select={' '.join(efa_harden.clean(values.get('select', '')))}", f"--port25_tls={values.get('port25', '')}",
            f"--os={_harden_items(values, 'os_', efa_harden.OS_ITEMS)}", f"--efa={_harden_items(values, 'efa_', efa_harden.EFA_ITEMS)}"]


# What the wizard does not change, for the open findings of the last check of the chosen standards: (start of the setting, where).
UNTOUCHED = [('certificate', 'Network & certificate page: a certificate with ECC or RSA 3072.'), ('DKIM keys', 'DKIM wizard: new keys with RSA 3072 or 4096.'),
             ('DANE incoming', 'DNS records and a mailbox: docs/dmarc-dane-mta-sts.md.'), ('TLS-RPT', 'DNS records and a mailbox: docs/dmarc-dane-mta-sts.md.'),
             ('MTA-STS', 'DNS records and a mailbox: docs/dmarc-dane-mta-sts.md.'), ('HSTS', 'Set in the web server of eFa-next; see the check.'),
             ('sshd permitrootlogin', 'Security page: root login through SSH.')]


def untouched(values, context):
    """[(setting, now, wanted, where)] of the open findings of the chosen standards that this wizard leaves alone."""
    shown = context.get('loaded', {}).get('standards-show', (False, {}))
    checked = (shown[1] or {}).get('standards', {}) if shown[0] and isinstance(shown[1], dict) else {}
    rows = {}
    for sid in efa_harden.clean(values.get('select', '')):
        for row in checked.get(sid, {}).get('rows', []):
            where = next((text for start, text in UNTOUCHED if row.get('setting', '').startswith(start)), None)
            if where and row.get('status') in ('not', 'needs'):
                rows[row['setting']] = (row['setting'], row.get('now', ''), row.get('wanted', ''), where)
    return list(rows.values())


def ready(name, values, fetched):
    """Why the draft cannot be applied yet, or None: the preview of exactly this draft is read, its warnings ticked as read."""
    if name != 'hardening':
        return None
    preview = fetched.get('standards-preview')
    if not preview or not preview[0] or preview[2] != preview_call(name, values):
        return 'Open the preview first.'
    if preview[1].get('warnings') and values.get('ack') != 'yes':
        return 'Tick the box to go on.'
    return None


WIZARDS['hardening'] = {
    'page': 'standards', 'title': 'Harden this server', 'command': 'standards-set', 'reads': ['standards-status', 'standards-show'],
    'reauth': True, 'prefill': _harden_prefill, 'summary': 'preview',
    'steps': [
        {'id': 'standards', 'title': 'Standards', 'fields': [
            {'name': 'select', 'label': 'Standards', 'kind': 'checks', 'source': 'standards', 'refills': True, 'optional': True}]},
        {'id': 'port25', 'title': 'Port 25', 'fields': [
            {'name': 'port25', 'label': 'TLS on port 25', 'kind': 'pick',
             'choices': [('off', 'Keep it opportunistic (recommended, RFC 3207)'), ('on', 'Require TLS')]}]},
        {'id': 'os', 'title': 'Operating system', 'fetch': ['os-harden-status'], 'fields': _harden_fields('os_', efa_harden.OS_ITEMS)},
        {'id': 'efa', 'title': 'eFa-next', 'fetch': ['os-harden-status'], 'fields': _harden_fields('efa_', efa_harden.EFA_ITEMS)},
        {'id': 'preview', 'title': 'Preview', 'preview': 'standards-preview', 'fields': [
            {'name': 'ack', 'label': 'I have read the warnings', 'kind': 'tick', 'when': lambda v: v.get('_warn') == 'yes'}]},
        {'id': 'summary', 'title': 'Check and apply', 'fields': []}]}
PAGES = {wizard['page']: name for name, wizard in WIZARDS.items()}


def fields(name, step_id=None):
    """The fields of one step, or of all steps."""
    return [field for step in WIZARDS[name]['steps'] if step_id in (None, step['id']) for field in step['fields']]


def step_ids(name):
    return [step['id'] for step in WIZARDS[name]['steps']]


def visible(field, values):
    return field.get('when') is None or field['when'](values)


def choices(field, context):
    """The values a field may take: its fixed ones or those of its source in the context (what this login may choose)."""
    if 'choices' in field:
        return list(field['choices'])
    if field.get('source') == 'standards':
        return [(sid, title) for sid, title, *_rest in _std_choices(context)]
    return list(context.get(field['source'], [])) if 'source' in field else []


def _status(context, name):
    ok, output = context.get('loaded', {}).get(name, (False, None))
    return output if ok and isinstance(output, dict) else {}


def _zip_texts(answer):
    """manifest.json, body.txt and body.html of a disclaimer ZIP (disclaimer-export), each read only up to its limit."""
    ok, output = answer
    if not ok or not isinstance(output.get('zip'), str):
        return {}
    found = {}
    try:
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(output['zip']))) as archive:
            for item in ('manifest.json', 'body.txt', 'body.html'):
                if item in archive.namelist() and archive.getinfo(item).file_size <= MAX_TEXT:
                    found[item] = archive.read(item).decode('utf-8', 'replace')
    except (ValueError, zipfile.BadZipFile):
        return {}
    return found


def current(name, values, context):
    """What is set now for the object the wizard works on, in the names of its fields; empty for a new one. context:
    loaded (the reads of the page), domains, tenants, settings, fetch (calls a read command with arguments)."""
    if name == 'disclaimer':
        found = next((item for item in _status(context, 'disclaimer-status').get('templates', []) if item.get('id') == values.get('id')), None)
        if not found:
            return {}
        files = _zip_texts(context['fetch']('disclaimer-export', f"--id={found['id']}"))
        scope = found.get('scope') or 'global'
        return {'scope': scope, 'tenant': found.get('target', '') if scope == 'tenant' else '', 'domain': found.get('target', '') if scope == 'domain' else '',
                'name': found.get('name') or '', 'format': found.get('format') or 'text', 'enabled': 'on' if found.get('enabled', True) else 'off',
                'text': files.get('body.txt', ''), 'html': files.get('body.html', '')}
    if name == 'archive':
        found = next((item for item in _status(context, 'archive-status').get('targets', []) if item.get('name') == values.get('target')), None)
        if not found:
            return {}
        return {'template': found.get('template', 'smtp'), 'address': found.get('address', ''), 'host': found.get('host', ''), 'port': str(found.get('port', 25)),
                'format': found.get('format', 'copy'), 'direction': found.get('direction', 'both'), 'all': CHOSEN if found.get('domains') else ALL,
                'domains': ','.join(found.get('domains') or []), 'tls': found.get('tls', 'encrypt')}
    if name == 'dkim':
        keys = [item for item in _status(context, 'dkim-check').get('keys', []) if item.get('domain') == values.get('domain') and item.get('state') == 'active']
        return {'keys': ', '.join(sorted(f"{item.get('type')} ({item.get('selector')})" for item in keys))}
    if name == 'route':
        destination = (context.get('settings') or {}).get('transports', {}).get(values.get('domain', ''))
        return {'destination': destination} if destination else {}
    if name == 'hardening':
        status = _status(context, 'standards-status')
        now = {'select': ','.join(efa_harden.clean(status.get('selected', [])))} if status else {}
        if status.get('port25_mode') or status.get('port25_tls'):
            now['port25'] = status.get('port25_mode') or status['port25_tls']
        for prefix, table in (('os_', efa_harden.OS_ITEMS), ('efa_', efa_harden.EFA_ITEMS)):
            for key in table:
                if _harden_state(context, table, key):
                    now[prefix + key] = 'on'
        return now
    return {}


# For a new object: the values efactl itself would take, so nothing changes by a hidden default.
NEW_VALUES = {
    'disclaimer': {'scope': 'global', 'format': 'text', 'enabled': 'on', 'text': EXAMPLE_TEXT, 'html': EXAMPLE_HTML, 'name': ''},
    'archive': {'template': 'mailstore', 'port': '25', 'format': 'copy', 'direction': 'both', 'all': ALL, 'domains': '', 'tls': 'verify', 'address': '', 'host': ''},
    'dkim': {'kind': 'both', 'bits': '2048'},
    'route': {'destination': ''},
    'hardening': {'select': '', 'port25': 'off', 'ack': ''},
}


def prefill(name, values, context, now=None):
    """The draft with every field it lacks taken from the configuration now (current), else from NEW_VALUES."""
    now = current(name, values, context) if now is None else now
    filled = dict(values)
    hook = WIZARDS[name].get('prefill')
    extra = hook(values, now, context) if hook else {}
    for field in fields(name):
        if field['name'] not in filled:
            if field['name'] in now:
                filled[field['name']] = now[field['name']]
            elif field['name'] in extra:
                filled[field['name']] = extra[field['name']]
            elif field.get('late'):
                continue  # filled once what it depends on is read
            elif field['name'] in NEW_VALUES[name]:
                filled[field['name']] = NEW_VALUES[name][field['name']]
            elif field.get('kind') in ('select', 'pick'):
                options = choices(field, context)
                filled[field['name']] = options[0][0] if options else ''
            else:
                filled[field['name']] = ''
    return filled


def take(name, step_id, values, form, context):
    """The values of one step from the form into the draft: (draft, problem). Only the fields of this step that are shown,
    each checked against its choices; a field that resets (which object) empties the rest of the draft when it changes. A
    field that a choice of this form opens is not in the form yet: it is left out, and opened() names it."""
    draft, problem = dict(values), None
    shown = [field['name'] for field in fields(name, step_id) if visible(field, values)]
    for field in fields(name, step_id):
        if not visible(field, draft) or (field['name'] not in shown and field['name'] not in form):
            continue
        if field['kind'] in ('multi', 'checks'):
            picked = [item for item in form.getlist(field['name'])] if hasattr(form, 'getlist') else form.get(field['name'], '').split(',')
            picked = [item for item in picked if item]
            allowed = {value for value, _text in choices(field, context)}
            if any(item not in allowed for item in picked):
                return values, 'Choose a value from the list.'
            value = ','.join(sorted(set(picked)))
        elif field['kind'] == 'tick':
            value = 'yes' if form.get(field['name']) == 'yes' else ''
            if not value:
                problem = problem or 'Tick the box to go on.'
        else:
            value = str(form.get(field['name'], '')).replace('\r\n', '\n').strip()
            if len(value) > MAX_TEXT:
                value = value[:MAX_TEXT]
        if field['kind'] in ('select', 'pick') and value not in {item for item, _text in choices(field, context)}:
            return values, 'Choose a value from the list.'
        if field.get('pattern') and not field['pattern'].match(value):
            problem = problem or ('Small letters, digits and dashes, up to 40.' if field['name'] == 'new_id' else 'Check the format of this value.')
        if not value and field['kind'] in ('text', 'textarea') and not field.get('optional'):
            problem = problem or 'This field is required.'
        if field.get('resets') and value != values.get(field['name']):
            draft = {key: item for key, item in draft.items() if key in [other['name'] for other in fields(name, step_id)]}
        if field.get('refills') and value != values.get(field['name']):
            # Another choice: what depends on it is preselected again.
            draft = {key: item for key, item in draft.items() if key not in [other['name'] for other in fields(name) if other.get('late')]}
        draft[field['name']] = value
    return draft, problem


def opened(name, step_id, before, after):
    """The fields of a step that the new values show and the old ones did not: the step is shown again with them."""
    return [field['name'] for field in fields(name, step_id) if visible(field, after) and not visible(field, before)]


def call(name, values):
    """The efactl call that applies the draft: the command and its arguments, as a list without a shell."""
    v = values
    if name == 'disclaimer':
        template_id = v['new_id'] if v.get('id') == NEW else v['id']
        target = v.get('tenant', '') if v.get('scope') == 'tenant' else v.get('domain', '') if v.get('scope') == 'domain' else ''
        # A real new line goes as it is; efactl turns the \n of the console into one too.
        return ['disclaimer-template-set', f'--id={template_id}', f"--name={v.get('name', '')}", f"--scope={v['scope']}", f'--target={target}',
                f"--format={v['format']}", f"--text={v.get('text', '')}",f"--html={v.get('html', '') if v['format'] == 'html' else ''}", f"--enabled={v['enabled']}"]
    if name == 'archive':
        target = v['name'] if v.get('target') == NEW else v['target']
        return ['archive-set', f'--name={target}', f"--template={v['template']}", f"--address={v['address']}", f"--host={v['host']}",
                f"--port={v['port']}", f"--direction={v['direction']}", f"--domains={v.get('domains', '') if v.get('all') == CHOSEN else ''}",
                f"--tls={v['tls']}", f"--format={v['format']}"]
    if name == 'dkim':
        return ['dkim-create', f"--domain={v['domain']}", f"--kind={v['kind']}"] + ([f"--bits={v['bits']}"] if v['kind'] != 'ed25519' else [])
    if name == 'route':
        return ['transport-set', f"--domain={v['domain']}", '--action=add', f"--destination={v['destination']}"]
    if name == 'hardening':
        return ['standards-set', *harden_args(v), '--apply=yes', '--confirm=yes']
    raise KeyError(name)


def preview_call(name, values):
    """The read command of the step with 'preview', with its arguments, or None."""
    return ['standards-preview', *harden_args(values)] if name == 'hardening' else None


def changes(name, values, context, now=None):
    """The rows of the summary: (label, now, after) for each field that is shown, the changed ones marked."""
    now = current(name, values, context) if now is None else now
    rows = []
    for field in fields(name):
        if field.get('resets') or not visible(field, values):
            continue
        before, after = now.get(field['name'], ''), values.get(field['name'], '')
        texts = dict(choices(field, context)) if field['kind'] in ('pick', 'select') else {}
        rows.append({'label': field['label'], 'now': texts.get(before, before), 'after': texts.get(after, after), 'changed': before != after})
    return rows


def all_texts():
    """Every text of the wizards, for scripts/i18n_extract.py."""
    found = list(TEXTS) + [text for _value, text in HARDEN_PICK] + efa_harden.all_texts() + [text for _start, text in UNTOUCHED]
    for wizard in WIZARDS.values():
        found.append(wizard['title'])
        for step in wizard['steps']:
            found.append(step['title'])
            for field in step['fields']:
                found.append(field['label'])
                found += [text for value, text in field.get('choices', []) if re.search('[A-Za-z]{2}', text)]
    return found


def self_test():
    loaded = {'disclaimer-status': (True, {'templates': [{'id': 'all', 'scope': 'domain', 'target': 'a.example', 'format': 'html', 'enabled': False, 'name': 'Main'}]}),
              'archive-status': (True, {'targets': [{'name': 'ms', 'template': 'mailstore', 'address': 'j@archive.example', 'host': 'archive.example',
                                                     'port': 2525, 'direction': 'in', 'tls': 'encrypt', 'domains': ['a.example'], 'format': 'journal'}]})}
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, 'w') as archive:
        archive.writestr('manifest.json', json.dumps({'id': 'all'}))
        archive.writestr('body.txt', 'Hello')
        archive.writestr('body.html', '<p>Hello</p>')
    context = {'loaded': loaded, 'domains': [('a.example', 'a.example'), ('b.example', 'b.example')], 'tenants': [('t1', 't1')],
               'templates': [(NEW, 'New'), ('all', 'all')], 'targets': [(NEW, 'New'), ('ms', 'ms')],
               'fetch': lambda *args: (True, {'zip': base64.b64encode(zipped.getvalue()).decode()}), 'settings': {'transports': {'a.example': 'mx.a.example'}}}
    found = prefill('disclaimer', {'id': 'all'}, context)
    assert (found['scope'], found['domain'], found['format'], found['enabled'], found['text'], found['html']) == ('domain', 'a.example', 'html', 'off', 'Hello', '<p>Hello</p>'), found
    assert prefill('disclaimer', {'id': NEW}, context)['text'] == EXAMPLE_TEXT
    assert call('disclaimer', found) == ['disclaimer-template-set', '--id=all', '--name=Main', '--scope=domain', '--target=a.example', '--format=html',
                                         '--text=Hello', '--html=<p>Hello</p>', '--enabled=off']
    assert not any(row['changed'] for row in changes('disclaimer', found, context))
    draft, problem = take('disclaimer', 'scope', found, {'scope': 'nope'}, context)
    assert problem and draft == found, 'a value outside the choices is refused'
    draft, problem = take('disclaimer', 'scope', {'id': NEW}, {'new_id': 'Bad Id', 'scope': 'global'}, context)
    assert problem == 'Small letters, digits and dashes, up to 40.'
    draft, problem = take('disclaimer', 'pick', found, {'id': NEW}, context)
    assert draft == {'id': NEW} and problem is None, 'another disclaimer starts from its own values'
    found = prefill('archive', {'target': 'ms'}, context)
    assert call('archive', found) == ['archive-set', '--name=ms', '--template=mailstore', '--address=j@archive.example', '--host=archive.example', '--port=2525',
                                      '--direction=in', '--domains=a.example', '--tls=encrypt', '--format=journal'], call('archive', found)
    assert prefill('archive', {'target': NEW}, context)['tls'] == 'verify', 'a new archive gets TLS with a checked certificate'
    draft, problem = take('archive', 'which', found, _Multi({'direction': 'both', 'all': CHOSEN, 'domains': ['b.example', 'evil.example']}), context)
    assert problem and draft == found, 'only own domains'
    draft, problem = take('archive', 'which', found, _Multi({'direction': 'both', 'all': CHOSEN, 'domains': ['b.example', 'a.example']}), context)
    assert problem is None and draft['domains'] == 'a.example,b.example'
    assert [row['label'] for row in changes('archive', draft, context) if row['changed']] == ['Which mail', 'Chosen domains']
    assert call('dkim', prefill('dkim', {'domain': 'a.example'}, context)) == ['dkim-create', '--domain=a.example', '--kind=both', '--bits=2048']
    assert call('dkim', {'domain': 'a.example', 'kind': 'ed25519', 'bits': '2048'}) == ['dkim-create', '--domain=a.example', '--kind=ed25519']
    assert prefill('route', {'domain': 'a.example'}, context)['destination'] == 'mx.a.example'
    draft, problem = take('archive', 'which', {**found, 'all': ALL}, {'direction': 'both', 'all': CHOSEN}, context)
    assert problem is None and opened('archive', 'which', {**found, 'all': ALL}, draft) == ['domains'], 'a choice that opens a field shows the step again'
    assert take('route', 'domain', {}, {'domain': 'x;rm'}, context)[1] == 'Check the format of this value.'
    assert take('route', 'server', {'domain': 'a.example'}, {'destination': ''}, context)[1] == 'This field is required.'
    assert all(text for text in all_texts())
    _hardening_self_test()
    return 'efa_wizard self-test ok'


def _hardening_self_test():
    status = {'selected': ['rfc9325'], 'port25_tls': 'off', 'port25_mode': 'off', 'port25_without_tls_7d': 3,
              'standards': [{'id': sid, 'title': sid.upper(), 'version': '1'} for sid in efa_harden.known()]}
    show = {'standards': {'rfc9325': {'status': 'over', 'rows': []},
                          'bsi-02102-2': {'status': 'not', 'rows': [{'setting': 'certificate web', 'status': 'not', 'now': 'rsa 2048 bits', 'wanted': 'RSA from 3000'},
                                                                    {'setting': 'TLS groups', 'status': 'not', 'now': 'X25519', 'wanted': 'not X25519'}]}}}
    harden = {'items': [{'id': key, 'on': key == 'chronyd'} for key in efa_harden.OS_ITEMS],
              'efa': [{'id': key, 'on': key == 'tls-min'} for key in efa_harden.EFA_ITEMS]}
    context = {'loaded': {'standards-status': (True, status), 'standards-show': (True, show)}}
    found = prefill('hardening', {}, context)
    assert found['select'] == 'rfc9325' and found['port25'] == 'off', 'from standards-status, never a default'
    assert not any(key.startswith(('os_', 'efa_')) for key in found), 'the items wait until their state is read'
    assert [value for value, _text in choices(fields('hardening', 'standards')[0], context)] == efa_harden.known()
    draft, problem = take('hardening', 'standards', found, _Multi({'select': ['bsi-02102-2', 'cis-el', 'evil']}), context)
    assert problem and draft == found, 'only known ids'
    draft, problem = take('hardening', 'standards', found, _Multi({'select': ['bsi-02102-2', 'cis-el']}), context)
    assert problem is None and draft['select'] == 'bsi-02102-2,cis-el'
    assert take('hardening', 'port25', draft, {'port25': 'maybe'}, context)[1] == 'Choose a value from the list.', 'the pill of port 25'
    draft = take('hardening', 'port25', draft, {'port25': 'off'}, context)[0]
    context['loaded']['os-harden-status'] = (True, harden)
    draft = prefill('hardening', draft, context, current('hardening', draft, context))
    assert draft['os_chronyd'] == 'on' and draft['os_auditd'] == 'on' and draft['os_ssh-profile'] == 'on', 'cis-el asks for them'
    assert draft['os_crypto-future'] == 'keep' and draft['efa_tls-min'] == 'on' and draft['efa_audit-mode'] == 'keep'
    again = take('hardening', 'standards', draft, _Multi({'select': ['rfc9325']}), context)[0]
    again = prefill('hardening', again, context, current('hardening', again, context))
    assert again['os_auditd'] == 'keep' and again['os_chronyd'] == 'on', 'another choice preselects again; what is on now stays on'
    draft = {**draft, 'os_ssh-profile': 'keep', 'efa_dane': 'on'}
    tail = [f"--os={','.join(key for key in efa_harden.OS_ITEMS if key not in ('ssh-profile', 'crypto-future'))}", '--efa=service-harden,tls-min,dane']
    assert preview_call('hardening', draft) == ['standards-preview', '--select=bsi-02102-2 cis-el', '--port25_tls=off', *tail], preview_call('hardening', draft)
    assert call('hardening', draft) == ['standards-set', '--select=bsi-02102-2 cis-el', '--port25_tls=off', *tail, '--apply=yes', '--confirm=yes']
    nothing = {key: 'keep' for key in draft if key.startswith(('os_', 'efa_'))}
    assert harden_args({**draft, **nothing, 'select': ''})[0::2] == ['--select=', '--os=none'], 'none chosen: no standard, no item'
    tick = fields('hardening', 'preview')[0]
    assert not visible(tick, draft) and visible(tick, {**draft, '_warn': 'yes'}), 'the tick box only with warnings'
    assert take('hardening', 'preview', {**draft, '_warn': 'yes'}, {'ack': ''}, context)[1] == 'Tick the box to go on.'
    assert take('hardening', 'preview', draft, {}, context)[1] is None
    fetched = {'standards-preview': (True, {'warnings': ['w']}, preview_call('hardening', draft))}
    assert ready('hardening', draft, {}) == 'Open the preview first.' and ready('hardening', draft, fetched) == 'Tick the box to go on.'
    assert ready('hardening', {**draft, 'ack': 'yes'}, fetched) is None
    assert ready('hardening', {**draft, 'ack': 'yes', 'efa_audit-mode': 'on'}, fetched) == 'Open the preview first.', 'a changed draft needs its own preview'
    secret = take('hardening', 'efa', draft, {'reauth': 'Secret-Pass-1', 'reauth_code': '123456', 'efa_dane': 'on'}, context)[0]
    assert 'Secret-Pass-1' not in json.dumps(secret) and not {'reauth', 'reauth_code'} & set(secret), 'never a password in the draft'
    assert [row[0] for row in untouched({'select': 'bsi-02102-2'}, context)] == ['certificate web']



class _Multi(dict):
    """A form with several values for one name, as the browser sends a list with multiple choice."""
    def getlist(self, key):
        value = self.get(key, [])
        return value if isinstance(value, list) else [value]

    def get(self, key, default=None):
        value = dict.get(self, key, default)
        return value


if __name__ == '__main__':
    print(self_test())
