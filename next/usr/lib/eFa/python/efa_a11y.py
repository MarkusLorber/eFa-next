# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""P5: own checks of WCAG 2.1 AA for the user portal and the warning pages, for the self-tests in CI; no external service.
They cover what a program can see: the language of the page, names of pictures, fields, buttons and links, a heading, no
positive tabindex, a visible focus, and the contrast of the colours of the style sheet (4.5:1 for text, 3:1 for the focus)."""
import html.parser
import re

TEXT_CONTRAST, UI_CONTRAST = 4.5, 3.0


class _Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems, self.labels, self.fields, self.lang, self.headings = [], set(), [], False, 0
        self.open, self.text = [], {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'html':
            self.lang = bool(attrs.get('lang'))
        if tag in ('h1', 'h2'):
            self.headings += 1
        if tag == 'img' and 'alt' not in attrs:
            self.problems.append(f'picture without alt: {attrs.get("src", "")[:60]}')
        if tag == 'label' and attrs.get('for'):
            self.labels.add(attrs['for'])
        if tag in ('input', 'select', 'textarea') and attrs.get('type') not in ('hidden', 'submit', 'button', 'image', 'reset'):
            self.fields.append((attrs.get('id'), attrs.get('aria-label') or attrs.get('aria-labelledby') or attrs.get('title'), attrs.get('name', tag)))
        if attrs.get('tabindex', '0').lstrip('-').isdigit() and int(attrs.get('tabindex', '0')) > 0:
            self.problems.append(f'positive tabindex on {tag}')
        if tag in ('button', 'a'):
            self.open.append((tag, attrs.get('aria-label') or attrs.get('title') or '', attrs.get('href')))
            self.text[len(self.open)] = ''

    def handle_data(self, data):
        if self.open:
            self.text[len(self.open)] = self.text.get(len(self.open), '') + data

    def handle_endtag(self, tag):
        if tag in ('button', 'a') and self.open and self.open[-1][0] == tag:
            name, label, href = self.open.pop()
            text = self.text.pop(len(self.open) + 1, '').strip()
            if not (text or label) and (tag == 'button' or href):
                self.problems.append(f'{tag} without a name')


def page_problems(text):
    """What a page lacks: language, names of pictures, fields, buttons and links, a heading, a sane tab order."""
    page = _Page()
    page.feed(text)
    page.close()
    problems = list(page.problems)
    if not page.lang:
        problems.append('no lang on html')
    if not page.headings:
        problems.append('no heading h1 or h2')
    for field_id, label, name in page.fields:
        if not label and field_id not in page.labels:
            problems.append(f'field without a label: {name}')
    return problems


def luminance(colour):
    colour = colour.lstrip('#')
    if len(colour) == 3:
        colour = ''.join(char * 2 for char in colour)
    channels = [int(colour[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    channels = [value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(first, second):
    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def palettes(css):
    """The colours of :root, for the light scheme and, from the media query, the dark one."""
    blocks = re.findall(r':root\{([^}]*)\}', css)
    found = []
    for block in blocks:
        found.append({name: value for name, value in re.findall(r'(--[\w-]+):(#[0-9a-fA-F]{3,6})\b', block)})
    if len(found) >= 2:
        found[1] = {**found[0], **found[1]}
    return found


def contrast_problems(css, pairs, ui_pairs=()):
    """Each pair of colour names (text, background) in each palette: 4.5:1 for text, 3:1 for focus and controls."""
    problems = []
    for index, colours in enumerate(palettes(css)):
        scheme = 'light' if index == 0 else 'dark'
        for (front, back), needed in [(pair, TEXT_CONTRAST) for pair in pairs] + [(pair, UI_CONTRAST) for pair in ui_pairs]:
            if front in colours and back in colours and contrast(colours[front], colours[back]) < needed:
                problems.append(f'{scheme}: {front} on {back} {contrast(colours[front], colours[back]):.1f}:1, needs {needed}:1')
    return problems


def focus_problems(css):
    """A style sheet that takes the outline away must give a focus of its own."""
    if re.search(r'outline\s*:\s*(none|0)\b', css) and not re.search(r':focus(-visible)?[^{]*\{[^}]*outline\s*:\s*\d', css):
        return ['the focus outline is taken away without a visible focus']
    return []


def self_test():
    good = '<!doctype html><html lang="en"><body><h1>T</h1><label for="u">User</label><input id="u" name="u"><button>Go</button>' \
           '<img src="x.png" alt=""><a href="/x">Next</a><input type="hidden" name="csrf"></body></html>'
    assert page_problems(good) == []
    bad = '<html><body><input name="q"><button></button><img src="y.png"><a href="/z"></a><div tabindex="2"></div></body></html>'
    problems = page_problems(bad)
    assert 'no lang on html' in problems and 'no heading h1 or h2' in problems and 'field without a label: q' in problems
    assert 'button without a name' in problems and 'a without a name' in problems and 'positive tabindex on div' in problems and any('alt' in p for p in problems)
    assert round(contrast('#000', '#fff'), 1) == 21.0 and round(contrast('#777', '#fff'), 2) == 4.48
    css = ':root{--ink:#3f444a;--bg:#ffffff;--lime:#C0CF48}@media (prefers-color-scheme: dark){:root{--ink:#e6e7e3;--bg:#1b1d1a}}'
    assert contrast_problems(css, [('--ink', '--bg')]) == []
    assert contrast_problems(css, [('--lime', '--bg')])[0].startswith('light: --lime on --bg')
    assert focus_problems('a{outline:none}') and not focus_problems('a{outline:none}a:focus-visible{outline:2px solid #000}')
    print('self-test ok')


if __name__ == '__main__':
    self_test()
