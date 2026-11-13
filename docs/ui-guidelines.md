# Web interface: UI guidelines

How the pages of the web interface look and behave. First used by the mail log, the live log and the quarantine
(6.0.0.6); the other pages follow these patterns when they are changed. Everything is self-hosted CSS and plain
JavaScript in `efa-web.py`: no framework, no CDN, no web fonts. Colours come only from the tokens of `efa_style.TOKENS`,
so dark mode works without extra rules.

## Speed

- Server time per page under 100 ms (p95); `scripts/page_times.py` checks it in CI.
- No new polling. A view that refreshes (the live log) does it only while it is open.
- Work in the browser rather than another round trip: filtering, sorting and the details drawer use the data the page
  already has.

## Tables

- Full width for pages that are mostly a table (`main.wide`).
- Compact rows (`table.log`), sticky head, the head never broken inside a word.
- No wrapping for short values: time, queue ID, IP, result, score (`td.nw`). Long values (addresses, recipients,
  subjects) are cut with an ellipsis and carry the full value in `title` (`td.cut`).
- Monospace only for machine values: queue ID, IP (`.mono`).
- Time as its age ("5 min", "3 h", then the day) with the exact time in the title. Ages in the browser are counted from
  the time of the server, never from the clock of the browser.
- State as a small coloured badge (`.st.g` good, `.st.w` warning, `.st.b` bad), never only by colour: the badge keeps its
  word, and the title names the check.
- Below 900 px a table becomes cards: every `td` has `data-label`, which is shown in front of the value.
- The tables `show()` makes from lists (`table.data`) do the same below 760 px.
- Empty results say what to do next (`p.empty`), never only "Done."; a search that runs shows a skeleton (`.skel`, no
  animation with `prefers-reduced-motion`).

## Settings forms and the menu

- Settings stay in their sections (`details.section`) and cards; each field keeps its label, its (i) help and its
  current value under the field.
- A form with six fields or more shows them in two columns on wide screens (from 1360 px), the label above the field;
  one column below that, full width on phones.
- A form with seven fields or more keeps its buttons in sight at the bottom of the card while the fields scroll.
- On a phone the menu starts folded under one button that names the page; on wide screens it is open.
- One choice from a few: on/off and yes/no as a pill switch (`label.sw`, `role="switch"`); two to four short choices
  (up to 18 characters each) as a pill group (`.segpick`, `role="radiogroup"`, radio buttons, so the keyboard and the
  browser work as with a list); more or longer choices stay a list. The value in effect is the one ticked; without
  one, the first choice counts, as in a list. On a phone the pills fill the row. The macro is `pickone()` in `field()`.

## Things to act on

- A sender, a domain or an IP is a chip (`button.chip` with `data-sender`, `data-kind`, `data-qid`, `data-rcpt`). Its menu
  is a small popover at the chip (`mailui.js`), reachable by keyboard: Enter opens, arrow keys move, Esc closes and gives
  the focus back.
- Row actions: the frequent ones as icon buttons (`button.icon`, with `aria-label`) shown on hover and keyboard focus of
  the row (always on touch screens), all of them in a "…" menu (`details.rowmenu`).
- Several rows at once: tick boxes (`input.pick`) and a bulk bar (`.bulk`) that appears with the first tick.
- Details of one item open in a drawer at the side (`dialog.drawer`); raw values (JSON, headers) stay under a fold there.

## The search of the menu

- While typing, suggestions come in groups (mail search, pages, actions, settings), each with one line: the line of the
  page, or the first sentence of the help text of the card (`efa_help.CARD`, the same text as the (i) popup). No text of
  its own.
- The index is one JSON per login, language and code version (`/search/index.json?v=…`), built from the menu and the
  schema of the reader: only what the reader may open. The page fetches it once, at the first focus; the matching
  (prefix, parts of words, one typo, synonyms in English and German) runs in the browser, nothing goes to the server
  per keystroke. Like every answer of the interface it is `no-store`.
- Keyboard: `/` focuses, the arrow keys move, Enter opens, Esc closes; ARIA combobox and listbox. Enter without a choice
  posts the search as before.
- An address, domain, IP or queue ID offers the mail log with that filter.

## Changes

- Every change goes through the efactl command that already exists for it, with its own checks of arguments and
  rights; the page never writes a list or a file itself.
- Every button with `data-confirm` asks in the small dialog of the page, not in the box of the browser.
- A change that cannot simply be taken back, or that a warning applies to, asks first in a small dialog
  (`dialog.confirm`) that names the exact entry and its target; the warnings come from efactl.
- After a change a toast (`.toast`) says what happened; where it can be taken back it has **Undo**.
- Pages ask for JSON with `json=1` on `/run/<command>` (only for the commands in `JSON_RUN`); CSRF and the rights stay
  the same as for a form.

## Privacy in addresses

- Search terms are posted, never put in a query string: nginx would log them. A search that should be bookmarked or
  shared stands after `#` (`#q=from:a@example.com`), which the browser never sends.

## Texts

- English in the code, German in `next/usr/share/eFa/locale/de.po`; texts for scripts go in as `data-texts` JSON made
  with `_()`, so `scripts/i18n_extract.py` finds them.
