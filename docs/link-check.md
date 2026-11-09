# Link check on click

Rewrites the links in incoming mail so they are checked again at the moment the reader clicks, not only when the mail
arrives. Off by default, under Protection.

## How it works

- Each `http` and `https` link in the text and HTML parts is rewritten to a signed address on this server
  (`https://mx.example.com/l/<token>`). The token is signed, so there is no open redirect: only links this server wrote work.
- On a click the address is checked again against the URL lists and rewriting rules of rspamd. The verdict is cached for a
  few minutes.
- A safe link forwards at once. A dangerous one shows a warning page with the real address and the reason.
- If rspamd cannot be reached, the setting decides: show the warning page with the address, or follow the link.

## Settings

- **Exceptions**: domains whose links are not rewritten.
- Links to this server itself, and links longer than the limit, are left as they are.
- What happens when a link cannot be checked: show the page (default) or follow it.

Links are rewritten before the DKIM signature. Signed or encrypted parts are left unchanged.
