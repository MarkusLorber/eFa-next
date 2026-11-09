// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Markus Lorber and eFa-next contributors
// 13: a new message to the report address of the manifest (?to=), with the open mail as an attachment; the user sends it.
Office.onReady(function () {
  var button = document.getElementById('report');
  var state = document.getElementById('state');
  var to = new URLSearchParams(window.location.search).get('to') || '';
  if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(to)) {
    state.textContent = 'No report address in the add-in: ask your administrator.';
    return;
  }
  button.disabled = false;
  button.addEventListener('click', function () {
    var item = Office.context.mailbox.item;
    var subject = (item.subject || 'mail').slice(0, 200);
    Office.context.mailbox.displayNewMessageForm({
      toRecipients: [to],
      subject: 'Report: ' + subject,
      htmlBody: 'Reported with the add-in of eFa-next. / Gemeldet mit dem Add-in von eFa-next.',
      attachments: [{type: 'item', itemId: item.itemId, name: subject}]
    });
    state.textContent = 'A new message to ' + to + ' is open: send it. / Eine neue Nachricht ist offen: senden Sie sie.';
  });
});
