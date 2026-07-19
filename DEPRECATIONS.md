# Deprecated eager APIs

Raven's preferred server-side message representation is an SMTP envelope plus a
stream or seekable spool containing the RFC 5322 message. The APIs below remain
available for source compatibility, but should not be used in new server code.

| Deprecated API | Preferred server-side path | Reason |
| --- | --- | --- |
| `mail.MIMEPart`, `Content.ToMIME`, `Content.FromMIME`, `MIMEPart.ToBytes` | `mail.WalkMIME` and `mail.MIMEWalkPart` | The tree retains every MIME body and serialization creates another complete body. |
| `Content.FromRaw`, `Content.ToRaw` | `server.Session.Data`, `client.SendRaw`, or a caller-owned spool | `FromRaw` retains the complete input buffer; `ToRaw` allocates a second complete message. Neither supports bounded streaming. |
| `Mail.ToJSON`, `Mail.ToJSONIndent`, `mail.FromJSON` | Stream metadata with `json.Encoder`/`json.Decoder`; spool message content separately | JSON embeds the body and byte-returning helpers allocate the complete encoded object. |
| `Mail.ToMessagePack`, `mail.FromMessagePack` | Generated `EncodeMsg`/`DecodeMsg` for compatibility; spool message content separately for new queues | The byte-returning helpers eagerly materialize the encoded object. |
| `dkim.SignMail`, `dkim.SignMailMultiple`, `dkim.QuickSign`, `dkim.VerifyMailContext` | `Signer.SignReader`, `SignMultipleReader`, `Verifier.VerifyReader` | Mail adapters reconstruct another complete raw message. |
| `arc.SignMail`, `arc.QuickSeal`, `arc.VerifyMailContext` | `Sealer.SealReader`, `Verifier.VerifyReader` | Mail adapters reconstruct another complete raw message. |
| `client.RawMessage`, `Client.SendMultiple`, `Client.SendRawMultiple` | Loop over `Send` or `SendRaw` on one client | Incremental queue processing releases each message and result promptly. |
| `Dialer.DialAndSend*`, `client.QuickSend*` | Reuse `Dialer.Dial` clients or `Pool`; prefer `SendRaw` for spooled messages | One-shot helpers create a connection per operation or retain whole batches. |

These are documentation deprecations: no API has been removed. Removal, if any,
is reserved for a future major version.
