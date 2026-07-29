<!doctype html>
<html lang="${locale.language}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${kcSanitize(msg("emailHeading"))?no_esc}</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f6fa; color:#1f2937; font-family:Arial, Helvetica, sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%; background-color:#f4f6fa;">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%; max-width:600px; background-color:#ffffff; border:1px solid #e5e7eb; border-radius:12px; overflow:hidden;">
          <tr>
            <td align="center" style="padding:24px 32px; background-color:#0f3b8f; color:#ffffff; font-size:28px; font-weight:700; letter-spacing:0.5px;">ORISO</td>
          </tr>
          <tr>
            <td style="padding:36px 40px 40px;">
              <h1 style="margin:0 0 16px; color:#111827; font-size:26px; line-height:1.25;">${kcSanitize(msg("emailHeading"))?no_esc}</h1>
              <p style="margin:0 0 28px; color:#4b5563; font-size:16px; line-height:1.6;">${kcSanitize(msg("emailIntro"))?no_esc}</p>

              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%; margin:0 0 12px; background-color:#eef3ff; border:1px solid #c7d6fa; border-radius:10px;">
                <tr>
                  <td align="center" style="padding:22px 16px;">
                    <div aria-label="${kcSanitize(msg("emailCodeAriaLabel", otp))?no_esc}" style="display:inline-block; color:#0f3b8f; font-family:'Courier New', Courier, monospace; font-size:36px; font-weight:700; line-height:1; letter-spacing:8px; white-space:nowrap; user-select:all; -webkit-user-select:all;">${kcSanitize(msg("emailCodeBody", otp))?no_esc}</div>
                  </td>
                </tr>
              </table>

              <p style="margin:0 0 24px; color:#6b7280; font-size:13px; line-height:1.5; text-align:center;">${kcSanitize(msg("emailCopyHint"))?no_esc}</p>
              <p style="margin:0 0 20px; color:#374151; font-size:15px; line-height:1.6;">${kcSanitize(msg("emailExpiryBody", ttl))?no_esc}</p>
              <p style="margin:0; padding-top:20px; border-top:1px solid #e5e7eb; color:#6b7280; font-size:13px; line-height:1.6;">${kcSanitize(msg("emailSecurityNotice"))?no_esc}</p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:20px 32px; background-color:#f9fafb; color:#6b7280; font-size:13px;">${kcSanitize(msg("emailFooter"))?no_esc}</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
