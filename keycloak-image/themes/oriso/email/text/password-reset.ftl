<#ftl output_format="plainText">
${msg("orisoResetHeadline")}
========================================

${msg("orisoResetBody1", (properties.orisoPlatformName)!'')}

${msg("orisoResetBody2", linkExpirationFormatter(linkExpiration))}

${msg("orisoResetCtaLabel")}:
${link}

${msg("orisoResetFootnote")}

----------------------------------------------------------------
${msg("orisoResetAssurance")}

${(properties.orisoOrgName)!''}
${(properties.orisoOrgAddress)!''}
${(properties.orisoContactLine)!''}

${msg("orisoResetOfferedBy", (properties.orisoPlatformName)!'', (properties.orisoOrgName)!'')}

${msg("orisoResetFooterLink1")}: ${(properties.orisoSettingsUrl)!''}
${msg("orisoResetFooterLink2")}: ${(properties.orisoPrivacyUrl)!''}
${msg("orisoResetFooterLink3")}: ${(properties.orisoImprintUrl)!''}
${msg("orisoResetFooterLink4")}: ${(properties.orisoUnsubscribeUrl)!''}

${msg("orisoResetAutomatedNote")}
