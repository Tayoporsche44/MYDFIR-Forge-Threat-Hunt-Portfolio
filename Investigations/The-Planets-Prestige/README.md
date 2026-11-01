# The Planet's Prestige – Email Forensics Investigation

## 1. Case Overview

- **Investigation Type:** Phishing / Suspicious Email Analysis
- **Analyst:** Tayo Porsche
- **Environment:** Isolated SOC Lab – Ubuntu
- **Status:** Completed

## 2. Executive Summary

An investigation was conducted into a suspicious email titled "A Hope to CoCanDa".

The investigation identified email spoofing, a misleading attachment file extension, and indicators associated with a suspected malicious actor.

## 3. Key Findings

| Finding | Result |
|---|---|
| Email Subject | A Hope to CoCanDa |
| Displayed Sender | Bill |
| Sender Address | billjobs@microapple.com |
| Email Service | emkei.cz |
| Reply-To Address | negeja3921@pashter.com |
| Actual Attachment Type | ZIP |
| Malicious Actor | Pestero Negeja |
| Attacker Location | The Martian Colony, Beside Interplanetary Spaceport |
| Probable C&C Domain | pashter.com |

## 4. Investigation and Analysis

### Email Header Analysis

The email headers revealed that the message originated through emkei.cz.

The SPF check failed for the displayed sender address, indicating that the sender could not be authenticated through the SPF mechanism.

The Reply-To address differed from the displayed sender address, providing another suspicious indicator.

### Attachment Analysis

The attachment was presented as a PDF named PuzzleToCoCanDa.pdf.

However, examination of its file signature revealed the ZIP magic bytes:

`50 4B 03 04`

This confirmed that the actual attachment was a ZIP archive rather than a PDF document.

### Extracted Evidence

The archive contained three files:

- DaughtersCrown – JPEG image
- GoodJobMajor – PDF document
- Money.xlsx – Excel workbook

The PDF metadata identified the author as Pestero Negeja.

The PDF also directed the investigation toward the DaughtersCrown image and Money.xlsx workbook.

### Location Discovery

An encoded Base64 value was discovered in the Excel workbook.

After decoding, it revealed:

`The Martian Colony, Beside Interplanetary Spaceport.`

### Command and Control Indicator

The Reply-To address used the domain pashter.com.

Based on the available challenge evidence, pashter.com was identified as the probable C&C domain.

## 5. Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| Email Service | emkei.cz |
| Reply-To | negeja3921@pashter.com |
| Suspicious Domain | pashter.com |
| Malicious Actor | Pestero Negeja |

## 6. Recommended Defensive Actions

1. Block or investigate the suspicious domain through approved security procedures.
2. Treat unexpected attachments as untrusted.
3. Validate sender identities using email authentication results.
4. Inspect attachment file signatures instead of trusting file extensions.
5. Preserve suspicious emails and extracted evidence for further analysis.

## 7. Conclusion

The investigation identified multiple suspicious indicators, including a failed SPF check, a suspicious Reply-To address, and an attachment disguised as a PDF.

File signature analysis confirmed that the attachment was actually a ZIP archive.

Further analysis of the extracted files revealed the suspected actor's name and location, alongside a probable C&C domain.

The investigation demonstrates the importance of email header analysis, file signature verification, metadata inspection, and evidence correlation.
