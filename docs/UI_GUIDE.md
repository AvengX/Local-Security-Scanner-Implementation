# Dashboard guide

The dashboard is a single page: **paste a folder, scan it, get a VAPT report as a PDF.**

## Using it
| Step | What happens |
|---|---|
| **Project folder** | Paste a path such as `D:\Projects\my-app` (quotes from Windows *Copy as path* are fine) or click **Browse…**. |
| **Scan** | Every Git repository inside the folder is scanned; a folder without Git is scanned as one project. Each check is listed live with its result. The scan runs in the background, so clicking or refreshing does not stop it. Only one scan runs at a time. |
| **Report** | The PDF opens in the page (the browser's own PDF viewer). **Download PDF** saves it; **Open in new tab** shows it full-screen. Several projects → choose the project from the list. |
| **Earlier reports** | Shown when no scan is on screen. Files are kept in `reports\vapt` (HTML and PDF). |

If no Edge / Chrome is found the PDF cannot be printed: the page says so and offers the same report as HTML.

## What is in the report
1. **Executive summary** — issues per severity (Critical, High, Medium, Low, Info) and the overall posture.
2. **Scope & methodology** — the folder, components found (languages, dependency and deployment files), which
   tool checked what (with versions), whether the live web scan ran, the rules and how scoring works.
3. **Findings table** — ID, title, severity, CVSS 3.1 (where the advisory publishes one), OWASP Top 10 category.
4. **Finding details** — location, confidence (Confirmed / Likely / Needs verification), effort, roadmap phase,
   description, evidence (secret values are never included), impact and fix steps.
5. **What's done well** — checks that ran and found nothing, plus recurring weak spots.
6. **Remediation roadmap** — Fix now (critical/high), Next sprint (medium), Backlog (low/info).
7. **Not tested in this pass** — checks that did not run or did not finish, and what an automated scan cannot cover.

Raw scanner results are grouped: all vulnerable libraries of one dependency file are one issue, the same kind of code
problem in several places is one issue, and so on.

## Design
Dark page, local system fonts only (no web-font downloads). The report itself is a light, print-ready A4 document.
