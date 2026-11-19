"""First-run welcome tour: a short step-by-step dialog shown the first time the dashboard opens.

Finishing or skipping it stores 'tour_done' in the local database; Help → 'Show the welcome tour' shows it again."""

from __future__ import annotations

import sqlite3

import streamlit as st

from database.db import get_setting, set_setting

STEPS = [
    ("Welcome to Local Security Scanner",
     "This app checks your own projects for security problems - on this computer only. Nothing is uploaded.\n\n"
     "It answers four questions:\n"
     "- **Are we using libraries with known flaws?** (Vulnerabilities)\n"
     "- **Did a password or key end up in the code?** (Secrets)\n"
     "- **Is any code written in a risky way?** (Code issues)\n"
     "- **What is wrong with our apps when they run?** (Web app issues)"),
    ("Step 1 - Tell it where your projects are",
     "Open **Settings → Repository roots** and pick the folder that holds your projects. Every Git project inside "
     "is found automatically and listed on the **Repositories** page."),
    ("Step 2 - Scan",
     "On **Repositories** press **Scan all**. The scan runs in the background; the sidebar shows progress. "
     "To also test a running web app, add its local address (and optionally a test-account login) under "
     "**Settings → Web scan (DAST)** and start the app first."),
    ("Step 3 - Read the results",
     "The **Overview** shows totals and a list of **Recommended next steps** - start at the top.\n\n"
     "Colours: **red = critical** (fix today), **orange = high** (this week), **yellow = medium**, "
     "**green/blue = low**."),
    ("Step 4 - Understand and fix",
     "Click any issue. The **In plain words** box explains what it is, why it matters, how an attacker would use "
     "it, the fix step by step, and how soon to fix it. Words you do not know are in **Help → Glossary**.\n\n"
     "Not a real problem? Under **Your decision** mark it as a **false positive**, **accept the risk** until a review "
     "date, or **archive** it - always with a reason. It leaves the counts but stays listed in the reports."),
    ("Step 5 - Scan again and share",
     "After fixing, scan again: fixed issues move to **Resolved** automatically. If a check could not run, issues "
     "show as **Unverified** - never as fixed.\n\n"
     "**Reports → Management summary** gives a one-page, plain-language report you can send to your manager."),
]


def maybe_show_tour(conn: sqlite3.Connection) -> None:
    if st.session_state.get("tour_hidden"):
        return
    if get_setting(conn, "tour_done") and not st.session_state.get("tour_force"):
        return
    st.session_state.setdefault("tour_step", 0)
    _tour(conn)


def _finish(conn: sqlite3.Connection) -> None:
    set_setting(conn, "tour_done", "1")
    st.session_state["tour_hidden"] = True
    st.session_state["tour_force"] = False
    st.session_state["tour_step"] = 0


@st.dialog("Getting started", width="large", dismissible=False)
def _tour(conn: sqlite3.Connection) -> None:
    i = min(st.session_state.get("tour_step", 0), len(STEPS) - 1)
    title, body = STEPS[i]
    st.progress((i + 1) / len(STEPS), text=f"{i + 1} of {len(STEPS)}")
    st.subheader(title)
    st.markdown(body)
    c1, c2, c3 = st.columns([1, 1, 1])
    if c1.button("Skip tour", key="tour_skip", width="stretch"):
        _finish(conn)
        st.rerun()
    if i > 0 and c2.button("Back", key="tour_back", width="stretch"):
        st.session_state["tour_step"] = i - 1
        st.rerun()
    if i < len(STEPS) - 1:
        if c3.button("Next", key="tour_next", type="primary", width="stretch"):
            st.session_state["tour_step"] = i + 1
            st.rerun()
    elif c3.button("Finish", key="tour_finish", type="primary", width="stretch"):
        _finish(conn)
        st.rerun()
