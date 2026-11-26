# AI usage: dsc26-cyb-w06

## Tools

I used Claude to explain the task and draft code for normalize.py, prompt.py, and output.py. I pasted the code, ran the tests, and tried the commands myself.

## What AI got wrong

The starter's constants (INVISIBLE and BIDI) contained invisible Unicode characters that could be lost when copied from a chat. I replaced them with Unicode escape sequences such as \u200b to make sure the characters were preserved correctly, and I checked it by running normalize on a zero-width space and a full-width "ｉｇｎｏｒｅ".

## In my own words

1. Which leg of the lethal trifecta does stripping markdown images remove, and why does that matter for Hisn?

Stripping Markdown images removes the outbound communication leg, because images can make the browser send requests to an attacker's server. This matters for Hisn because sensitive information from alerts could be leaked outside the system.

2. Why does `triage` raise the severity of an alert that contains an injection attempt instead of just warning?

Triage raises the severity because an injection attempt in a log is a sign that someone is trying to manipulate the AI. Treating it as a simple warning could cause an analyst to ignore it, especially during a busy shift, and miss a real security threat.
