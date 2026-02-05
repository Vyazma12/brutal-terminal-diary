# brutal-terminal-diary
Encrypted terminal diary with time-lock, mood tracking, and zero cloud sync. Write honestly. Read later.
# Brutal Diary
What is this?

Brutal Diary is a **CLI-based personal diary** with:

-Encrypted entries (Fernet / PBKDF2 if available)
-Time-lock system (entries unlock after N days)
-Mood tracking (1–10) + simple stats
-Uses your system editor (`$EDITOR`)
-Stores everything locally in a single JSON file

You write today. And you’re not allowed to read it immediately.  
Why?

Because sometimes:
- you’re honest only when nobody’s watching
- reading your thoughts *too early* just makes things worse
- you want something private that doesn’t live on a server

This tool is intentionally **boring**.


## Features

- "Strong encryption"
  - Uses cryptography (Fernet + PBKDF2) if installed
  - Falls back to XOR + HMAC if not (still encrypted, just weaker)
- timelock
  - Entries stay locked for a configurable number of days
- Mood tracking
  - Daily mood score
  - Simple ASCII chart
- Search
  - Search through unlocked entries only
- Single-file storage
  - Easy backup, easy deletion, no surprises

## Installation

Clone the repo:
git clone https://github.com/Vyazma12/Brutal-diary.git
cd Brutal-diary

(Optional but recommended) install cryptography:

pip install cryptography

## Usage
-Run it:
-"python3 brutal_diary.py"

First run:
-You’ll be asked to create a passphrase
-A local encrypted database will be created in:
-~/.brutal_diary.json

Daily use:
Just press Enter to write today’s entry
Follow the prompt
Rate your mood
Done

## Commands:

/read        Read unlocked entries
/search kw  Search unlocked entries
/stats       Mood stats + chart
/export f   Export encrypted JSON
/quit        Exit
Security notes (read this)
Your diary file is encrypted at rest, Without the passphrase, entries are unreadable. Losing the passphrase = losing the diary. Forever.
This tool does not protect against: 
-malware
-a compromised OS
-someone running code as you

Threat model: curiosity, not nation-states.

## Philosophy

This is not a productivity app.
This is not therapy software.
This is not “self-improvement”.

It’s a place to dump thoughts
and let time decide whether they still matter.

## License

Do whatever you want, just don’t blame me.

## Disclaimer

This project was built for personal use.
If it helps you, cool.
If it doesn’t, ignore it.
