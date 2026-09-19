#!/bin/sh
# Message filter for git filter-branch: replace the wrong test count in 51969bf's message.
#
# WHY A FILE AND NOT AN INLINE ARGUMENT. The message contains apostrophes ("the Zeek view's OWN
# window", "the README's GUI section"). Passing this script inline as a single-quoted -m
# argument therefore terminates the quote early and the shell tries to EXECUTE the words that
# follow -- observed as `sh: line 3: these: command not found` and a fatal syntax error, with the
# rewrite aborting. A file has no quoting problem at all.
#
# THE REPLACEMENT IS ONE LINE ON PURPOSE. sed operates per line, so a replacement containing a
# newline produces "unterminated `s' command" and the filter fails. Keeping the corrected figure
# on a single line is also better in a commit message.
#
# git runs this with the message on stdin and takes stdout as the new message.
set -eu

MSG=$(cat)

# ASSERT the target text is present. Without this, a message that no longer contains the wrong
# figure would be rewritten to itself and the caller would report success.
case "$MSG" in
    *"1014 passed, 3 skipped. Gate green, now 11 checks."*) ;;
    *)
        echo "msg-filter: the target text is not in this message; refusing to rewrite" >&2
        exit 1
        ;;
esac

WRONG='1014 passed, 3 skipped. Gate green, now 11 checks.'
RIGHT='928 passed, 4 skipped (MEASURED at this commit by checking it out into a worktree and running the suite; an earlier draft of this message said 1014, a hand-incremented figure that no run ever produced). Gate green, now 11 checks.'

# printf '%s' rather than echo: echo would interpret backslashes in the message.
printf '%s' "$MSG" | sed "s|$WRONG|$RIGHT|"
