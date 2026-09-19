#!/bin/sh
# Message filter for git filter-branch: replace the wrong test count in 51969bf's message.
#
# WHY A FILE AND NOT AN INLINE ARGUMENT. The message contains apostrophes ("the Zeek view's OWN
# window", "the README's GUI section"). Passing this script inline as a single-quoted -m
# argument terminates the quote early and the shell tries to EXECUTE the words that follow --
# observed as `sh: line 3: these: command not found` plus a fatal syntax error, with the rewrite
# aborting. A file has no quoting problem.
#
# IT MUST PASS THROUGH COMMITS THAT DO NOT CONTAIN THE TEXT. git filter-branch runs the filter
# for EVERY commit in the range, so a filter that refuses when the text is absent fails the whole
# rewrite on the first unrelated commit -- observed as "msg-filter: the target text is not in
# this message; refusing to rewrite". Safety does NOT belong here: the caller checks the target
# commit contains the text BEFORE rewriting and verifies the corrected figure is present AFTER,
# which is stronger than an in-filter assert because it is checked against the named commit
# rather than against whatever commit happens to be streaming through.
#
# THE REPLACEMENT IS ONE LINE ON PURPOSE. sed works per line, so a replacement containing a
# newline gives "unterminated `s' command". One line is also the right shape for a commit message.
#
# git runs this with the message on stdin and takes stdout as the new message.
printf '%s' "$(cat)" | sed 's|1014 passed, 3 skipped\. Gate green, now 11 checks\.|928 passed, 4 skipped (MEASURED at this commit by checking it out into a worktree and running the suite; an earlier draft of this message said 1014, a hand-incremented figure that no run ever produced). Gate green, now 11 checks.|'
