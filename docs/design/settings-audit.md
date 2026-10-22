# Settings tab audit — 2026-10-22

## Findings

The Settings tab carried the same card and control vocabulary as the rest of the console,
but it had no scan layer of its own.

1. **It opened on a redundant card.** The first card contained the title "Settings", a
   window label, and a summary that rendered empty. It consumed the strongest position on
   the page without giving the operator a starting point.
2. **Every section had equal visual weight.** Account, Users, Break-glass access,
   Detection, Reverse DNS, Storage, Domain blocklists and Pending changes were one
   uninterrupted stack. Nothing distinguished a frequently used detection control from a
   rarely used account form.
3. **The pending set was last.** An operator who edited a value near the top had to
   remember that the Apply action lived at the bottom of a long page.
4. **There was no find or bulk expand.** More than thirty settings rows across several
   groups, all collapsed by default, with no way to search a setting's name or its
   explanation.
5. **The tab did not lead like the other views.** Other tabs lead with a view header;
   Settings began directly with a card, so it read as an administrative appendix rather
   than a first-class surface.

## Changes

- Replaced the opening card with a view header: title, version, explanation, a **Find**
  control, **Expand all**, **Collapse all**, and a **Review pending** jump that appears only
  while the one staged set is non-empty.
- Added section labels: **Access and security**, **Detection**, **Operations**, **Changes**.
- Made the single pending-changes card sticky at the bottom of the viewport on wide screens
  (static on phones), so Apply stays in reach without creating a second stage.
- Kept the existing card/control vocabulary, focus behaviour, help text, accordion, and
  write path. No settings value, route, or apply semantics changed.
- Added harness checks for the header, find control, section labels, expand/collapse, and
  pending jump.

## Deliberately not changed

- Cards still start collapsed; the view header now makes expanding all or finding a row a
  single action. Opening the whole page by default would turn a scannable index into a
  wall of controls.
- Account, token and blocklist behaviour is unchanged. The audit's issue was hierarchy,
  not those capabilities.
- No second pending store was introduced. The jump and the card render the same `STAGE`.
