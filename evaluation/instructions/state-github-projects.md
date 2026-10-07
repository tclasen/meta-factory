Use the assigned private GitHub Projects v2 project through native gh commands.
Your immutable resource descriptor supplies owner, project number/node ID, and
field/option IDs; obtain item IDs by listing seeded draft items, with pagination.
Read all items when choosing work or recovering context. Map Todo, In progress,
Blocked, Done to the common status vocabulary.

At the common semantic boundaries, edit only Status, Progress, and Next action
on seeded items, then read back updates. Native gh api graphql is allowed for
equivalent operations unavailable through the pinned CLI. If a split update
partially persists, read the item and finish the intended update; do not assume
atomicity. Do not create/delete items, change schema or immutable descriptors,
use issues/comments, or store a local mutable cache or mirror.

If authentication or connectivity to the state service fails, stop and report a
state-service incomplete. Preserve partial state; do not fall back to a file or
conversation-only workflow or automatically rerun the attempt.
