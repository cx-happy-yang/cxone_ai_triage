# Jira: minimum permissions for the API token

`JIRA_EMAIL` / `JIRA_API_TOKEN` (see README.md "Authentication") authenticate
to Jira Cloud as a specific Jira **user account** — an API token isn't
scoped on its own, it inherits whatever permissions that account has on
whatever projects it can see. So "minimum permission" here means: what the
account behind the token needs, and — just as importantly — what it
*shouldn't* need.

## What this tool actually calls (`jira_client.py`)

| Call | Jira REST API | Needs |
|---|---|---|
| `JIRA.issue(key)` (`get_issue_for_triage`) | `GET /rest/api/2/issue/{key}` | **Browse Projects** on the ticket's project |
| `JIRA.search_issues('parent = "<key>"')` (subtasks) | `GET /rest/api/2/search` | **Browse Projects** on the ticket's project |
| `JIRA.comments(issue)` (duplicate-comment check) | `GET /rest/api/2/issue/{key}/comment` | **Browse Projects** (comment visibility follows issue visibility, unless a comment has its own security level restricting it further) |
| `JIRA.add_comment(issue, body)` | `POST /rest/api/2/issue/{key}/comment` | **Add Comments** on the ticket's project |

That's it — this tool never edits, transitions, resolves, assigns, deletes,
or links an issue, never touches issue security levels or workflow, and
never needs any project-administration permission.

## Recommended: a dedicated service account, scoped down

1. **Don't** point `JIRA_EMAIL`/`JIRA_API_TOKEN` at a real person's account
   or a Jira admin account — the token would inherit whatever broad access
   that account happens to have (including permissions this tool doesn't
   use, like transitioning or deleting issues), and it'd break if that
   person leaves or rotates their own credentials.
2. Create a dedicated Jira user for this integration (e.g.
   `cxone-ai-triage-bot@...`).
3. On the relevant project(s)' **permission scheme**
   (Project settings → Permissions), grant that user only:
   - **Browse Projects**
   - **Add Comments**

   Do not grant Edit Issues, Transition Issues, Resolve Issues, Delete
   Issues, Administer Projects, or anything else — none of it is used.
4. Generate a classic API token for that account at
   [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
   and set it as `JIRA_API_TOKEN` (with `JIRA_EMAIL` as that account's
   email).

## If your site supports scoped API tokens

Atlassian's newer **API tokens with scopes** let a token be restricted
below the account's full permission set, similar in spirit to an OAuth
scope. If available on your site, the two classic scopes that cover
everything this tool does are:

- `read:jira-work` — covers `GET issue`, the JQL subtask search, and
  reading comments.
- `write:jira-work` — covers posting a comment.

**Prefer the classic scopes over granular per-resource scopes** for the
write path: there's a documented issue where granular-scoped tokens
authenticate fine for `GET`/`PUT` but return `401` on `POST` requests
(which is exactly how `add_comment` posts a new comment) — see the
References below. `write:jira-work` (classic) doesn't hit this.

Either way (scoped token or not), the underlying account still needs
**Browse Projects** + **Add Comments** on the relevant project(s) via its
permission scheme — a scope only narrows what the *token* can do within
whatever the *account* is already permitted to do; it doesn't grant
anything by itself.

## Verifying the grant

Run the tool (or `python main.py -i samples/input.sample.json -o /tmp/out.json`
against a real ticket) with `-v` and confirm no `401`/`403` on any Jira
call, and that the comment actually appears on the ticket. A `403` on
`GET /rest/api/2/issue/{key}` usually means Browse Projects is missing for
that project; a `403`/`401` only on the `POST .../comment` call usually
means Add Comments is missing, or (if using a scoped token) that
`write:jira-work` — not a granular scope — is what's needed.

## References

- [Manage API tokens for service accounts](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) (Atlassian)
- [Permission schemes overview](https://support.atlassian.com/jira-cloud-administration/docs/manage-project-permissions/) (Atlassian)
- Community thread on the granular-scope `POST` `401` issue:
  [Jira Token With Scopes](https://community.atlassian.com/forums/Jira-questions/Jira-Token-With-Scopes/qaq-p/3027245)
