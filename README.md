# jkauthz

Authorization shared by the estate's services: figaro, figbox, the egress
relay, herald. Each service authenticates a caller into a `Subject`, then
asks its own policy whether that subject may perform a verb on one of its
resources.

## Principals

`[node/]kind:id`. Kinds in use: `user`, `sandbox`, `node`. Everything after the
first colon is the id, so SPIFFE-shaped ids need no escaping:
`sandbox:spiffe://kelliher.info/sandbox/dev/3`. A principal without a node
belongs to the node evaluating it; `spain2/user:1000` is not `user:1000`.

`Labels` carry what a caller asserted and nobody verified (the calling aria,
a display name). `Policy.Allow` never sees them.

## Policy

```toml
[roles.owner]
grants = ["*:*"]

[roles.sender]
grants = [
  "read:owner:self", "listen:owner:self", "send:owner:self",
  "read:role:@herald", "listen:role:@herald", "send:role:@herald",
]

[[bind]]
role = "owner"
principals = ["user:1000"]
groups = ["figaro-admin"]

[[bind]]
role = "sender"
principals = ["sandbox:*"]
```

A grant is `verb:object`. The verb ends at the first colon, so the object
keeps its own colons; either side may be `*`. A role's grants are held in
canonical form: duplicates and grants another one covers are dropped (`*:X`
covers `read:X`, `read:*` covers `read:X`), then sorted by the schema's verb
order and by object. `Grants.String` prints that form and `ParseGrants`
reads it back. Covering is syntactic: no selector is taken to contain another.

The host service supplies a `Schema`: its verbs, and a `Selectors`
implementation that validates and matches every selector except `*` against
its own resource type. Allow-only: nothing is permitted unless a bound role
grants the verb on a selector that matches.

Compile refuses unknown verbs, selectors and keys, roles that grant nothing,
and bindings to nobody. A `Store` swaps policies atomically; a failed load
keeps the policy that was serving, and a store with nothing loaded denies.

## Bearer tokens

`bearer.Verifier` checks signature (JWKS, refetched on an unknown kid at most
once a minute and at least hourly), issuer, expiry and, when configured,
audience and `typ`.

Token claims are never authorized on. Authelia 4.39 access tokens carry no
`aud` and no groups, and a refresh is not re-authorized. So a verified token
only yields `client_id` and `sub`, and a `Resolver` turns those into a subject:

- `bearer.ByClient` admits only listed clients, so a token minted for another
  service is refused.
- `bearer.Client{Kind}` makes the client itself the principal (sandboxes,
  service clients).
- `bearer.Userinfo` asks the issuer's userinfo endpoint for the user and
  groups, cached per token for 30s and never past the token's expiry. A
  failed lookup is a failed authentication.
