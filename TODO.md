# TODO

## Admin UI & Account UI — new profile fields

The following OIDC standard profile fields were added to the user model and database but are not yet exposed in the UI:

- `middle_name`
- `nickname`
- `website`
- `gender`
- `birthdate`
- `profile` (URL to user's profile page)

**Admin UI** (`pkg/admin/`): Update the user edit form to display and allow editing of these fields.

**Account UI**: Update the account self-service profile page to display and allow editing of these fields.
