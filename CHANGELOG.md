1.6.0 - 1/24/2024

Live-docs: https://tapis-project.github.io/live-docs/?service=GlobusProxy

Breaking Changes:
 - auth flow has been reworked to allow for v5 endpoints - users will need to refresh their auth tokens

New features:
 - created functional tests - unit tests were inadequate for certain functions
 - better handling of personal connect endpoints
 - initial support for additional consent auth flow
 - initial support for consent management

Bug fixes:
 - catch consent required errors instead of returning a 500 code
 - fixed imports of functions
