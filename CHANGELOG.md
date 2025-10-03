# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [unreleased]
### Added
* #1506 Support for Wildcard Origin and Redirect URIs
* #1586 Turkish language support added

### Changed
The project is now hosted in the django-oauth organization.

<!--
### Deprecated
### Removed
-->
### Fixed
* #1517 OP prompts for logout when no OP session
* #1512 client_secret not marked sensitive
* #1521 Fix 0012 migration loading access token table into memory
* #1584 Fix IDP container in docker compose environment could not find templates and static files.
* #1562 Fix: Handle AttributeError in IntrospectTokenView
* #1583 Fix: Missing pt_BR translations
<!--
### Security
-->


## [3.0.1] - 2024-09-07
### Fixed
* #1491 Fix migration error when there are pre-existing Access Tokens.

## [3.0.0] - 2024-09-05

### WARNING - POTENTIAL BREAKING CHANGES
* Changes to the `AbstractAccessToken` model require doing a `manage.py migrate` after upgrading.
* If you use swappable models you will need to make sure your custom models are also updated (usually `manage.py makemigrations`).
* Old Django versions below 4.2 are no longer supported.
* A few deprecations warned about in 2.4.0 (#1345) have been removed. See below.

### Added
* #1366 Add Docker containerized apps for testing IDP and RP.
* #1454 Added compatibility with `LoginRequiredMiddleware` introduced in Django 5.1.

### Changed
* Many documentation and project internals improvements.
* #1446 Use generic models `pk` instead of `id`. This enables, for example, custom swapped models to have a different primary key field.
* #1447 Update token to TextField from CharField. Removing the 255 character limit enables supporting JWT tokens with additional claims.
  This adds a SHA-256 `token_checksum` field that is used to validate tokens.
* #1450 Transactions wrapping writes of the Tokens now rely on Django's database routers to determine the correct
  database to use instead of assuming that 'default' is the correct one.
* #1455 Changed minimum supported Django version to >=4.2.

### Removed
* #1425 Remove deprecated `RedirectURIValidator`, `WildcardSet` per #1345; `validate_logout_request` per #1274

### Fixed
* #1444, #1476 Fix several 500 errors to instead raise appropriate errors.
* #1469 Fix `ui_locales` request parameter triggers `AttributeError` under certain circumstances

### Security
* #1452 Add a new setting [`REFRESH_TOKEN_REUSE_PROTECTION`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#refresh-token-reuse-protection).
  In combination with [`ROTATE_REFRESH_TOKEN`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#rotate-refresh-token),
  this prevents refresh tokens from being used more than once. See more at
  [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-29#name-recommendations)
* #1481 Bump oauthlib version required to 3.2.2 and above to address [CVE-2022-36087](https://github.com/advisories/GHSA-3pgj-pg6c-r5p7).

## [2.4.0] - 2024-05-13

### WARNING
Issues caused by **Release 2.0.0 breaking changes** continue to be logged. Please **make sure to carefully read these release notes** before
performing a MAJOR upgrade to 2.x.

These issues both result in `{"error": "invalid_client"}`:

1. The application client secret is now hashed upon save. You must copy it before it is saved. Using the hashed value will fail.

2. `PKCE_REQUIRED` is now `True` by default. You should use PKCE with your client or set `PKCE_REQUIRED=False` if you are unable to fix the client.

If you are going to revert migration 0006 make note that previously hashed client_secret cannot be reverted!

### Added
* #1304 Add `OAuth2ExtraTokenMiddleware` for adding access token to request.
  See [Setup a provider](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_03.html#setup-a-provider) in the Tutorial.
* #1273 Performance improvement: Add caching of loading of OIDC private key.
* #1285 Add `post_logout_redirect_uris` field in the [Application Registration form](https://django-oauth-toolkit.readthedocs.io/en/latest/templates.html#application-registration-form-html)
* #1311,#1334 (**Security**) Add option to disable client_secret hashing to allow verifying JWTs' signatures when using
  [HS256 keys](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#using-hs256-keys).
  This means your client secret will be stored in cleartext but is the only way to successfully use HS256 signed JWT's.
* #1350 Support Python 3.12 and Django 5.0
* #1367 Add `code_challenge_methods_supported` property to auto discovery information, per [RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414.html#page-7)
* #1328 Adds the ability to [define how to store a user profile](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#define-where-to-store-the-profile).

### Fixed
* #1292 Interpret `EXP` in AccessToken always as UTC instead of (possibly) local timezone.
  Use setting `AUTHENTICATION_SERVER_EXP_TIME_ZONE` to enable different time zone in case the remote
  authentication server does not provide EXP in UTC.
* #1323 Fix instructions in [documentation](https://django-oauth-toolkit.readthedocs.io/en/latest/getting_started.html#authorization-code)
  on how to create a code challenge and code verifier
* #1284 Fix a 500 error when trying to logout with no id_token_hint even if the browser session already expired.
* #1296 Added reverse function in migration `0006_alter_application_client_secret`. Note that reversing this migration cannot undo a hashed `client_secret`.
* #1345 Fix encapsulation for Redirect URI scheme validation. Deprecates `RedirectURIValidator` in favor of `AllowedURIValidator`.
* #1357 Move import of setting_changed signal from test to django core modules.
* #1361 Fix prompt=none redirects to login screen
* #1380 Fix AttributeError in OAuth2ExtraTokenMiddleware when a custom AccessToken model is used.
* #1288 Fix #1276 which attempted to resolve #1092 for requests that don't have a client_secret per [RFC 6749 4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1)
* #1337 Gracefully handle expired or deleted refresh tokens, in `validate_user`.
* Various documentation improvements: #1410, #1408, #1405, #1399, #1401, #1396, #1375, #1162, #1315, #1307

### Removed
* #1350 Remove support for Python 3.7 and Django 2.2

## [2.3.0] 2023-05-31

### WARNING

Issues caused by **Release 2.0.0 breaking changes** continue to be logged. Please **make sure to carefully read these release notes** before
performing a MAJOR upgrade to 2.x.

These issues both result in `{"error": "invalid_client"}`:

1. The application client secret is now hashed upon save. You must copy it before it is saved. Using the hashed value will fail.

2. `PKCE_REQUIRED` is now `True` by default. You should use PKCE with your client or set `PKCE_REQUIRED=False` if you are unable to fix the client.

### Added
* Add Japanese(日本語) Language Support
* #1244 implement [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* #1092 Allow Authorization Code flow without a client_secret per [RFC 6749 2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1)
* #1264 Support Django 4.2.

### Changed
* #1222 Remove expired ID tokens alongside access tokens in `cleartokens` management command
* #1267, #1253, #1251, #1250, #1224, #1212, #1211 Various documentation improvements

## [2.2.0] 2022-10-18

### Added
* #1208 Add 'code_challenge_method' parameter to authorization call in documentation
* #1182 Add 'code_verifier' parameter to token requests in documentation

### Changed
* #1203 Support Django 4.1.

### Fixed
* #1203 Remove upper version bound on Django, to allow upgrading to Django 4.1.1 bugfix release.
* #1210 Handle oauthlib errors on create token requests

## [2.1.0] 2022-06-19

### Added
* #1164 Support `prompt=login` for the OIDC Authorization Code Flow end user [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
* #1163 Add French (fr) translations.
* #1166 Add Spanish (es) translations.

### Changed
* #1152 `createapplication` management command enhanced to display an auto-generated secret before it gets hashed.
* #1172, #1159, #1158 documentation improvements.

### Fixed
* #1147 Fixed 2.0.0 implementation of [hashed](https://docs.djangoproject.com/en/stable/topics/auth/passwords/) client secret to work with swapped models.

## [2.0.0] 2022-04-24

This is a major release with **BREAKING** changes. Please make sure to review these changes before upgrading:

### Added
* #1106 OIDC: Add "scopes_supported" to the [ConnectDiscoveryInfoView](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#connectdiscoveryinfoview).
  This completes the view to provide all the REQUIRED and RECOMMENDED [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
* #1128 Documentation: [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_05.html)
  on using Celery to automate clearing expired tokens.

### Changed
* #1129 (**Breaking**) Changed default value of PKCE_REQUIRED to True. This is a **breaking change**. Clients without
  PKCE enabled will fail to authenticate. This breaks with [section 5 of RFC7636](https://datatracker.ietf.org/doc/html/rfc7636)
  in favor of the [OAuth2 Security Best Practices for Authorization Code Grants](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1).
  If you want to retain the pre-2.x behavior, set `PKCE_REQUIRED = False` in your settings.py
* #1093 (**Breaking**) Changed to implement [hashed](https://docs.djangoproject.com/en/stable/topics/auth/passwords/)
  client_secret values. This is a **breaking change** that will migrate all your existing
  cleartext `application.client_secret` values to be hashed with Django's default password hashing algorithm
  and can not be reversed. When adding or modifying an Application in the Admin console, you must copy the
  auto-generated or manually-entered `client_secret` before hitting Save.
* #1108 OIDC: (**Breaking**) Add default configurable OIDC standard scopes that determine which claims are returned.
  If you've [customized OIDC responses](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#customizing-the-oidc-responses)
  and want to retain the pre-2.x behavior, set `oidc_claim_scope = None` in your subclass of `OAuth2Validator`.
* #1108 OIDC: Make the `access_token` available to `get_oidc_claims` when called from `get_userinfo_claims`.
* #1132: Added `--algorithm` argument to `createapplication` management command

### Fixed
* #1108 OIDC: Fix `validate_bearer_token()` to properly set `request.scopes` to the list of granted scopes.
* #1132: Fixed help text for `--skip-authorization` argument of the `createapplication` management command.

### Removed
* #1124 (**Breaking**, **Security**) Removes support for insecure `urn:ietf:wg:oauth:2.0:oob` and `urn:ietf:wg:oauth:2.0:oob:auto` which are replaced
  by [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) "OAuth 2.0 for Native Apps" BCP. Google has
  [deprecated use of oob](https://developers.googleblog.com/2022/02/making-oauth-flows-safer.html?m=1#disallowed-oob) with
  a final end date of 2022-10-03. If you still rely on oob support in django-oauth-toolkit, do not upgrade to this release.

## [1.7.1] 2022-03-19

### Removed
* #1126 Reverts #1070 which incorrectly added Celery auto-discovery tasks.py (as described in #1123) and because it conflicts
  with Huey's auto-discovery which also uses tasks.py as described in #1114. If you are using Celery or Huey, you'll need
  to separately implement these tasks.

## [1.7.0] 2022-01-23

### Added
* #969 Add batching of expired token deletions in `cleartokens` management command and `models.clear_expired()`
  to improve performance for removal of large numbers of expired tokens. Configure with
  [`CLEAR_EXPIRED_TOKENS_BATCH_SIZE`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#clear-expired-tokens-batch-size) and
  [`CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#clear-expired-tokens-batch-interval).
* #1070 Add a Celery task for clearing expired tokens, e.g. to be scheduled as a [periodic task](https://docs.celeryproject.org/en/stable/userguide/periodic-tasks.html).
* #1062 Add Brazilian Portuguese (pt-BR) translations.
* #1069 OIDC: Add an alternate form of
  [get_additional_claims()](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-claims-to-the-id-token)
  which makes the list of additional `claims_supported` available at the OIDC auto-discovery endpoint (`.well-known/openid-configuration`).

### Fixed
* #1012 Return 200 status code with `{"active": false}` when introspecting a nonexistent token
  per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2). It had been incorrectly returning 401.

## [1.6.3] 2022-01-11

### Fixed
* #1085 Fix for #1083 admin UI search for idtoken results in `django.core.exceptions.FieldError: Cannot resolve keyword 'token' into field.`

### Added
* #1085 Add admin UI search fields for additional models.

## [1.6.2] 2022-01-06

**NOTE: This release reverts an inadvertently-added breaking change.**

### Fixed

* #1056 Add missing migration triggered by [Django 4.0 changes to the migrations autodetector](https://docs.djangoproject.com/en/4.0/releases/4.0/#migrations-autodetector-changes).
* #1068 Revert #967 which incorrectly changed an API. See #1066.

## [1.6.1] 2021-12-23

### Changed
* Note: Only Django 4.0.1+ is supported due to a regression in Django 4.0.0. [Explanation](https://github.com/django-oauth/django-oauth-toolkit/pull/1046#issuecomment-998015272)

### Fixed
* Miscellaneous 1.6.0 packaging issues.

## [1.6.0] 2021-12-19
### Added
* #949 Provide django.contrib.auth.authenticate() with a `request` for compatibility with more backends (like django-axes).
* #968, #1039 Add support for Django 3.2 and 4.0.
* #953 Allow loopback redirect URIs using random ports as described in [RFC8252 section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3).
* #972 Add Farsi/fa language support.
* #978 OIDC: Add support for [rotating multiple RSA private keys](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#rotating-the-rsa-private-key).
* #978 OIDC: Add new [OIDC_JWKS_MAX_AGE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#oidc-jwks-max-age-seconds) to improve `jwks_uri` caching.
* #967 OIDC: Add [additional claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-claims-to-the-id-token) beyond `sub` to the id_token.
* #1041 Add a search field to the Admin UI (e.g. for search for tokens by email address).

### Changed
* #981 Require redirect_uri if multiple URIs are registered per [RFC6749 section 3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3)
* #991 Update documentation of [REFRESH_TOKEN_EXPIRE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#refresh-token-expire-seconds) to indicate it may be `int` or `datetime.timedelta`.
* #977 Update [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/stable/tutorial/tutorial_01.html#) to show required `include`.

### Removed
* #968 Remove support for Django 3.0 & 3.1 and Python 3.6
* #1035 Removes default_app_config for Django Deprecation Warning
* #1023 six should be dropped

### Fixed
* #963 Fix handling invalid hex values in client query strings with a 400 error rather than 500.
* #973 [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_01.html#start-your-app) updated to use `django-cors-headers`.
* #956 OIDC: Update documentation of [get_userinfo_claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-information-to-the-userinfo-service) to add the missing argument.


## [1.5.0] 2021-03-18

### Added
* #915 Add optional OpenID Connect support.

### Changed
* #942 Help via defunct Google group replaced with using GitHub issues

## [1.4.1] 2021-03-12

### Changed
* #925 OAuth2TokenMiddleware converted to new style middleware, and no longer extends MiddlewareMixin.

### Removed
* #936 Remove support for Python 3.5

## [1.4.0] 2021-02-08

### Added
* #917 Documentation improvement for Access Token expiration.
* #916 (for DOT contributors) Added `tox -e livedocs` which launches a local web server on `localhost:8000`
  to display Sphinx documentation with live updates as you edit.
* #891 (for DOT contributors) Added [details](https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html)
  on how best to contribute to this project.
* #884 Added support for Python 3.9
* #898 Added the ability to customize classes for django admin
* #690 Added pt-PT translations to HTML templates. This enables adding additional translations.

### Fixed
* #906 Made token revocation not apply a limit to the `select_for_update` statement (impacts Oracle 12c database).
* #903 Disable `redirect_uri` field length limit for `AbstractGrant`

## [1.3.3] 2020-10-16

### Added
* added `select_related` in intospect view for better query performance
* #831 Authorization token creation now can receive an expire date
* #831 Added a method to override Grant creation
* #825 Bump oauthlib to 3.1.0 to introduce PKCE
* Support for Django 3.1

### Fixed
* #847: Fix inappropriate message when response from authentication server is not OK.

### Changed
* few smaller improvements to remove older django version compatibility #830, #861, #862, #863

## [1.3.2] 2020-03-24

### Fixed
* Fixes: 1.3.1 inadvertently uploaded to pypi with an extra migration (0003...) from a dev branch.

## [1.3.1] 2020-03-23

### Added
* #725: HTTP Basic Auth support for introspection (Fix issue #709)

### Fixed
* #812: Reverts #643 pass wrong request object to authenticate function.
* Fix concurrency issue with refresh token requests (#[810](https://github.com/django-oauth/django-oauth-toolkit/pull/810))
* #817: Reverts #734 tutorial documentation error.


## [1.3.0] 2020-03-02

### Added
* Add support for Python 3.7 & 3.8
* Add support for Django>=2.1,<3.1
* Add requirement for oauthlib>=3.0.1
* Add support for [Proof Key for Code Exchange (PKCE, RFC 7636)](https://tools.ietf.org/html/rfc7636).
* Add support for custom token generators (e.g. to create JWT tokens).
* Add new `OAUTH2_PROVIDER` [settings](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html):
  - `ACCESS_TOKEN_GENERATOR` to override the default access token generator.
  - `REFRESH_TOKEN_GENERATOR` to override the default refresh token generator.
  - `EXTRA_SERVER_KWARGS` options dictionary for oauthlib's Server class.
  - `PKCE_REQUIRED` to require PKCE.
* Add `createapplication` management command to create an application.
* Add `id` in toolkit admin console applications list.
* Add nonstandard Google support for [urn:ietf:wg:oauth:2.0:oob] `redirect_uri`
  for [Google OAuth2](https://developers.google.com/identity/protocols/OAuth2InstalledApp) "manual copy/paste".
  **N.B.** this feature appears to be deprecated and replaced with methods described in
  [RFC 8252: OAuth2 for Native Apps](https://tools.ietf.org/html/rfc8252) and *may* be deprecated and/or removed
  from a future release of Django-oauth-toolkit.

### Changed
* Change this change log to use [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
* **Backwards-incompatible** squashed migrations:
  If you are currently on a release < 1.2.0, you will need to first install 1.2.0 then `manage.py migrate` before
  upgrading to >= 1.3.0.
* Improved the [tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial.html).

### Removed
* Remove support for Python 3.4
* Remove support for Django<=2.0
* Remove requirement for oauthlib<3.0

### Fixed
* Fix a race condition in creation of AccessToken with external oauth2 server.
* Fix several concurrency issues. (#[638](https://github.com/django-oauth/django-oauth-toolkit/issues/638))
* Fix to pass `request` to `django.contrib.auth.authenticate()` (#[636](https://github.com/django-oauth/django-oauth-toolkit/issues/636))
* Fix missing `oauth2_error` property exception oauthlib_core.verify_request method raises exceptions in authenticate.
  (#[633](https://github.com/django-oauth/django-oauth-toolkit/issues/633))
* Fix "django.db.utils.NotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join" for postgresql.
  (#[714](https://github.com/django-oauth/django-oauth-toolkit/issues/714))
* Fix to return a new refresh token during grace period rather than the recently-revoked one.
  (#[702](https://github.com/django-oauth/django-oauth-toolkit/issues/702))
* Fix a bug in refresh token revocation.
  (#[625](https://github.com/django-oauth/django-oauth-toolkit/issues/625))

## 1.2.0 [2018-06-03]

* **Compatibility**: Python 3.4 is the new minimum required version.
* **Compatibility**: Django 2.0 is the new minimum required version.
* **New feature**: Added TokenMatchesOASRequirements Permissions.
* validators.URIValidator has been updated to match URLValidator behaviour more closely.
* Moved `redirect_uris` validation to the application clean() method.


## 1.1.2 [2018-05-12]

* Return state with Authorization Denied error (RFC6749 section 4.1.2.1)
* Fix a crash with malformed base64 authentication headers
* Fix a crash with malformed IPv6 redirect URIs

## 1.1.1 [2018-05-08]

* **Critical**: Django OAuth Toolkit 1.1.0 contained a migration that would revoke all existing
  RefreshTokens (`0006_auto_20171214_2232`). This release corrects the migration.
  If you have already ran it in production, please see the following issue for more details:
  https://github.com/django-oauth/django-oauth-toolkit/issues/589


## 1.1.0 [2018-04-13]

* **Notice**: The Django OAuth Toolkit project is now hosted by JazzBand.
* **Compatibility**: Django 1.11 is the new minimum required version. Django 1.10 is no longer supported.
* **Compatibility**: This will be the last release to support Django 1.11 and Python 2.7.
* **New feature**: Option for RFC 7662 external AS that uses HTTP Basic Auth.
* **New feature**: Individual applications may now override the `ALLOWED_REDIRECT_URI_SCHEMES`
  setting by returning a list of allowed redirect uri schemes in `Application.get_allowed_schemes()`.
* **New feature**: The new setting `ERROR_RESPONSE_WITH_SCOPES` can now be set to True to include required
  scopes when DRF authorization fails due to improper scopes.
* **New feature**: The new setting `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` controls a grace period during which
  refresh tokens may be reused.
* An `app_authorized` signal is fired when a token is generated.

## 1.0.0 [2017-06-07]

* **New feature**: AccessToken, RefreshToken and Grant models are now swappable.
* #477: **New feature**: Add support for RFC 7662 (IntrospectTokenView, introspect scope)
* **Compatibility**: Django 1.10 is the new minimum required version
* **Compatibility**: Django 1.11 is now supported
* **Backwards-incompatible**: The `oauth2_provider.ext.rest_framework` module
  has been moved to `oauth2_provider.contrib.rest_framework`
* #177: Changed `id` field on Application, AccessToken, RefreshToken and Grant to BigAutoField (bigint/bigserial)
* #321: Added `created` and `updated` auto fields to Application, AccessToken, RefreshToken and Grant
* #476: Disallow empty redirect URIs
* Fixed bad `url` parameter in some error responses.
* Django 2.0 compatibility fixes.
* The dependency on django-braces has been dropped.
* The oauthlib dependency is no longer pinned.

## 0.12.0 [2017-02-24]

* **New feature**: Class-based scopes backends. Listing scopes, available scopes and default scopes
  is now done through the class that the `SCOPES_BACKEND_CLASS` setting points to.
  By default, this is set to `oauth2_provider.scopes.SettingsScopes` which implements the
  legacy settings-based scope behaviour. No changes are necessary.
* **Dropped support for Python 3.2 and Python 3.3**, added support for Python 3.6
* Support for the `scopes` query parameter, deprecated in 0.6.1, has been dropped
* #448: Added support for customizing applications' allowed grant types
* #141: The `is_usable(request)` method on the Application model can be overridden to dynamically
  enable or disable applications.
* #434: Relax URL patterns to allow for UUID primary keys


## 0.11.0 [2016-12-1]

* #315: AuthorizationView does not overwrite requests on get
* #425: Added support for Django 1.10
* #396: added an IsAuthenticatedOrTokenHasScope Permission
* #357: Support multiple-user clients by allowing User to be NULL for Applications
* #389: Reuse refresh tokens if enabled.


## 0.10.0 [2015-12-14]

* **#322: dropping support for python 2.6 and django 1.4, 1.5, 1.6**
* #310: Fixed error that could occur sometimes when checking validity of incomplete AccessToken/Grant
* #333: Added possibility to specify the default list of scopes returned when scope parameter is missing
* #325: Added management views of issued tokens
* #249: Added a command to clean expired tokens
* #323: Application registration view uses custom application model in form class
* #299: `server_class` is now pluggable through Django settings
* #309: Add the py35-django19 env to travis
* #308: Use compact syntax for tox envs
* #306: Django 1.9 compatibility
* #288: Put additional information when generating token responses
* #297: Fixed doc about SessionAuthenticationMiddleware
* #273: Generic read write scope by resource


## 0.9.0 [2015-07-28]

* ``oauthlib_backend_class`` is now pluggable through Django settings
* #127: ``application/json`` Content-Type is now supported using ``JSONOAuthLibCore``
* #238: Fixed redirect uri handling in case of error
* #229: Invalidate access tokens when getting a new refresh token
* added support for oauthlib 1.0


## 0.8.2 [2015-06-25]

* Fix the migrations to be two-step and allow upgrade from 0.7.2

## 0.8.1 [2015-04-27]

* South migrations fixed. Added new django migrations.

## 0.8.0 [2015-03-27]

* Several docs improvements and minor fixes
* #185: fixed vulnerabilities on Basic authentication
* #173: ProtectResourceMixin now allows OPTIONS requests
* Fixed `client_id` and `client_secret` characters set
* #169: hide sensitive information in error emails
* #161: extend search to all token types when revoking a token
* #160: return empty response on successful token revocation
* #157: skip authorization form with ``skip_authorization_completely`` class field
* #155: allow custom uri schemes
* fixed ``get_application_model`` on Django 1.7
* fixed non rotating refresh tokens
* #137: fixed base template
* customized ``client_secret`` length
* #38: create access tokens not bound to a user instance for *client credentials* flow


## 0.7.2 [2014-07-02]

* Don't pin oauthlib

## 0.7.1 [2014-04-27]

* Added database indexes to the OAuth2 related models to improve performances.

**Warning: schema migration does not work for sqlite3 database, migration should be performed manually**

## 0.7.0 [2014-03-01]

* Created a setting for the default value for approval prompt.
* Improved docs
* Don't pin django-braces and six versions

**Backwards incompatible changes in 0.7.0**

* Make Application model truly "swappable" (introduces a new non-namespaced setting `OAUTH2_PROVIDER_APPLICATION_MODEL`)


## 0.6.1 [2014-02-05]

* added support for `scope` query parameter keeping backwards compatibility for the original `scopes` parameter.
* __str__ method in Application model returns content of `name` field when available

## 0.6.0 [2014-01-26]

* oauthlib 0.6.1 support
* Django dev branch support
* Python 2.6 support
* Skip authorization form via `approval_prompt` parameter

**Bugfixes**

* Several fixes to the docs
* Issue #71: Fix migrations
* Issue #65: Use OAuth2 password grant with multiple devices
* Issue #84: Add information about login template to tutorial.
* Issue #64: Fix urlencode clientid secret


## 0.5.0 [2013-09-17]

* oauthlib 0.6.0 support

**Backwards incompatible changes in 0.5.0**

* `backends.py` module has been renamed to `oauth2_backends.py` so you should change your imports whether
  you're extending this module

**Bugfixes**

* Issue #54: Auth backend proposal to address #50
* Issue #61: Fix contributing page
* Issue #55: Add support for authenticating confidential client with request body params
* Issue #53: Quote characters in the url query that are safe for Django but not for oauthlib


## 0.4.1 [2013-09-06]

* Optimize queries on access token validation

## 0.4.0 [2013-08-09]

**New Features**

* Add Application management views, you no more need the admin to register, update and delete your application.
* Add support to configurable application model
* Add support for function based views

**Backwards incompatible changes in 0.4.0**

* `SCOPE` attribute in settings is now a dictionary to store `{'scope_name': 'scope_description'}`
* Namespace `oauth2_provider` is mandatory in urls. See issue #36

**Bugfixes**

* Issue #25: Bug in the Basic Auth parsing in Oauth2RequestValidator
* Issue #24: Avoid generation of `client_id` with ":" colon char when using HTTP Basic Auth
* Issue #21: IndexError when trying to authorize an application
* Issue #9: `default_redirect_uri` is mandatory when `grant_type` is implicit, `authorization_code` or all-in-one
* Issue #22: Scopes need a verbose description
* Issue #33: Add django-oauth-toolkit version on example main page
* Issue #36: Add mandatory namespace to urls
* Issue #31: Add docstring to OAuthToolkitError and FatalClientError
* Issue #32: Add docstring to `validate_uris`
* Issue #34: Documentation tutorial part1 needs corsheaders explanation
* Issue #36: Add mandatory namespace to urls
* Issue #45: Add docs for AbstractApplication
* Issue #47: Add docs for views decorators


## 0.3.2 [2013-07-10]

* Bugfix #37: Error in migrations with custom user on Django 1.5

## 0.3.1 [2013-07-10]

* Bugfix #27: OAuthlib refresh token refactoring

## 0.3.0 [2013-06-14]

* [Django REST Framework](http://django-rest-framework.org/) integration layer
* Bugfix #13: Populate request with client and user in `validate_bearer_token`
* Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

* `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`


## 0.2.1 [2013-06-06]

* Core optimizations

## 0.2.0 [2013-06-05]

* Add support for Django1.4 and Django1.6
* Add support for Python 3.3
* Add a default ReadWriteScoped view
* Add tutorial to docs


## 0.1.0 [2013-05-31]

* Support OAuth2 Authorization Flows


## 0.0.0 [2013-05-17]

* Discussion with Daniel Greenfeld at Django Circus
* Ignition
