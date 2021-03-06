# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
and utilizes [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) messages.

## Unreleased

No unreleased changes

## v0.3.8 (2021-10-18)

## Fixes

* Fixed multiple bugs with middleware error headers being set incorrectly or not at all.

## Enhancements

* Enhanced all middleware options to accept the ability to enable or disable error headers.

## v0.3.7 (2021-10-17)

## Features

* Added `extraFields` to Logger middleware for logging additional context values for each request.
  
## Enhancements

* Modified JWT auth middleware to utilize `JWTCreateAuthServiceHandler` for creating the JWT auth service for token validation.
* Removed log context parameters from `JWTAuthHandler`.
* Modified JWT crypto functions to use standard `jwt.Claims` objects.

## v0.3.1 (2021-10-02)

## Features

* Added `HereDoc()` and `HereDocf()` functions to the `strings` package.

## v0.3.0 (2021-10-01)

### Notes

* Initial release of the module
