# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

<!-- insertion marker -->
## [0.5.0]  - 2020-10-16
- Swapped the [classforge](https://classforge.io/) base classing to
  [attrs](https://www.attrs.org)
- Added a lot of additional type annotations to assist with attrs conversion -
  this also assists in the documentation markup,  These needed to be carefully
  handled to make portable to python under travis.  Aditionally the
  `OrderedDict[str, str]` annotation completely broke mkdocs/mkdocstrings.

## [0.4.0]  - 2020-10-16
### Packaging
- Switched to using poetry for development and release
- Updated the `pre-commit` pipeline, with some minor formatting reworks
- Switch to [MkDocs](https://www.mkdocs.org/) for documentation, along with
  [mkdocstrings](https://github.com/pawamoy/mkdocstrings/) for API documentation

## [0.3.x]  - 2020-09-27
- Fixed up documentation
- Added a few additional tests
- This is now reasonably presentable


## [0.2.x]  - 2020-09-25
- First release
- Documentation build
- CI and release automation


## [0.1.0]  - 2020-05-07
- First builds - never release on PyPI.

----
