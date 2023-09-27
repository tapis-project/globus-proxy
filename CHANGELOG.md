1.4.3 - 2023-9-27

Live-docs: https://tapis-project.github.io/live-docs/?service=GlobusProxy

Breaking Changes:

    Users will need to pass an absolute path to any operations endpoint

New features:

    Improved path building to account for systems which don't resolve /~/
    Polling added to operations
    Improved error handling and logging

Bug fixes:

    Fixed several bugs related to path sanitization logic
    